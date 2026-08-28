export interface Row {
  sub: string
  /** Lowercased sub, precomputed at fetch time for allocation-free filtering. */
  lc: string
  firstSeen: string | null
}

// Where the API lives. Empty means same-origin (the single-binary
// deployment); Vercel builds set VITE_API_BASE to the Render service URL.
export const apiBase = ((import.meta.env.VITE_API_BASE as string | undefined) ?? '').replace(/\/+$/, '')

const apiUrl = (path: string) => `${apiBase}${path}`

export interface Rate {
  limit: number
  remaining: number
}

export interface Stats {
  total: number
  top: { apex: string; count: number }[]
}

export interface FeedMeta {
  total: number | null
  rate: Rate | null
  maxSeq: number | null
}

export class ApiError extends Error {
  status: number
  retryAfter: number | null

  constructor(status: number, message: string, retryAfter: number | null) {
    super(message)
    this.status = status
    this.retryAfter = retryAfter
  }
}

function rateFrom(res: Response): Rate | null {
  const limit = res.headers.get('x-ratelimit-limit')
  const remaining = res.headers.get('x-ratelimit-remaining')
  if (limit === null || remaining === null) return null
  const l = Number(limit)
  const r = Number(remaining)
  if (!Number.isFinite(l) || !Number.isFinite(r)) return null
  return { limit: l, remaining: r }
}

function retryFrom(res: Response): number | null {
  const v = Number(res.headers.get('retry-after'))
  return Number.isFinite(v) && v > 0 ? v : null
}

function rowFrom(o: { sub: string; first_seen: string | null }): Row {
  const sub = o.sub
  const lower = sub.toLowerCase()
  return { sub, lc: lower === sub ? sub : lower, firstSeen: o.first_seen }
}

// searchFeed streams the search response as NDJSON and invokes onBatch
// with each chunk of parsed rows, so the UI renders progressively while
// a multi-megabyte response is still arriving.
export async function searchFeed(
  apex: string,
  onMeta: (meta: FeedMeta) => void,
  onBatch: (rows: Row[]) => void,
  signal?: AbortSignal
): Promise<void> {
  let res: Response
  try {
    res = await fetch(apiUrl(`/v1/search?apex=${encodeURIComponent(apex)}&format=ndjson&dates=1`), { signal })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e
    throw new ApiError(0, 'cannot reach the subidx server', null)
  }
  if (!res.ok) {
    const text = (await res.text()).trim()
    throw new ApiError(res.status, text || res.statusText, retryFrom(res))
  }
  const totalRaw = Number(res.headers.get('x-total-count'))
  const maxSeqRaw = Number(res.headers.get('x-max-seq'))
  onMeta({
    total: Number.isFinite(totalRaw) && totalRaw >= 0 ? totalRaw : null,
    rate: rateFrom(res),
    maxSeq: Number.isFinite(maxSeqRaw) && maxSeqRaw >= 0 ? maxSeqRaw : null,
  })

  const reader = res.body!.getReader()
  const dec = new TextDecoder()
  let buf = ''
  let pos = 0
  let batch: Row[] = []

  const flush = () => {
    if (batch.length > 0) {
      onBatch(batch)
      batch = []
    }
  }

  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buf += dec.decode(value, { stream: true })
    let nl: number
    while ((nl = buf.indexOf('\n', pos)) >= 0) {
      if (nl > pos) {
        batch.push(rowFrom(JSON.parse(buf.slice(pos, nl)) as { sub: string; first_seen: string | null }))
        if (batch.length >= 5000) flush()
      }
      pos = nl + 1
    }
    if (pos > 0) {
      buf = buf.slice(pos)
      pos = 0
    }
  }
  flush()
}

export async function stats(signal?: AbortSignal): Promise<Stats | null> {
  try {
    const res = await fetch(apiUrl('/v1/stats'), { signal })
    if (!res.ok) return null
    const data = (await res.json()) as Stats
    if (!Number.isFinite(data.total) || !Array.isArray(data.top)) return null
    return data
  } catch {
    return null
  }
}

// watchDelta fetches the names added to an apex since sequence cursor
// `after`. Used to backfill anything missed while a live feed was down.
export async function watchDelta(
  apex: string,
  after: number,
  signal?: AbortSignal
): Promise<{ rows: Row[]; maxSeq: number; truncated: boolean }> {
  let res: Response
  try {
    res = await fetch(apiUrl(`/v1/watch?apex=${encodeURIComponent(apex)}&after=${after}&format=ndjson&dates=1`), { signal })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e
    throw new ApiError(0, 'cannot reach the subidx server', null)
  }
  if (!res.ok) {
    const text = (await res.text()).trim()
    throw new ApiError(res.status, text || res.statusText, retryFrom(res))
  }
  const maxSeqRaw = Number(res.headers.get('x-max-seq'))
  const truncated = res.headers.get('x-truncated') === '1'
  const text = await res.text()
  const rows: Row[] = []
  for (const line of text.split('\n')) {
    if (!line) continue
    rows.push(rowFrom(JSON.parse(line) as { sub: string; first_seen: string | null }))
  }
  return { rows, maxSeq: Number.isFinite(maxSeqRaw) ? maxSeqRaw : after, truncated }
}

// openFeed subscribes to the server-sent-event stream for one apex and
// returns a close function. EventSource reconnects on its own; callers
// react via onStateChange to run catch-ups after gaps.
export interface FeedHandlers {
  onRow: (row: Row) => void
  onResync: () => void
  onStateChange: (connected: boolean) => void
}

export function openFeed(apex: string, h: FeedHandlers): () => void {
  const es = new EventSource(apiUrl(`/v1/feed?apex=${encodeURIComponent(apex)}`))
  es.onopen = () => h.onStateChange(true)
  es.onerror = () => h.onStateChange(false)
  es.onmessage = (ev: MessageEvent<string>) => {
    try {
      h.onRow(rowFrom(JSON.parse(ev.data) as { sub: string; first_seen: string | null }))
    } catch {
      // Malformed line: skip it, the stream stays usable.
    }
  }
  es.addEventListener('resync', () => h.onResync())
  return () => es.close()
}
