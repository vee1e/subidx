<script lang="ts">
  import { onMount } from 'svelte'
  import { ApiError, apiBase, openFeed, searchFeed, stats as fetchStats, watchDelta, type Rate, type Row, type Stats } from './lib/api'
  import { copyText, dayOf, download, fmtCount, fmtNum, toCSV, toTXT } from './lib/format'
  import VirtualList from './lib/VirtualList.svelte'

  const ROW_H = 30

  let input = $state('')
  let viewedApex = $state('')
  // The big result array lives outside $state: wrapping 50k+ objects in
  // reactive proxies makes every filter/sort pass pay a proxy tax on each
  // property access. rowsRev just signals "rowsRaw changed".
  let rowsRaw: Row[] = []
  let rowsRev = $state(0)
  let searched = $state(false)
  let loading = $state(false)
  let streaming = $state(false)
  let streamTotal = $state<number | null>(null)
  let error = $state<string | null>(null)
  let retryIn = $state<number | null>(null)
  let copied = $state(false)
  let searchEpoch = $state(0)

  // Live mode: an SSE subscription to newly collected names for the
  // viewed apex. Fresh rows buffer up and merge every couple of seconds
  // so a burst of certificates never causes a re-render storm.
  let liveOn = $state(false)
  let liveState = $state<'off' | 'connecting' | 'live'>('off')
  let pendingNew = $state(0)
  let freshSet = $state<Record<string, true>>({})
  let lastSeq = 0
  let freshRows: Row[] = []
  let knownLc: Set<string> = new Set()
  let closeFeedFn: (() => void) | null = null
  let flushTimer: ReturnType<typeof setTimeout> | null = null
  let hadFeedError = false
  let catchingUp = false

  let info = $state<Stats | null>(null)
  let rate = $state<Rate | null>(null)

  let showDates = $state(true)
  let filterText = $state('')
  let sortKey = $state<'name' | 'seen'>('seen')
  let sortAsc = $state(false)

  let aborter: AbortController | null = null

  const collator = new Intl.Collator('en', { numeric: true })

  function setRows(rows: Row[]) {
    rowsRaw = rows
    rowsRev++
  }

  // Results arrive seq-ascending (oldest collected first) and live merges
  // append at the end, so identity order is stable; "first seen ↑" is a
  // free pass-through and ↓ reverses one copy. No per-keystroke sorts.
  const sorted = $derived.by(() => {
    void rowsRev
    if (streaming) return rowsRaw
    if (sortKey === 'seen') {
      if (sortAsc) return rowsRaw
      const rev = [...rowsRaw]
      rev.reverse()
      return rev
    }
    const arr = [...rowsRaw].sort((a, b) => collator.compare(a.sub, b.sub))
    if (sortAsc) return arr
    arr.reverse()
    return arr
  })

  const visible = $derived.by(() => {
    const f = filterText.trim().toLowerCase()
    if (!f) return sorted
    return sorted.filter((r) => r.lc.includes(f))
  })

  const totalCount = $derived.by(() => {
    void rowsRev
    return rowsRaw.length
  })

  const curlExample = $derived.by(() => {
    const q = input.trim() || 'letsencrypt.org'
    return `curl "${apiBase || location.origin}/v1/search?apex=${q}"`
  })

  function cleanQuery(raw: string): string {
    let q = raw.trim()
    q = q.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    q = q.split('/')[0].split('?')[0]
    return q.toLowerCase()
  }

  async function run(raw: string) {
    const q = cleanQuery(raw)
    input = q
    if (!q || !q.includes('.')) {
      error = 'enter a registered domain, e.g. example.com'
      return
    }
    if (retryIn !== null && retryIn > 0) return

    aborter?.abort()
    aborter = new AbortController()
    const signal = aborter.signal

    loading = true
    streaming = true
    streamTotal = null
    error = null
    setRows([])
    filterText = ''
    searchEpoch++
    viewedApex = q
    searched = true

    // Reset live state for the new apex; the feed restarts after load.
    stopLiveFeed(false)
    if (flushTimer !== null) {
      clearTimeout(flushTimer)
      flushTimer = null
    }
    freshRows = []
    pendingNew = 0
    freshSet = {}
    lastSeq = 0

    const url = new URL(location.href)
    url.searchParams.set('apex', q)
    history.replaceState(null, '', url)

    try {
      await searchFeed(
        q,
        (meta) => {
          rate = meta.rate ?? rate
          streamTotal = meta.total
          if (meta.maxSeq !== null) lastSeq = meta.maxSeq
        },
        (batch) => {
          if (signal.aborted) return
          rowsRaw = rowsRaw.concat(batch)
          rowsRev++
        },
        signal
      )
      rebuildKnown()
      if (liveOn && !signal.aborted) startLiveFeed()
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') return
      if (e instanceof ApiError) {
        if (e.status === 429 && e.retryAfter !== null) {
          retryIn = e.retryAfter
          error = `daily search budget spent. resets in ${fmtRetry(e.retryAfter)}`
        } else {
          error = e.status === 0 ? e.message : `server said: ${e.message}`
        }
      } else {
        error = 'search failed'
      }
      if (rowsRaw.length > 0) {
        error = `${error} — showing ${fmtNum(rowsRaw.length)} partial names`
      }
    } finally {
      if (aborter?.signal === signal) {
        loading = false
        streaming = false
        aborter = null
      }
    }
  }

  function fmtRetry(s: number): string {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return m > 0 ? `${m}m ${String(sec).padStart(2, '0')}s` : `${sec}s`
  }

  // --- live feed ---

  function rebuildKnown() {
    knownLc = new Set(rowsRaw.map((r) => r.lc))
  }

  function toggleLive() {
    if (!searched || loading || !viewedApex) return
    liveOn = !liveOn
    if (liveOn) startLiveFeed()
    else stopLiveFeed(true)
  }

  function startLiveFeed() {
    stopLiveFeed(false)
    hadFeedError = false
    liveState = 'connecting'
    closeFeedFn = openFeed(viewedApex, {
      onRow: receiveFresh,
      onResync: () => void catchUp(),
      onStateChange: (up) => {
        if (up) {
          // After a dropped connection, backfill whatever was missed.
          if (hadFeedError) void catchUp()
          liveState = 'live'
        } else {
          hadFeedError = true
          liveState = 'connecting'
        }
      },
    })
    // Cover the gap between the search snapshot and the stream opening.
    setTimeout(() => {
      if (liveOn && closeFeedFn !== null) void catchUp()
    }, 3000)
  }

  function stopLiveFeed(resetState: boolean) {
    closeFeedFn?.()
    closeFeedFn = null
    if (resetState) liveState = 'off'
  }

  function receiveFresh(row: Row) {
    if (knownLc.has(row.lc)) return
    knownLc.add(row.lc)
    freshRows.push(row)
    pendingNew = freshRows.length
    scheduleFlush()
  }

  function scheduleFlush() {
    if (flushTimer !== null) return
    flushTimer = setTimeout(mergeFresh, 2000)
  }

  function mergeNow() {
    mergeFresh()
  }

  function mergeFresh() {
    if (flushTimer !== null) {
      clearTimeout(flushTimer)
      flushTimer = null
    }
    if (freshRows.length === 0 || streaming) return
    const batch = freshRows
    freshRows = []
    pendingNew = 0
    rowsRaw = rowsRaw.concat(batch)
    rowsRev++
    const upd = { ...freshSet }
    for (const r of batch) upd[r.sub] = true
    freshSet = upd
    setTimeout(() => clearFresh(batch.map((r) => r.sub)), 8000)
  }

  function clearFresh(subs: string[]) {
    let changed = false
    const upd = { ...freshSet }
    for (const s of subs) {
      if (s in upd) {
        delete upd[s]
        changed = true
      }
    }
    if (changed) freshSet = upd
  }

  async function catchUp() {
    if (catchingUp || !viewedApex || lastSeq <= 0) return
    catchingUp = true
    try {
      const d = await watchDelta(viewedApex, lastSeq)
      lastSeq = d.maxSeq
      if (d.truncated) {
        // Too much slipped through while disconnected; reload honestly.
        void run(viewedApex)
        return
      }
      for (const row of d.rows) receiveFresh(row)
      mergeNow()
    } catch {
      // Reconnect or the next resync retries; nothing user-facing to do.
    } finally {
      catchingUp = false
    }
  }

  $effect(() => {
    if (!liveOn) return
    // Refresh the stats header occasionally while live mode is on,
    // only when someone can actually see it.
    const id = setInterval(() => {
      if (document.visibilityState !== 'visible') return
      void fetchStats().then((s2) => {
        if (s2) info = s2
      })
    }, 300_000)
    return () => clearInterval(id)
  })

  $effect(() => {
    if (retryIn === null) return
    const id = setInterval(() => {
      if (retryIn === null) return
      retryIn--
      if (retryIn <= 0) {
        retryIn = null
        if (error?.startsWith('daily search budget')) error = null
      }
    }, 1000)
    return () => clearInterval(id)
  })

  async function copyAll() {
    if (await copyText(toTXT(visible, showDates))) {
      copied = true
      setTimeout(() => (copied = false), 1500)
    }
  }

  function sortBy(key: 'name' | 'seen') {
    if (sortKey === key) {
      sortAsc = !sortAsc
    } else {
      sortKey = key
      sortAsc = key === 'name'
    }
  }

  function pick(apex: string) {
    input = apex
    run(apex)
  }

  onMount(() => {
    fetchStats().then((s) => (info = s))
    const q = new URLSearchParams(location.search).get('apex')
    if (q) run(q)
    return () => {
      stopLiveFeed(false)
      if (flushTimer !== null) clearTimeout(flushTimer)
    }
  })

  const budgetPct = $derived(rate && rate.limit > 0 ? (rate.remaining / rate.limit) * 100 : null)
</script>

<div class="page">
  <header class="masthead">
    <div class="brand">
      <span class="wordmark">subidx</span>
      <span class="tagline">passive subdomain index · certificate transparency</span>
    </div>
    {#if info}
      <div class="total">
        <span class="total-n">{fmtNum(info.total)}</span>
        <span class="total-label">names indexed</span>
      </div>
    {/if}
  </header>

  <form
    class="searchrow"
    onsubmit={(e) => {
      e.preventDefault()
      run(input)
    }}
  >
    <span class="prompt" aria-hidden="true">&rsaquo;</span>
    <input
      class="q"
      type="text"
      bind:value={input}
      placeholder="example.com"
      spellcheck="false"
      autocapitalize="off"
      autocomplete="off"
      aria-label="Registered domain to search"
    />
    <button class="go" type="submit" disabled={loading || (retryIn !== null && retryIn > 0)}>
      {loading ? 'searching' : 'search'}
    </button>
  </form>

  {#if info && info.top.length > 0}
    <nav class="chips" aria-label="Busiest domains in the index">
      {#each info.top.slice(0, 8) as t (t.apex)}
        <button class="chip" type="button" onclick={() => pick(t.apex)}>
          {t.apex}<span class="chip-n">{fmtCount(t.count)}</span>
        </button>
      {/each}
    </nav>
  {/if}

  {#if error}
    <p class="error" role="alert">{error}</p>
  {/if}

  <section class="results" class:hidden={!searched}>
    <div class="toolbar">
      <span class="count" role="status">
        {loading
          ? totalCount > 0
            ? `${fmtNum(totalCount)}${streamTotal !== null ? ` of ${fmtNum(streamTotal)}` : ''} names…`
            : 'searching…'
          : `${fmtNum(visible.length)}${filterText.trim() ? ` of ${fmtNum(totalCount)}` : ''} names`}
      </span>
      {#if pendingNew > 0}
        <button type="button" class="newpill" onclick={mergeNow} title="Merge newly collected names now">
          +{fmtNum(pendingNew)} new
        </button>
      {/if}
      <span class="tools">
        <button
          type="button"
          class="toggle livebtn"
          aria-pressed={liveOn}
          disabled={!searched || loading}
          onclick={toggleLive}
          title="Watch this domain: highlight names as they are collected"
        >
          <span class="livedot" class:on={liveState === 'live'} class:wait={liveState === 'connecting'}></span>
          live
        </button>
        <input
          class="filter"
          type="search"
          bind:value={filterText}
          placeholder="filter…"
          spellcheck="false"
          aria-label="Filter loaded results"
        />
        <span class="seg" role="group" aria-label="Sort order">
          <button type="button" aria-pressed={sortKey === 'seen'} onclick={() => sortBy('seen')}>
            first seen{sortKey === 'seen' ? (sortAsc ? ' ↑' : ' ↓') : ''}
          </button>
          <button type="button" aria-pressed={sortKey === 'name'} onclick={() => sortBy('name')}>
            name{sortKey === 'name' ? (sortAsc ? ' ↑' : ' ↓') : ''}
          </button>
        </span>
        <button type="button" class="toggle" aria-pressed={showDates} onclick={() => (showDates = !showDates)}>
          dates
        </button>
        <span class="exports">
          <button type="button" onclick={copyAll} disabled={loading || visible.length === 0}>
            {copied ? 'copied' : 'copy'}
          </button>
          <button
            type="button"
            disabled={loading || visible.length === 0}
            title="Download filtered results as .txt"
            onclick={() => download(`${viewedApex || 'subidx'}.txt`, 'text/plain', toTXT(visible, showDates))}
          >
            .txt
          </button>
          <button
            type="button"
            disabled={loading || visible.length === 0}
            title="Download filtered results as .csv"
            onclick={() => download(`${viewedApex || 'subidx'}.csv`, 'text/csv', toCSV(visible, showDates))}
          >
            .csv
          </button>
        </span>
      </span>
    </div>

    <div class="sheet" class:nodates={!showDates}>
      <div class="thead" aria-hidden="true">
        <span>name</span>
        {#if showDates}<span class="th-date">first seen</span>{/if}
      </div>
      <div class="rows">
        <VirtualList items={visible} rowHeight={ROW_H} epoch={searchEpoch}>
          {#snippet row(item)}
            <div class="lrow" class:fresh={freshSet[item.sub] === true}>
              <span class="sub" title={item.sub}>{item.sub}</span>
              {#if showDates}
                <span class="seen" class:unknown={!item.firstSeen} title={item.firstSeen ?? 'date unknown'}>
                  {item.firstSeen ? dayOf(item.firstSeen) : '—'}
                </span>
              {/if}
            </div>
          {/snippet}
        </VirtualList>
      </div>
    </div>
  </section>

  {#if !searched && !error}
    <section class="hint">
      <p>List every hostname this collector has seen issued a certificate for. Type an apex — the registered domain, not a subdomain.</p>
      <p>The same data is served over plain HTTP:</p>
      <code>{curlExample}</code>
    </section>
  {/if}

  {#if searched && !loading && visible.length === 0 && !error}
    <section class="hint">
      <p>No names collected for <strong>{viewedApex}</strong> yet.</p>
      <p>Certificate Transparency only records names that were issued a certificate. Names living only in DNS are invisible here.</p>
      <code>{curlExample}</code>
    </section>
  {/if}

  <footer class="foot">
    {#if rate}
      <div class="budget" class:low={budgetPct !== null && budgetPct < 10}>
        <span class="budget-label">search budget</span>
        <span class="budget-bar"><span class="budget-fill" style="width: {budgetPct ?? 0}%"></span></span>
        <span class="budget-n">{fmtNum(Math.max(0, rate.remaining))}/{fmtNum(rate.limit)}</span>
      </div>
    {:else}
      <span class="budget-label">self-hosted · no keys, no quotas</span>
    {/if}
    <a class="api-link" href="/v1/stats">API</a>
  </footer>
</div>

<style>
  .page {
    max-width: 980px;
    margin: 0 auto;
    padding: 20px 24px 12px;
    height: 100dvh;
    display: flex;
    flex-direction: column;
  }

  .hidden {
    display: none;
  }

  /* masthead */
  .masthead {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 16px;
    padding-bottom: 14px;
    border-bottom: 1px solid var(--line);
  }

  .brand {
    display: flex;
    align-items: baseline;
    gap: 12px;
    min-width: 0;
  }

  .wordmark {
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.06em;
  }

  .tagline {
    font-family: var(--sans);
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--faint);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .total {
    display: flex;
    align-items: baseline;
    gap: 8px;
    white-space: nowrap;
  }

  .total-n {
    font-size: 15px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }

  .total-label {
    font-family: var(--sans);
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--faint);
  }

  /* search */
  .searchrow {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 18px;
  }

  .prompt {
    color: var(--accent);
    font-weight: 700;
    font-size: 18px;
    user-select: none;
  }

  .q {
    flex: 1;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 3px;
    padding: 9px 12px;
    caret-color: var(--accent);
  }

  .q::placeholder {
    color: var(--faint);
  }

  .q:focus-visible,
  .filter:focus-visible {
    outline-offset: 0;
    border-color: var(--accent-dim);
  }

  .go {
    background: transparent;
    border: 1px solid var(--accent-dim);
    color: var(--accent);
    border-radius: 3px;
    padding: 9px 16px;
    cursor: pointer;
    letter-spacing: 0.04em;
  }

  .go:hover:not(:disabled) {
    background: rgba(226, 165, 74, 0.09);
  }

  .go:disabled {
    opacity: 0.45;
    cursor: default;
  }

  /* chips */
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 10px;
  }

  .chip {
    background: transparent;
    border: none;
    color: var(--muted);
    padding: 3px 8px;
    border-radius: 3px;
    cursor: pointer;
    font-size: 12px;
  }

  .chip:hover {
    color: var(--accent);
    background: rgba(226, 165, 74, 0.07);
  }

  .chip-n {
    margin-left: 7px;
    color: var(--faint);
    font-variant-numeric: tabular-nums;
  }

  .chip:hover .chip-n {
    color: var(--accent-dim);
  }

  .error {
    margin: 14px 0 0;
    color: var(--err);
  }

  /* results */
  .results {
    margin-top: 16px;
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    padding-bottom: 8px;
  }

  .count {
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }

  .tools {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .filter {
    width: 130px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 3px;
    padding: 4px 8px;
    font-size: 12px;
  }

  .filter::placeholder {
    color: var(--faint);
  }

  .seg,
  .exports {
    display: inline-flex;
  }

  .seg button,
  .exports button,
  .toggle {
    background: transparent;
    border: 1px solid var(--line);
    border-right-width: 0;
    color: var(--muted);
    padding: 4px 9px;
    font-family: var(--sans);
    font-size: 10px;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    cursor: pointer;
    white-space: nowrap;
  }

  .exports button:last-child,
  .seg button:last-child {
    border-right-width: 1px;
    border-radius: 0 3px 3px 0;
  }

  .seg button:first-child,
  .exports button:first-child {
    border-radius: 3px 0 0 3px;
  }

  .toggle {
    border-radius: 3px;
    border-right-width: 1px;
  }

  .livebtn {
    display: inline-flex;
    align-items: center;
    gap: 7px;
  }

  .livedot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--faint);
  }

  .livedot.on {
    background: var(--ok);
  }

  .livedot.wait {
    background: var(--accent-dim);
    animation: pulse 1.2s ease-in-out infinite;
  }

  @keyframes pulse {
    50% {
      opacity: 0.35;
    }
  }

  .newpill {
    background: rgba(226, 165, 74, 0.1);
    color: var(--accent);
    border: 1px solid var(--accent-dim);
    border-radius: 10px;
    padding: 2px 10px;
    font-size: 11px;
    cursor: pointer;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }

  .newpill:hover {
    background: rgba(226, 165, 74, 0.2);
  }

  .seg button[aria-pressed='true'],
  .toggle[aria-pressed='true'] {
    color: var(--accent);
    border-color: var(--accent-dim);
  }

  .seg button:hover:not([aria-pressed='true']),
  .exports button:hover:not(:disabled),
  .toggle:hover:not([aria-pressed='true']) {
    color: var(--text);
  }

  .exports button:disabled {
    opacity: 0.4;
    cursor: default;
  }

  /* sheet */
  .sheet {
    border: 1px solid var(--line);
    border-radius: 3px;
    background: var(--panel);
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
  }

  .thead {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 140px;
    gap: 16px;
    padding: 7px 14px;
    border-bottom: 1px solid var(--line);
    font-family: var(--sans);
    font-size: 10px;
    letter-spacing: 0.09em;
    text-transform: uppercase;
    color: var(--faint);
    user-select: none;
  }

  .nodates .thead {
    grid-template-columns: minmax(0, 1fr);
  }

  .th-date {
    text-align: right;
  }

  .rows {
    flex: 1;
    min-height: 0;
  }

  .lrow {
    height: 30px;
    display: grid;
    grid-template-columns: minmax(0, 1fr) 140px;
    gap: 16px;
    align-items: center;
    padding: 0 14px;
    border-bottom: 1px solid var(--line-soft);
  }

  .nodates .lrow {
    grid-template-columns: minmax(0, 1fr);
  }

  .sub {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    transition: color 1.4s ease;
  }

  .lrow.fresh .sub {
    color: var(--accent);
  }

  .seen {
    text-align: right;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }

  .unknown {
    color: var(--faint);
  }

  .rows :global(.viewport) {
    height: 100%;
  }

  /* hint panels */
  .hint {
    margin-top: 22px;
    border-left: 2px solid var(--line);
    padding: 2px 0 2px 16px;
    color: var(--muted);
    max-width: 640px;
  }

  .hint p {
    margin: 6px 0;
  }

  .hint strong {
    color: var(--text);
  }

  .hint code {
    display: inline-block;
    margin-top: 8px;
    padding: 7px 11px;
    background: var(--panel);
    border: 1px solid var(--line-soft);
    border-radius: 3px;
    color: var(--accent-dim);
    font-size: 12px;
    overflow-x: auto;
    max-width: 100%;
  }

  /* footer */
  .foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding-top: 14px;
    margin-top: auto;
    border-top: 1px solid var(--line);
    color: var(--faint);
  }

  .budget {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .budget-label,
  .api-link {
    font-family: var(--sans);
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .budget-bar {
    width: 72px;
    height: 3px;
    background: var(--line);
    border-radius: 2px;
    overflow: hidden;
  }

  .budget-fill {
    display: block;
    height: 100%;
    background: var(--ok);
  }

  .budget.low .budget-fill {
    background: var(--err);
  }

  .budget.low .budget-n {
    color: var(--err);
  }

  .budget-n {
    color: var(--muted);
    font-variant-numeric: tabular-nums;
    font-size: 11px;
  }

  .api-link {
    color: var(--faint);
    text-decoration: none;
  }

  .api-link:hover {
    color: var(--accent);
  }

  @media (max-width: 640px) {
    .page {
      padding: 14px 14px 10px;
      height: auto;
      min-height: 100dvh;
    }

    .tagline {
      display: none;
    }

    .thead {
      grid-template-columns: minmax(0, 1fr) 96px;
    }

    .lrow {
      grid-template-columns: minmax(0, 1fr) 96px;
      gap: 10px;
    }
  }
</style>
