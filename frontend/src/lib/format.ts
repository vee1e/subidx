import type { Row } from './api'

export function fmtNum(n: number): string {
  return n.toLocaleString('en-US')
}

export function fmtCount(n: number): string {
  if (n >= 10_000_000) return Math.round(n / 1_000_000) + 'M'
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 10_000) return Math.round(n / 1000) + 'k'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k'
  return String(n)
}

export function dayOf(ts: string | null): string {
  return ts ? ts.slice(0, 10) : ''
}

function csvField(v: string): string {
  if (/[",\n\r]/.test(v)) return '"' + v.replaceAll('"', '""') + '"'
  return v
}

export function toTXT(rows: Row[], withDates: boolean): string {
  const lines = rows.map((r) => (withDates ? `${r.sub}\t${r.firstSeen ?? ''}` : r.sub))
  return lines.join('\n') + '\n'
}

export function toCSV(rows: Row[], withDates: boolean): string {
  const head = withDates ? 'subdomain,first_seen\n' : 'subdomain\n'
  const body = rows
    .map((r) => (withDates ? `${csvField(r.sub)},${r.firstSeen ?? ''}` : csvField(r.sub)))
    .join('\n')
  return head + body + '\n'
}

export function download(name: string, mime: string, text: string): void {
  const blob = new Blob([text], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
