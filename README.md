# subidx

subidx is a self-hosted passive subdomain enumeration tool for recon and attack-surface mapping. It tails public Certificate Transparency logs (public records of every HTTPS certificate issued), indexes every hostname it sees, and serves them through a search API you control. Think crt.name, but the data lives on your machine and answers to nobody else's rate limits.

## Why not just use subfinder?

Tools like [subfinder](https://github.com/projectdiscovery/subfinder) query other people's services (crt.sh, Shodan, VirusTotal...) at run time. That works, but you inherit their quotas, captchas, downtime, and blind spots, and every run starts from zero. subidx takes a different position: pull from the source yourself, once, and own the index.

What that buys you in a recon workflow:

- **Continuous coverage.** The tailer runs 24/7 with crash-safe resume. A certificate issued thirty seconds ago is already searchable. Point-in-time tools only see what third parties had indexed when you ran them.
- **First-seen timelines.** Every name carries the earliest date it appeared in any watched log (`&dates=1`). Diff over time to catch new subdomains on targets between engagements.
- **No keys, no quotas.** Zero API keys, zero third-party terms of service. Your only dependencies are the log lists themselves.
- **Verified provenance.** Each log's signing key is pinned against the log list, every signed tree head is cryptographically verified before the tailer acts on it, and every fetched batch must pass an RFC 6962 inclusion-proof spot check against the signed root before it is ingested — entries that cannot be proven part of the signed tree are never stored.
- **Historical drains.** Years of history from retired and rejected logs can be backfilled locally — terabytes if you want all of it.
- **A hosted API, not just a CLI.** Pipe results straight into your existing tooling: `curl "http://localhost:8099/v1/search?apex=target.com"`.

Honest limits: CT logs only contain hostnames that were issued a certificate. Names that exist purely in DNS records or web mentions are invisible here, which is why subidx complements rather than replaces broader-source tools.

Status: the live pipeline works end to end. A four minute run against the live firehose collected about 470,000 names from 21 logs.

## Note on subfaster

A similar project exists: [subfaster](https://github.com/melvinsh/subfaster). This project was built before its author was aware of subfaster. The two share no code and take different approaches: subfaster queries other people's services (crt.sh, RapidDNS, and friends) at run time, while subidx tails the CT logs itself, builds its own local index, and serves it from your own machine. Any resemblance is convergent evolution, not copying.

## Quick start

```
go build -o subidx .
./subidx tail -store ./data          # collect names (runs forever, Ctrl-C to stop)
./subidx serve -store ./data -addr :8099   # search what you collected
```

Then:

```
curl "http://localhost:8099/v1/search?apex=letsencrypt.org"
```

## How it works

1. **Log discovery.** Every hour, subidx fetches three log lists (Chrome's main list, Chrome's full list including rejected logs, and Apple's current list) and merges them by log ID. Logs marked pending, qualified, or usable are tailed live. Old and rejected logs hold years of history; use `-no-drain` if you do not want to pull all of that.
2. **Tailing.** For each log, subidx checks the tree size every few seconds and downloads only the new entries, up to 1000 per request. It tracks how far it got per log (a watermark) so it can resume after a restart, and it never moves that marker backwards even if a log misbehaves.
3. **Parsing.** Each entry is decoded just long enough to read the SAN list (the part of a certificate that names the domains it covers). Both ordinary certificates and precertificates are handled. Everything else about the certificate is thrown away.
4. **Normalizing.** Names are lowercased, trailing dots and wildcard prefixes (`*.`) are stripped, reserved names like `.local` are rejected, and each name is assigned to its registered domain (apex) using the Public Suffix List.
5. **Storing.** One writer process inserts into a pebble key-value store, keyed by domain plus subdomain. If a name shows up again, only the earliest date is kept. Nothing is ever deleted.
6. **Serving.** A small HTTP API answers searches, with rate limiting and health checks.

## Commands

| Command | What it does |
|---|---|
| `tail` | Watch CT logs and store names. Runs until you stop it. |
| `serve` | Serve the search API. Add `-no-tail` to serve without collecting. |
| `stats` | Print total records and the top 10 domains. `-recount` fixes the counters with a full scan if they ever drift. |
| `version` | Print the version. |

Useful flags:

| Flag | Default | Meaning |
|---|---|---|
| `-store` | `./data` | Where the database lives |
| `-addr` | `127.0.0.1:8080` | Listen address for `serve` (binds localhost by default; use `:8080` to expose) |
| `-poll-interval` | `3s` | How often each log is checked for new entries |
| `-window` | `512` | Entries fetched per request while catching up |
| `-no-drain` | off | Skip old and rejected logs (they hold years of history, terabytes) |
| `-rate-limit` | `1000` | Search requests allowed per IP per rolling 24 hours |
| `-max-results` | `100000` | Max results buffered per search query (newest-collected first) |
| `-allowed-hosts` | loopback names | Host header values to accept. Blocks DNS rebinding; add your hostname when exposing the API |
| `-trusted-proxy-hops` | `0` | How many proxies in front of you. 0 means X-Forwarded-For is ignored |

Only one process can use a store directory at a time. The database takes an exclusive lock.

## The API

`GET /v1/search?apex=example.com` returns one name per line. This matches crt.name exactly, including the odd parts:

| Case | Response |
|---|---|
| Known domain | `200`, one name per line, in collection order |
| Unknown domain | `200`, empty body (not 404) |
| Not a bare domain (`www.example.com`, `_bad.com`) | `400`, plain text reason |
| Missing `apex` parameter | `400`, `missing apex parameter` |
| Add `&dates=1` | Each line gets a TAB and the first-seen date |
| Add `&format=json` | JSON array of `{"sub":"..."}` objects |
| Add both | Objects become `{"first_seen":"...","sub":"..."}`, date can be `null` |
| HEAD requests | `405` |

Also served: `/healthz` (process is up) and `/readyz` (store is open and usable). Both skip the rate limit.

## What gets stored

Three facts per name: the domain (apex, the registered domain like `example.com`), the full subdomain, and `first_seen`, the earliest date the name appeared in any log we watched. Multi-level names are kept whole, so `ap.www.sandbox.namecheap.com` is one record under `namecheap.com`.
