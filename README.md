# wstg-info

Automated reconnaissance runner for the OWASP Web Security Testing Guide (WSTG)
Information Gathering category, `WSTG-INFO-01` through `WSTG-INFO-10`.

Each WSTG test maps to one module. A run produces a Markdown report, a
machine-readable `findings.json`, and a `raw/` folder containing the evidence
captured from the target.

> **Only run this against systems you own or are explicitly authorized to test.**
> Active checks (`--active`) generate real traffic against the target and any
> subdomains listed in certificate transparency logs.

---

## Requirements

- Python 3.10+
- `requests` (the only hard dependency)

Optional extras unlock better results. Without them the tool degrades
gracefully and tells you what was skipped:

| Package | Enables |
|---|---|
| `beautifulsoup4` | Robust HTML form parsing in INFO-06 |
| `dnspython` | Full DNS records (NS, MX, TXT) in INFO-10 |
| `tldextract` | Accurate registrable-domain handling for multi-part TLDs (`.co.uk`, `.com.au`) |
| `PyYAML` | Loading `config.yaml` |

## Install

```bash
git clone <this folder>
cd pentest-case

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Minimal install (requests only):

```bash
pip install requests
```

## Quick start

```bash
# 1. See available modules
python3 wstg_info.py --list

# 2. Passive reconnaissance (safe, no enumeration)
python3 wstg_info.py -t https://example.com

# 3. Full run including active checks (directory enumeration, subdomain probing)
python3 wstg_info.py -t https://example.com --active

# 4. Preview the requests without sending anything
python3 wstg_info.py -t https://example.com --active --dry-run
```

Results are written to `results/<host>-<timestamp>/`:

```
results/example.com-20261011-235229/
├── report.md            # human-readable report with WSTG links and checklists
├── findings.json        # machine-readable results (keyed by WSTG ID)
└── raw/                 # evidence files
    ├── requests.jsonl   # audit trail of every request made
    ├── INFO-02.homepage.headers.txt
    ├── INFO-03..env.txt
    ├── INFO-05.app.js.js
    ├── INFO-09.favicon.ico
    └── INFO-10.tls.pem
```

## Modules

| ID | Test | Mode | What it does |
|---|---|---|---|
| INFO-01 | Search engine reconnaissance | passive | crt.sh subdomains, Wayback CDX review, search-engine dork generation |
| INFO-02 | Fingerprint web server | passive | Server headers, HTTP version, error-page fingerprints |
| INFO-03 | Review metafiles | passive | robots.txt, sitemap.xml, security.txt, `.git/HEAD`, `.env`, crossdomain.xml, ... |
| INFO-04 | Attack surface identification | **active** | CT subdomain liveness probing, directory enumeration, optional port scan |
| INFO-05 | Review page content | passive | Comments, emails, secrets/API keys, source maps, internal IPs (HTML + JS) |
| INFO-06 | Identify entry points | passive | Forms, query parameters, fetch/axios/WebSocket endpoints |
| INFO-07 | Map execution paths | passive | BFS crawl (depth/page limits), graph JSON + Mermaid diagram |
| INFO-08 | Fingerprint framework | passive | Cookie/header/body/script signatures (WordPress, Django, Next.js, ...) |
| INFO-09 | Fingerprint application | passive | Favicon mmh3 hash (+ Shodan link), curated known-path probes |
| INFO-10 | Map architecture | passive | DNS records, TLS certificate inventory, CDN/WAF detection, Mermaid sketch |

`INFO-04` is skipped unless `--active` is passed.

## CLI reference

```
python3 wstg_info.py [options]
```

| Option | Description |
|---|---|
| `-t, --target` | Target URL or host (`https://example.com`, `example.com` defaults to `https://`) |
| `-o, --output` | Base output directory (default: `results`) |
| `--config` | Path to a config file (default: `config.yaml` next to the script) |
| `--only` | Comma-separated tests or IDs, e.g. `INFO-01,INFO-03` or `1,3`; `INFO` means all |
| `--skip` | Comma-separated WSTG IDs to exclude |
| `--active` | Enable active checks (INFO-04) |
| `--depth` | Crawler depth for INFO-07 (default 2) |
| `--max-pages` | Crawler page limit for INFO-07 (default 50) |
| `--rate-limit` | Max requests per second (default 10) |
| `--threads` | Worker threads for active checks (default 10) |
| `--timeout` | Per-request timeout in seconds (default 10) |
| `--ports` | Comma-separated ports for the INFO-04 port scan, e.g. `80,443,8080` |
| `--user-agent` | Override the User-Agent header |
| `--proxy` | HTTP(S) proxy, e.g. `http://127.0.0.1:8080` (Burp/ZAP) |
| `--insecure` | Do not verify TLS certificates |
| `--dry-run` | Print the requests that would be sent, send nothing |
| `--show-secrets` | Do not redact secrets/emails in reports |
| `--list` | List modules and exit |

## Common workflows

**Passive-only assessment** (safe during early engagement):

```bash
python3 wstg_info.py -t https://target.example.com
```

**Route everything through Burp or ZAP:**

```bash
python3 wstg_info.py -t https://target.example.com --proxy http://127.0.0.1:8080 --insecure
```

**Full active run with tuned limits:**

```bash
python3 wstg_info.py -t https://target.example.com \
    --active --depth 3 --max-pages 200 --rate-limit 5 --threads 5
```

**Port scan as part of INFO-04:**

```bash
python3 wstg_info.py -t target.example.com --active --ports 80,443,8080,8443
```

**Re-run a subset (`--only` also accepts bare numbers):**

```bash
python3 wstg_info.py -t target.example.com --only 2,3,5
python3 wstg_info.py -t target.example.com --only WSTG-INFO-01
python3 wstg_info.py -t target.example.com --skip INFO-04,INFO-07
```

## Configuration

`config.yaml` is loaded automatically from the script directory; CLI flags
override it.

```yaml
http:
  timeout: 10          # per-request timeout (seconds)
  rate_limit: 10       # max requests per second
  threads: 10          # worker threads for active checks
  user_agent: "wstg-info/0.1 (authorized security testing)"

scan:
  depth: 2             # crawler depth for INFO-07
  max_pages: 50        # crawler page limit for INFO-07
  max_js_files: 25     # JS files fetched and scanned by INFO-05
  wordlist: wordlists/common.txt   # directory enumeration list for INFO-04

info01:
  wayback_limit: 2000  # Wayback CDX result cap
  max_wayback_hits: 50 # interesting URLs shown in the report

info04:
  max_subdomains: 100  # CT-listed subdomains probed for liveness
  max_wordlist: 200    # wordlist entries used
  ports: []            # leave empty to skip the port scan

info07:
  max_mermaid_nodes: 30  # nodes drawn in the Mermaid diagram
```

Add paths to `wordlists/common.txt` (one per line, `#` for comments), or point
`scan.wordlist` at your own list.

## Safety and scope

- **Scope guard:** requests are restricted to the target host, its `www`
  variant, and (only with `--active`) subdomains of the target's registrable
  domain. Recon providers (crt.sh, web.archive.org) are the only external
  hosts contacted.
- **Active checks are opt-in:** directory enumeration, subdomain probing, and
  port scanning only run with `--active`.
- **Rate limiting:** applies globally to all requests, including threaded
  enumeration. Default 10 req/s; lower it for sensitive targets.
- **Off-scope redirects:** recorded in `raw/requests.jsonl` with an
  `off_scope_final` flag; review it after every run.
- **Evidence, not verdicts:** every item is a candidate lead. INFO-01, INFO-05,
  INFO-06, INFO-07, and INFO-10 always need human validation.
- **Redaction:** secrets and emails are masked in reports by default. Use
  `--show-secrets` only if your report handling policy allows it.
- **No search-engine scraping:** INFO-01 generates dork URLs for manual use
  instead of scraping Google/Bing.

## What to expect from results

### Volume

A typical internet-facing target yields **roughly 15–30 findings, and most of
them will be `info` severity**. This is normal:

- **Passive run** against a real internet-facing site (measured): 25 findings —
  2 medium, 2 low, 21 info — in ~75 s.
- **Active run** against a lab target seeded with deliberate flaws (measured):
  23 findings — 2 critical, 1 high, 2 medium, 5 low, 13 info — in ~2 s.

A run with zero critical/high findings is not unusual and does not mean the
tool failed. Information Gathering is recon, not exploitation.

### Runtime

Passive runs typically take **10–90 seconds**, dominated by INFO-01's external
APIs (crt.sh, Wayback CDX — which can be slow or time out from some networks;
a timeout degrades into a manual follow-up note, not an error). A `--dry-run`
completes instantly. Active runs add directory enumeration time, roughly
`wordlist entries / rate limit` (e.g. 146 paths at 10 req/s ≈ 20 s), plus
subdomain liveness probing when CT results exist.

### Per-module baseline (what a "clean-ish" target still returns)

| Module | Normal output on almost any target | When to act |
|---|---|---|
| INFO-01 | Dork set artifact; CT subdomain list on domains; Wayback often a manual note | Suspicious archived URLs (medium) |
| INFO-02 | Server banner + HTTP version + 404 fingerprint (info/low) | Version number disclosed (low) |
| INFO-03 | robots.txt / sitemap.xml / security.txt (info) | `.env` or `.git/HEAD` readable (**critical**), permissive crossdomain (low) |
| INFO-04 | `skipped` without `--active`; with it, a handful of 200/301 paths (info) | Sensitive-keyword paths (medium), 401/403s worth retesting |
| INFO-05 | Emails, generator meta, benign comments (info) | Matched secret patterns (high), suspicious TODOs (low) |
| INFO-06 | Form/parameter/endpoint inventory (info) | None — this is an intelligence finding by design |
| INFO-07 | Crawl count + Mermaid map (info) | 5xx pages discovered during the map |
| INFO-08 | Often no signatures → only a manual checklist; not a failure | Any detected framework + version strings (low) |
| INFO-09 | Favicon hash + Shodan link (info) | phpinfo/server-status/actuator exposed (high) |
| INFO-10 | DNS table, TLS inventory, CDN detection, architecture sketch (info) | Certificate expiring < 30 days (medium), expired (high), unverified |

### INFO-03 — expected results by file and status

INFO-03 probes 16 fixed metafile paths. For each path it fetches the URL,
compares the response body against a random-path baseline (soft-404 filter),
runs a per-file content check, then classifies the path as `exposed`,
`restricted`, `absent`, or `unreachable`. Every exposed file is saved as
`raw/INFO-03.<file>.txt`, and a manifest covering all 16 probes is written to
`raw/INFO-03.manifest.json`.

**How each HTTP status is interpreted:**

| Status | Classification | What appears in the report |
|---|---|---|
| 200/204, content check passes | `exposed` | Per-file finding (severity depends on the file, see below) + evidence |
| 200/204, body matches the baseline page | `absent` | No finding — soft-404 filter (e.g. SPA/catch-all routing returns the homepage for everything) |
| 200/204, content check fails | `absent (content check failed)` | No finding — anti-false-positive filter (e.g. an HTML error page served with status 200) |
| 401 / 403 | `restricted` | Info finding: "`<file>` exists but is protected" — the path is confirmed real; treat it as intel, not absence |
| 404, 3xx redirects, 5xx, anything else | `absent` | No finding; visible only in the manifest and `raw/requests.jsonl` |
| Timeout / network error | `unreachable` | Manifest row only; the tool cannot classify it |

**What a 200 means per file** (401/403 always produces the "exists but is
protected" info finding; 404 always produces nothing but a manifest row):

| File | 200/204 result |
|---|---|
| `robots.txt` | Directive table (info). Escalates to **medium** if any `Disallow`/`Allow` value contains sensitive keywords (`admin`, `backup`, `config`, `api`, ...) — flagged values are listed in `sensitive_entries`. Paths are seeded into INFO-04 for live verification. |
| `sitemap.xml` | info — "Metafile exposed"; sitemaps enumerate real URLs |
| `sitemap_index.xml` | info — same as above |
| `security.txt` | info — parsed `Contact:` field(s) |
| `.well-known/security.txt` | info — same as above |
| `.well-known/change-password` | info — reveals the password-change route (rare) |
| `.well-known/openid-configuration` | info — auth server configuration disclosed |
| `humans.txt` | info — team/author info |
| `crossdomain.xml` | **low** if a `<allow-access-from domain="*">` wildcard is present, else info |
| `clientaccesspolicy.xml` | low — legacy client-access policy exposed |
| `.git/HEAD` | **critical** — content must start with `ref:` or be a 40-char hash; the repository may be fully downloadable |
| `.svn/entries` | **high** — Subversion metadata |
| `.hg/requires` | **high** — Mercurial metadata |
| `.env` | **critical** — variable names are extracted into the summary (`DB_PASSWORD`, ...) |
| `web.config` | **high** — IIS configuration |
| `.DS_Store` | **low** — macOS directory listing |

Note that a file's reported finding severity comes from this table, not from
the manifest table — the manifest's `severity` column shows the *potential* of
the file regardless of the outcome.

**Reading the "Metafile probe summary" finding** (always present, info):

- The one-line count `N exposed, M restricted, K absent` summarises the run.
- The manifest table lists every probed path with `status`, `bytes`,
  `classification`, and its evidence file when exposed.

**How to read your result:**

- `robots.txt` at medium → the `sensitive_entries` list is the point; with
  `--active`, cross-check whether INFO-04 confirms those paths are live. A
  plain robots.txt (info) is normal configuration, not a vulnerability.
- `.env` at 200 → treat every variable name listed as compromised and rotate.
- 403 on `.env`/`.git/HEAD` → the file almost certainly exists. Do not treat
  it as absent; retry with path variations (case, trailing slash) manually.
- No `security.txt` → informational gap (RFC 9116), not a vulnerability;
  recommend adding one in the report.
- An empty-but-200 robots.txt may be classified `absent (content check
  failed)` — fetch it manually and decide; the tool errs toward fewer
  false positives, not coverage.

### Sanity checks on any run

- Open `report.md` first: the **Coverage table** tells you each module's
  status (`completed` / `skipped` / `failed`) in one row per test.
- `skipped` = doesn't apply without a flag or a dependency (most often
  INFO-04 without `--active`). `failed` = the module errored but the rest of
  the run continued; the error message is in the report and `findings.json`.
- Every finding lists its evidence files under `raw/`. **A finding without
  evidence backing should not exist** — if you ever see one, it's a tool bug.
- Check `raw/requests.jsonl` for entries with `"off_scope_final": true`; the
  scope guard records (does not follow) unexpected cross-domain redirects.
- Spot-check 2–3 low/info findings against their evidence files; format-based
  secret matching (INFO-05) and path probing (INFO-09) can produce candidates
  that vanish on manual review.

### What the tool will never do

- Confirm exploitability or fabricate a verdict — it produces **evidence-backed
  candidate leads**; INFO-01, INFO-06, INFO-07, and INFO-10 always need human
  validation (each module appends a `- [ ]` checklist to the report).
- Report findings that aren't tied to a WSTG ID, or contact hosts outside your
  declared scope.

## Reading the report

`report.md` contains:

1. A metadata header (target, duration, active flag).
2. A severity summary table.
3. A coverage table: one row per WSTG test, its status, and finding counts.
4. Per-module sections: each finding has a severity tag, summary, details
   (tables, Mermaid diagrams), and links to evidence files in `raw/`.
5. A `- [ ]` manual follow-up checklist per module.

Severities used: `critical`, `high`, `medium`, `low`, `info`.

`findings.json` mirrors the same data for automation:

```json
{
  "meta": { "target": "https://example.com", "active": true, "...": "..." },
  "summary": { "findings_total": 23, "by_severity": { "critical": 2 }, "artifacts": ["raw/..."] },
  "modules": [
    {
      "wstg_id": "WSTG-INFO-03",
      "status": "completed",
      "findings": [
        { "title": "Environment file with credentials...", "severity": "critical", "evidence": ["raw/INFO-03..env.txt"] }
      ],
      "manual_followup": ["..."]
    }
  ]
}
```

## Exit status and failure handling

- Modules run independently; a failure in one module is recorded as
  `"status": "failed"` with the error message and does not abort the run.
- Unreachable homepage, missing optional dependencies, and blocked recon
  providers produce manual follow-up notes instead of crashes.
- Wayback CDX can be slow from some networks; if it times out the report links
  the manual query URL.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Missing dependency 'requests'` | `pip install -r requirements.txt` |
| `[warn] PyYAML not installed; ignoring config.yaml` | `pip install PyYAML` or pass settings via CLI flags |
| INFO-01 reports no subdomains | crt.sh may be unreachable; open the link in the report manually |
| INFO-06 misses entry points | SPA/JS-rendered app; use a browser/proxy (see checklist in the report) |
| INFO-04 finds nothing | try `--only INFO-04 --active` with a larger `scan.wordlist` |
| TLS certificate shows no issuer | Python could not parse the PEM; attach `raw/INFO-10.tls.pem` to your notes |

## Adding a module

1. Create `modules/info11_yourtest.py` exposing:

   ```python
   WSTG_ID = "WSTG-INFO-11"
   TITLE = "..."
   REFERENCE = "https://owasp.org/..."
   ACTIVE = False

   def run(ctx):
       resp = ctx.http.get(ctx.base_url)
       evidence = ctx.artifact("INFO-11.homepage.txt", resp.text)
       ctx.finding(WSTG_ID, "Title", "info", "Summary", {"key": "value"}, [evidence])
       ctx.manual(WSTG_ID, "Manual step...")
   ```

2. Register it in `modules/__init__.py` (import + `MODULES` list).
3. Use `ctx.http` for all requests so scope guard, rate limiting, and the
   request audit trail apply automatically.

## Legal

This tool is intended for authorized security testing only. Unauthorized
scanning of systems you do not own or have written permission to test may be
illegal in your jurisdiction.
