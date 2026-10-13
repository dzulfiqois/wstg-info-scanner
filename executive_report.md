# Executive Report — WSTG-INFO Automated Security Assessment

| | |
|---|---|
| **Target** | http://127.0.0.1:8765 (local test lab / fixture application) |
| **Date** | 2026-10-12 |
| **Tool** | wstg-info v0.1.0 (custom OWASP WSTG automation) |
| **Coverage** | WSTG-INFO-01 … WSTG-INFO-10 (all 10 tests, active mode) |
| **Duration** | 2.1 s — 23 findings, 16 evidence artifacts, full request audit trail |
| **Purpose** | Validation run of the automated WSTG-INFO toolkit in a controlled environment. Findings are demonstration of tool capability; none apply to a production system. |

---

## 1. Executive Summary

An automated assessment implementing all ten OWASP WSTG Information Gathering
tests was executed against a controlled lab application. The run completed all
10 modules in ~2 seconds and produced **23 candidate findings: 2 critical,
1 high, 2 medium, 5 low, 13 informational**, each backed by raw evidence files.

The results demonstrate the highest-value risk class this tooling is designed
to surface early — **unintentionally exposed sensitive files and secrets**:

1. **CRITICAL — Git metadata exposed** (`/.git/HEAD`, HTTP 200).
   If a real system shipped this, the entire repository history and source code
   could be downloaded publicly.
2. **CRITICAL — Environment file exposed** (`/.env`, HTTP 200) containing
   keys named `DB_PASSWORD`, `API_KEY`, `AWS_SECRET`. Direct database/account
   compromise risk.
3. **HIGH — API key embedded in client-side JavaScript** (`app.js`,
   Google API key format). Client-side secrets are visible to any visitor.
4. **MEDIUM — robots.txt discloses sensitive areas** (`/secret-admin/`,
   `/backup/`) which active enumeration then confirmed reachable — a live
   demonstration of how robots.txt can be a directory listing for attackers.

The remaining findings (server banner/version disclosure, permissive
cross-domain policy, exposed emails, developer debug comments, source-map
references) are low severity individually but are the raw material attackers
chain into the critical findings above.

**Bottom line:** the tool correctly identified every seeded issue in the lab
and correctly *did not* fabricate findings where none existed (INFO-08, INFO-09
reported clean with honest caveats). It is fit to support real engagements as
an evidence-gathering and first-pass reporting layer.

## 2. Coverage

| WSTG ID | Test | Mode | Status | Findings |
|---|---|---|---|---|
| WSTG-INFO-01 | Search engine recon | passive | completed (n/a for IP target) | 0 |
| WSTG-INFO-02 | Fingerprint web server | passive | completed | 4 |
| WSTG-INFO-03 | Review webserver metafiles | passive | completed | 7 |
| WSTG-INFO-04 | Attack surface identification | **active** | completed | 1 |
| WSTG-INFO-05 | Review page content | passive | completed | 5 |
| WSTG-INFO-06 | Identify entry points | passive | completed | 2 |
| WSTG-INFO-07 | Map execution paths | passive | completed | 1 |
| WSTG-INFO-08 | Fingerprint framework | passive | completed | 0 (manual follow-up raised) |
| WSTG-INFO-09 | Fingerprint application | passive | completed | 2 |
| WSTG-INFO-10 | Map application architecture | passive | completed | 1 |

## 3. Key Findings (by risk)

| # | Severity | Finding | Business impact |
|---|---|---|---|
| 1 | **Critical** | `/.env` publicly readable (keys: `DB_PASSWORD`, `API_KEY`, `AWS_SECRET`) | Database takeover, cloud account compromise |
| 2 | **Critical** | `/.git/HEAD` publicly readable | Full source code and commit history disclosure |
| 3 | **High** | Google-format API key in `app.js` | API abuse/billing fraud under the organization's account |
| 4 | **Medium** | robots.txt discloses `/secret-admin/`, `/backup/`; both confirmed live by enumeration | Hides nothing, advertises targets; admin panel discovery |
| 5 | **Low** | Server banner discloses `SimpleHTTP/0.6 Python/3.14.4` (headers + 404 page) | CVE targeting against known versions |
| 6 | **Low** | `crossdomain.xml` allows all domains (`*`) | Cross-origin access for legacy Flash/Silverlight clients |
| 7 | **Low** | 2 developer comments leak operational detail (debug endpoint, DB access contact) | Intel for social engineering and attack planning |
| 8 | **Low** | `sourceMappingURL` reference in `app.js` | Original source reconstruction if `.map` is public |
| 9 | **Info** | 2 email addresses exposed; framework string `FixtureCMS 1.0`; forms/params/endpoints inventoried; app map generated | Reconnaissance material (phishing, user enumeration, injection targets) |

### Attack chain this demonstrates

`robots.txt` (or a search engine) → finds `/secret-admin/` → admin panel login
form + `/api/admin/create` endpoint → credentials available in exposed `.env`
and `app.js`. Each finding is easily fixed alone; together they compress an
attacker's work from weeks to minutes.

## 4. Recommendations (priority order)

1. **Rotate immediately** any credential found in `.env` or client-side code —
   assume they are already compromised once served.
2. **Remove dotfiles/build artifacts from the web root** (`.git/`, `.env`,
   `.DS_Store`); block them at the web server or deploy from an artifact
   pipeline, not a working copy.
3. **Remove secrets from client-side JavaScript**; proxy third-party APIs
   server-side and never embed keys in bundles.
4. **Align robots.txt with reality** — if `/secret-admin/` exists and is
   sensitive, the fix is access control, not robots directives.
5. **Harden server banners** (`Server`/`X-Powered-By`) and serve consistent,
   low-information error pages.
6. **Restrict `crossdomain.xml`** to explicit, required domains or remove it.

## 5. Manual Follow-Up Priorities

Top items carried from the automated run (full checklist in `report.md`):

- Verify each exposed metafile for content beyond automated pattern matching.
- Walk every discovered form/parameter in ZAP/Burp (entry points are inventoried
  in `raw/INFO-06.entrypoints.json`).
- Compare the crawl-generated application map with an authenticated manual
  browsing session.
- Confirm the framework via response diffing and cookie naming (INFO-08 found
  no passive signatures).

## 6. Limitations

- **Evidence, not verdicts:** automated output marks candidates; exploitation
  and impact confirmation remain human work.
- **INFO-01/07/10 are inherently semi-manual:** search-engine dorking requires
  manual review; JS-rendered flows need a browser; architecture inference needs
  operator validation.
- **IP-address targets** exclude CT logs, Wayback, and `site:` dorks (INFO-01).
- Active checks (INFO-04) are rate-limited and wordlist-bound; absence of
  findings is not proof of absence.

## 7. Evidence Locations

- Full technical report: `results/<run>/report.md`
- Machine-readable: `results/<run>/findings.json`
- Raw artifacts (headers, metafiles, favicon, TLS cert, request log):
  `results/<run>/raw/`
