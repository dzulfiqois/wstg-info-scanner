import json
import re

WSTG_ID = "WSTG-INFO-01"
TITLE = "Conduct Search Engine Reconnaissance for Information Leakage"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage"
ACTIVE = False

DORK_TEMPLATES = [
    "site:{domain} filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx",
    "site:{domain} filetype:sql OR filetype:db OR filetype:log OR filetype:bak OR filetype:env",
    "site:{domain} inurl:admin OR inurl:dashboard OR inurl:debug OR inurl:test",
    'site:{domain} "index of /"',
    'site:{domain} "api_key" OR "apikey" OR "access_token" OR "password"',
    "site:{domain} inurl:login OR inurl:signin OR inurl:register",
    "site:{domain} ext:yml OR ext:yaml OR ext:json OR ext:conf",
    'site:{domain} "stack trace" OR "exception" OR "sql syntax"',
    '"@{domain}" contact OR email',
]

WAYBACK_INTERESTING = re.compile(
    r"(\.(?:bak|old|backup|sql|db|zip|tar|gz|tgz|log|env|yml|yaml|json|xml|conf|config|swp|save)$)"
    r"|/(?:test|tests|dev|staging|debug|old|backup|backups|private|internal|admin)(/|$|\?)"
    r"|(?:^|[?&])(?:debug|test|admin|token|key|password)=",
    re.I,
)


HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def _wayback_links(domain, limit):
    url = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original,mimetype,statuscode,timestamp"
        f"&collapse=urlkey&limit={limit}"
    )
    return url


def run(ctx):
    m = WSTG_ID
    if ctx.is_ip:
        ctx.manual(m, "Target is an IP address; certificate transparency, Wayback and site: dorks do not apply. Use reverse-IP lookups (Shodan, Censys) manually.")
        return

    domain = ctx.domain
    subdomains = set()
    crt_resp = ctx.http.get(f"https://crt.sh/?q=%25.{domain}&output=json", external=True)
    if crt_resp is not None and crt_resp.ok:
        crt_evidence = ctx.artifact("INFO-01.crt.json", crt_resp.text)
        try:
            entries = crt_resp.json()
        except ValueError:
            entries = []
        for entry in entries:
            for name in (entry.get("name_value") or "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if not HOSTNAME_RE.match(name):
                    continue
                if name == domain or name.endswith("." + domain):
                    subdomains.add(name)
        if subdomains:
            sorted_subs = sorted(subdomains)
            ctx.data["subdomains"] = sorted_subs
            wildcard = [s for s in sorted_subs if s.count(".") > domain.count(".") + 1]
            ctx.finding(
                m,
                "Subdomains discovered via Certificate Transparency",
                "info",
                f"{len(sorted_subs)} subdomain(s) appear in CT logs for {domain}; verify which are live and in scope.",
                {
                    "table": [{"subdomain": s} for s in sorted_subs],
                    "deep_subdomains": wildcard[:50],
                    "source": "crt.sh",
                },
                [crt_evidence],
            )
            ctx.manual(m, "Cross-check CT results against DNS and confirm which subdomains are in scope before probing them.")
        else:
            ctx.finding(m, "Certificate Transparency query returned no subdomains", "info", f"No subdomains found in CT logs for {domain}.", {}, [crt_evidence])
    else:
        ctx.manual(m, f"crt.sh unreachable for {domain}; run manually: https://crt.sh/?q=%25.{domain}")

    limit = int(ctx.config.get("info01", {}).get("wayback_limit", 2000))
    max_hits = int(ctx.config.get("info01", {}).get("max_wayback_hits", 50))
    wb_resp = ctx.http.get(_wayback_links(domain, limit), external=True)
    if wb_resp is not None and wb_resp.ok:
        wb_evidence = ctx.artifact("INFO-01.wayback.json", wb_resp.text)
        try:
            rows = wb_resp.json()
        except ValueError:
            rows = []
        header = rows[0] if rows else []
        hits = []
        for row in rows[1:]:
            record = dict(zip(header, row)) if header else {}
            original = record.get("original", "")
            if WAYBACK_INTERESTING.search(original) or record.get("mimetype", "").startswith(("application/zip", "application/x-sql", "text/x-sql")):
                hits.append(
                    {
                        "url": original,
                        "mimetype": record.get("mimetype", ""),
                        "status": record.get("statuscode", ""),
                        "timestamp": record.get("timestamp", ""),
                    }
                )
        if hits:
            ctx.finding(
                m,
                "Historically indexed sensitive-looking URLs (Wayback Machine)",
                "medium",
                f"{len(hits)} archived URL(s) match backup/config/debug patterns. Verify whether they are still reachable: archived secrets may persist on the live host.",
                {"table": hits[:max_hits]},
                [wb_evidence],
            )
        else:
            ctx.finding(m, "Wayback Machine query completed", "info", f"{max(len(rows) - 1, 0)} archived URL(s) reviewed, no high-signal patterns matched.", {}, [wb_evidence])
    else:
        ctx.manual(m, f"Wayback CDX API unreachable; run manually: http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json")

    dorks = []
    for template in DORK_TEMPLATES:
        query = template.format(domain=domain)
        dorks.append(
            {
                "query": query,
                "google": "https://www.google.com/search?q=" + query.replace(" ", "+").replace('"', "%22"),
                "bing": "https://www.bing.com/search?q=" + query.replace(" ", "+").replace('"', "%22"),
            }
        )
    dork_evidence = ctx.artifact("INFO-01.dorks.json", json.dumps(dorks, indent=2))
    ctx.finding(
        m,
        "Search engine dork set generated",
        "info",
        f"{len(dorks)} dork queries prepared. Search engines block automated scraping, so these are provided as links for manual review.",
        {"table": [{"query": d["query"], "google": d["google"]} for d in dorks]},
        [dork_evidence],
    )
    ctx.manual(m, "Run each dork link and review results for documents, backups, credentials, and error pages. Optionally wire Google CSE / Bing API keys into config for automation.")
    ctx.manual(m, "Check code-sharing sites manually: GitHub/GitLab code search for the domain, plus pastebin-style sites for leaked credentials.")
    ctx.manual(m, "Review archived pages for emails, internal hostnames, and comments removed from the live site.")
