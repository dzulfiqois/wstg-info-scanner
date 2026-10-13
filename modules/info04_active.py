import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

from core.dns_tls import port_open, resolve_a
from core.util import extract_title, is_soft_404

WSTG_ID = "WSTG-INFO-04"
TITLE = "Attack Surface Identification"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Attack_Surface_Identification"
ACTIVE = True

SENSITIVE_DIR_WORDS = ["admin", "backup", "config", "secret", "private", "internal", "dev", "staging", "test", "db", "sql", "dump", "token", "password", "env", "api", "console", "manage", "debug", "old", "tmp", "phpmyadmin", "server-status"]


def _load_words(ctx):
    config = ctx.config.get("info04", {})
    max_words = int(config.get("max_wordlist", 200))
    wordlist = ctx.config.get("scan", {}).get("wordlist", "wordlists/common.txt")
    path = Path(wordlist)
    if not path.is_absolute():
        path = ctx.project_root / path
    words = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    for discovered in ctx.data.get("discovered_paths", []):
        cleaned = discovered.strip("/")
        if cleaned and cleaned not in words:
            words.append(cleaned)
    return words[:max_words]


def run(ctx):
    m = WSTG_ID

    subdomains = ctx.data.get("subdomains", [])
    max_subs = int(ctx.config.get("info04", {}).get("max_subdomains", 100))
    live_hosts = []
    if subdomains:
        ctx.log(f"probing {min(len(subdomains), max_subs)} subdomain(s) for liveness")
        for sub in subdomains[:max_subs]:
            ips = resolve_a(sub, timeout=3)
            if not ips:
                continue
            for scheme in ("https", "http"):
                resp = ctx.http.get(f"{scheme}://{sub}/", timeout=5, allow_redirects=False)
                if resp is not None:
                    content_type = resp.headers.get("content-type", "")
                    title = extract_title(resp.text) if "html" in content_type else ""
                    live_hosts.append({"host": sub, "url": f"{scheme}://{sub}/", "status": resp.status_code, "server": resp.headers.get("Server", ""), "title": title, "ips": ips})
                    break
        if live_hosts:
            ctx.finding(
                m,
                "Live subdomains reachable over HTTP(S)",
                "info",
                f"{len(live_hosts)} of {len(subdomains)} CT-listed subdomain(s) responded.",
                {"table": [{"host": item["host"], "url": item["url"], "status": item["status"], "server": item["server"], "title": item["title"]} for item in live_hosts]},
            )
        else:
            ctx.finding(m, "No live subdomains detected", "info", f"{len(subdomains)} CT-listed subdomain(s) resolved but none responded to HTTP(S).", {})

    baseline = ctx.http.get(ctx.root_url.rstrip("/") + "/wstg-baseline-" + secrets.token_hex(4) + ".txt")
    if baseline is None:
        ctx.manual(m, "Baseline request failed; directory enumeration skipped.")
        return

    words = _load_words(ctx)
    ctx.log(f"directory enumeration with {len(words)} word(s)")

    def probe(word):
        url = ctx.root_url.rstrip("/") + "/" + word
        resp = ctx.http.get(url, allow_redirects=False)
        if resp is None:
            return None
        status = resp.status_code
        if status in (401, 403):
            return {"path": "/" + word, "status": status, "bytes": len(resp.content), "notes": "exists but restricted"}
        if status in (301, 302, 307, 308):
            return {"path": "/" + word, "status": status, "bytes": len(resp.content), "notes": f"redirect to {resp.headers.get('Location', '')[:120]}"}
        if status in (200, 204) and not is_soft_404(resp, baseline):
            content_type = resp.headers.get("content-type", "").split(";")[0]
            title = extract_title(resp.text) if "html" in content_type else ""
            return {"path": "/" + word, "status": status, "bytes": len(resp.content), "content_type": content_type, "title": title}
        return None

    hits = []
    with ThreadPoolExecutor(max_workers=max(1, ctx.threads)) as pool:
        for result in pool.map(probe, words):
            if result:
                hits.append(result)

    if hits:
        for hit in hits:
            path_lower = hit["path"].lower()
            hit["severity"] = "medium" if any(word in path_lower for word in SENSITIVE_DIR_WORDS) and hit["status"] in (200, 204, 301, 302, 307, 308) else "info"
        evidence = ctx.artifact("INFO-04.directories.json", json.dumps(hits, indent=2))
        ctx.finding(
            m,
            "Directories and files discovered through enumeration",
            "medium" if any(hit["severity"] == "medium" for hit in hits) else "info",
            f"{len(hits)} path(s) responded outside the baseline 404.",
            {"table": [{"path": h["path"], "status": h["status"], "bytes": h.get("bytes"), "severity": h["severity"], "notes": h.get("notes", h.get("title", ""))} for h in sorted(hits, key=lambda h: h["path"])]},
            [evidence],
        )
        ctx.manual(m, "Manually verify each enumerated path; automated enumeration cannot tell a decoy from a sensitive resource.")
    else:
        ctx.finding(m, "Directory enumeration found no additional paths", "info", f"{len(words)} word(s) tested, all matched the 404 baseline.", {})

    ports = ctx.config.get("info04", {}).get("ports", [])
    if ports:
        ctx.log(f"port scan of {len(ports)} port(s)")
        with ThreadPoolExecutor(max_workers=max(1, min(ctx.threads, 20))) as pool:
            results = list(pool.map(lambda port: {"port": port, "open": port_open(ctx.host, port, timeout=2)}, ports))
        open_ports = [item for item in results if item["open"]]
        if open_ports:
            ctx.finding(
                m,
                "Open TCP ports on target host",
                "info",
                f"{len(open_ports)} port(s) open: {', '.join(str(item['port']) for item in open_ports)}. Banner-grab and map each to a service manually.",
                {"table": open_ports},
            )
        else:
            ctx.finding(m, "Port scan completed", "info", "No open ports among the tested set.", {})

    ctx.manual(m, "Virtual-host discovery needs DNS/hosts-file tricks (`ffuf -H 'Host: FUZZ.target'`); run it manually because it can reveal hidden applications.")
    ctx.manual(m, "Review any 401/403 responses with different HTTP methods and paths (trailing slash, case variations) before concluding they are inaccessible.")
