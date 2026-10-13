import re
from urllib.parse import urlparse

from core.util import redact, safe_name
from ._common import extract_scripts, fetch, same_host, sample_pages

WSTG_ID = "WSTG-INFO-05"
TITLE = "Review Web Page Content for Information Leakage"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage"
ACTIVE = False

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
GENERATOR_RE = re.compile(r"""<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']""", re.I)
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")

SECRET_PATTERNS = [
    ("Private key block", "critical", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Generic secret assignment", "medium", re.compile(r"""(?i)\b(api[_-]?key|apikey|secret|client[_-]?secret|auth[_-]?token|access[_-]?token|password|passwd|pwd)\b\s*[:=]\s*["']?([A-Za-z0-9\-_./+]{6,})["']?""")),
    ("JWT", "medium", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    ("Internal IP address", "low", re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")),
]

SUSPICIOUS_COMMENT_WORDS = ["todo", "fixme", "hack", "password", "passwd", "secret", "token", "debug", "internal", "prod", "remove", "temporary", "credentials", "api key"]


def _scan_text(text):
    matches = {"secrets": [], "emails": [], "comments": [], "internal_ips": []}
    for name, severity, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if name == "Generic secret assignment":
                value = match.group(2)
            matches["secrets"].append({"type": name, "severity": severity, "value": value[:200]})
            if len(matches["secrets"]) > 200:
                break
    matches["emails"] = sorted(set(EMAIL_RE.findall(text)))[:100]
    matches["comments"] = [re.sub(r"\s+", " ", c).strip()[:300] for c in COMMENT_RE.findall(text)][:100]
    return matches


def run(ctx):
    m = WSTG_ID
    pages = sample_pages(ctx)
    if not pages:
        ctx.manual(m, "Homepage unreachable; content review skipped.")
        return

    js_urls = []
    for page_url, resp in pages:
        for script in extract_scripts(resp.text, page_url):
            if same_host(script, ctx.host, urlparse(ctx.base_url).port) and script.split("?")[0].lower().endswith((".js", ".mjs")):
                js_urls.append(script)
    js_urls = sorted(set(js_urls))[: ctx.max_js_files]

    sources = [(url, resp.text, ctx.artifact(f"INFO-05.{safe_name(urlparse(url).path)}.html", resp.text[:200000])) for url, resp in pages]
    for js_url in js_urls:
        resp = fetch(ctx, js_url)
        if resp is not None:
            sources.append((js_url, resp.text, ctx.artifact(f"INFO-05.{safe_name(urlparse(js_url).path)}.js", resp.text[:500000])))

    all_secrets = []
    all_emails = {}
    all_comments = []
    generators = {}
    sourcemaps = []
    internal_ips = {}

    for url, text, evidence in sources:
        found = _scan_text(text)
        for secret in found["secrets"]:
            if secret["type"] == "Internal IP address":
                internal_ips.setdefault(secret["value"], url)
                continue
            all_secrets.append({**secret, "source": url, "evidence": evidence})
        for email in found["emails"]:
            all_emails.setdefault(email, url)
        for comment in found["comments"]:
            all_comments.append({"source": url, "comment": comment, "evidence": evidence})
        generator = GENERATOR_RE.search(text)
        if generator:
            generators[url] = generator.group(1)
        for match in SOURCEMAP_RE.finditer(text):
            sourcemaps.append({"source": url, "map": match.group(1).strip()})

    if all_secrets:
        deduped = {}
        specific_values = {secret["value"] for secret in all_secrets if secret["type"] != "Generic secret assignment"}
        for secret in all_secrets:
            if secret["type"] == "Generic secret assignment" and secret["value"] in specific_values:
                continue
            key = (secret["type"], secret["value"])
            if key not in deduped:
                deduped[key] = secret
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        worst = min(deduped.values(), key=lambda s: severity_rank.get(s["severity"], 9))["severity"]
        ctx.finding(
            m,
            "Potential secrets exposed in page/JS content",
            worst,
            f"{len(deduped)} potential secret(s) matched. Values are {'shown in full' if ctx.show_secrets else 'redacted'}; verify before treating as real.",
            {
                "table": [
                    {"type": s["type"], "severity": s["severity"], "value": redact(s["value"], ctx.show_secrets), "source": s["source"]}
                    for s in list(deduped.values())[:50]
                ]
            },
            sorted({s["evidence"] for s in deduped.values()}),
        )
    if all_emails:
        ctx.finding(
            m,
            "Email addresses exposed in page content",
            "info",
            f"{len(all_emails)} unique email(s) found; useful for phishing/social engineering and user enumeration.",
            {"table": [{"email": redact(email, ctx.show_secrets, keep=3, tail=0), "source": source} for email, source in list(all_emails.items())[:50]]},
        )
    flagged_comments = [c for c in all_comments if any(word in c["comment"].lower() for word in SUSPICIOUS_COMMENT_WORDS)]
    if flagged_comments:
        ctx.finding(
            m,
            "Suspicious developer comments in page/JS content",
            "low",
            f"{len(flagged_comments)} comment(s) mention debug/secret/internal concepts.",
            {"table": [{"source": c["source"], "comment": c["comment"]} for c in flagged_comments[:50]]},
        )
    elif all_comments:
        ctx.finding(m, "HTML comments present", "info", f"{len(all_comments)} comment(s) collected; none matched sensitive keywords.", {"table": [{"source": c["source"], "comment": c["comment"][:120]} for c in all_comments[:30]]})
    if generators:
        ctx.finding(m, "Framework disclosed via meta generator", "info", "; ".join(f"{url} -> {value}" for url, value in generators.items()), {"table": [{"url": url, "generator": value} for url, value in generators.items()]})
    if sourcemaps:
        ctx.finding(m, "JavaScript source maps referenced", "low", f"{len(sourcemaps)} sourceMappingURL reference(s); if the .map files are public, original source can be reconstructed.", {"table": sourcemaps[:30]})
    if internal_ips:
        ctx.finding(m, "Internal IP addresses disclosed in content", "low", f"{len(internal_ips)} internal IP(s) found.", {"table": [{"ip": ip, "source": source} for ip, source in list(internal_ips.items())[:50]]})

    ctx.manual(m, "Read every flagged comment and JS file manually; automated pattern matching misses bespoke leaks (build paths, feature flags, hidden endpoints).")
