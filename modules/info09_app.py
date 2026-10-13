import json
import secrets

from core.mmh3 import favicon_hash
from core.util import extract_title, is_soft_404, safe_name

WSTG_ID = "WSTG-INFO-09"
TITLE = "Fingerprint Web Application"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/09-Fingerprint_Web_Application"
ACTIVE = False

KNOWN_PATHS = [
    ("wp-login.php", "WordPress login page", "medium"),
    ("wp-admin/", "WordPress admin", "medium"),
    ("administrator/", "Joomla administrator", "medium"),
    ("actuator", "Spring Boot Actuator index", "high"),
    ("actuator/env", "Spring Boot environment dump", "critical"),
    ("actuator/health", "Spring Boot health endpoint", "low"),
    ("phpinfo.php", "phpinfo() output", "high"),
    ("server-status", "Apache server-status", "high"),
    ("server-info", "Apache server-info", "high"),
    ("console", "Generic admin/debug console", "medium"),
    ("swagger-ui.html", "Swagger UI", "low"),
    ("swagger/index.html", "Swagger UI", "low"),
    ("v2/api-docs", "API documentation", "low"),
    ("v3/api-docs", "API documentation", "low"),
    ("api-docs", "API documentation", "low"),
    ("graphql", "GraphQL endpoint", "info"),
    ("package.json", "Node.js application manifest", "medium"),
    ("composer.json", "PHP application manifest", "medium"),
    ("CHANGELOG.md", "Changelog", "low"),
    ("README.md", "Readme", "low"),
    ("login", "Login page", "info"),
]


def _content_confirms(path, resp):
    body = resp.text
    content_type = resp.headers.get("content-type", "")
    if path.startswith("actuator/env"):
        return '"propertySources"' in body or '"activeProfiles"' in body
    if path.startswith("actuator"):
        return '"_links"' in body or '"status"' in body
    if path == "phpinfo.php":
        return "phpinfo()" in body or "PHP Version" in body
    if path == "server-status":
        return "Apache Server Status" in body
    if path == "server-info":
        return "Server Information" in body or "Apache Server" in body
    if path.endswith(".json"):
        stripped = body.lstrip()
        return stripped.startswith("{") and ('"name"' in body or '"require"' in body or '"dependencies"' in body)
    if path.endswith(".md"):
        return body.lstrip().startswith("#")
    if "graphql" in path:
        return "query" in body.lower() or "graphql" in body.lower() or resp.status_code in (400, 405)
    return True


def run(ctx):
    m = WSTG_ID
    baseline = ctx.http.get(ctx.root_url.rstrip("/") + "/wstg-baseline-" + secrets.token_hex(4) + ".txt")

    home = ctx.http.get(ctx.base_url)
    if home is not None:
        title = extract_title(home.text)
        meta_names = {}
        if title:
            meta_names["title"] = title
        for meta in ("application-name", "generator", "description"):
            marker = f'name="{meta}"'
            if marker in home.text:
                start = home.text.find(marker)
                snippet = home.text[start : start + 200]
                if "content=" in snippet:
                    value = snippet.split("content=", 1)[1].split('"')[1] if '"' in snippet.split("content=", 1)[1] else ""
                    if value:
                        meta_names[meta] = value[:120]
        if meta_names:
            ctx.finding(m, "Application metadata from homepage", "info", "; ".join(f"{key}: {value}" for key, value in meta_names.items()), meta_names)

    favicon = ctx.http.get(ctx.root_url.rstrip("/") + "/favicon.ico")
    if favicon is not None and favicon.status_code == 200 and favicon.content and not is_soft_404(favicon, baseline):
        content_type = favicon.headers.get("content-type", "")
        if "image" in content_type or favicon.content[:4] in (b"\x00\x00\x01\x00", b"\x89PNG"):
            digest = favicon_hash(favicon.content)
            evidence = ctx.artifact("INFO-09.favicon.ico", favicon.content)
            ctx.finding(
                m,
                "Favicon fingerprint computed",
                "info",
                f"Favicon hash `{digest}`. Search Shodan for related hosts: this hash identifies the product if it ships a stock favicon.",
                {
                    "favicon_mmh3": digest,
                    "shodan_search": f"https://www.shodan.io/search?query=http.favicon.hash%3A{digest}",
                    "content_type": content_type,
                },
                [evidence],
            )

    results = []
    for path, description, severity in KNOWN_PATHS:
        url = ctx.root_url.rstrip("/") + "/" + path
        resp = ctx.http.get(url)
        if resp is None:
            continue
        if is_soft_404(resp, baseline) or resp.status_code not in (200, 401, 403):
            continue
        if resp.status_code in (401, 403):
            results.append({"path": "/" + path, "status": resp.status_code, "description": description, "severity": "info", "notes": "exists but restricted"})
            continue
        if resp.status_code == 200 and not _content_confirms(path, resp):
            continue
        evidence = ctx.artifact(f"INFO-09.{safe_name(path)}.txt", resp.text[:20000])
        results.append({"path": "/" + path, "status": resp.status_code, "description": description, "severity": severity, "evidence": evidence, "bytes": len(resp.content)})

    if results:
        worst_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        worst = min(results, key=lambda r: worst_rank.get(r["severity"], 9))["severity"]
        ctx.finding(
            m,
            "Known application files/endpoints identified",
            worst,
            f"{len(results)} known path(s) matched. Review exposed admin, manifest, and actuator endpoints before reporting.",
            {"table": [{"path": r["path"], "status": r["status"], "severity": r["severity"], "description": r["description"]} for r in results]},
            [r["evidence"] for r in results if r.get("evidence")],
        )
        ctx.manual(m, "Open each matched path and confirm whether it exposes data, grants access, or reveals install/build information.")
    else:
        ctx.finding(m, "No known application files detected", "info", "Curated path probe found no default/known files. This does not rule out a custom application or rewritten routing.", {}, [])

    report_evidence = ctx.artifact("INFO-09.known_paths.json", json.dumps(results, indent=2))
    ctx.manual(m, "Fingerprint the application through behaviour: default error pages, password reset flows, cookie naming, and API error formats.")
