import json
import re
import secrets

from core.util import is_soft_404, safe_name

WSTG_ID = "WSTG-INFO-03"
TITLE = "Review Webserver Metafiles for Information Leakage"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"
ACTIVE = False

METAFILES = [
    ("robots.txt", "info", None),
    ("sitemap.xml", "info", None),
    ("sitemap_index.xml", "info", None),
    ("security.txt", "info", None),
    (".well-known/security.txt", "info", None),
    (".well-known/change-password", "info", None),
    (".well-known/openid-configuration", "info", None),
    ("humans.txt", "info", None),
    ("crossdomain.xml", "low", "Flash cross-domain policy exposed"),
    ("clientaccesspolicy.xml", "low", "Silverlight/Flash cross-domain policy exposed"),
    (".git/HEAD", "critical", "Exposed Git metadata; source code may be downloadable via /.git/"),
    (".svn/entries", "high", "Exposed Subversion metadata"),
    (".hg/requires", "high", "Exposed Mercurial metadata"),
    (".env", "critical", "Environment file with credentials/configuration exposed"),
    ("web.config", "high", "IIS configuration file may leak connection strings"),
    (".DS_Store", "low", "macOS metadata file discloses directory contents"),
]

SENSITIVE_KEYWORDS = [
    "admin",
    "backup",
    "config",
    "secret",
    "private",
    "internal",
    "dev",
    "staging",
    "test",
    "db",
    "sql",
    "dump",
    "api",
    "token",
    "password",
    "login",
    "manage",
    "debug",
    "old",
    "tmp",
]


def _text_valid(resp):
    body = resp.text
    path = resp.request.path_url.lower()
    if path.endswith(".git/head"):
        return body.startswith("ref:") or bool(re.fullmatch(r"[0-9a-f]{40}\s*", body.strip()))
    if ".svn/entries" in path:
        return "<entry" in body[:1000] or bool(re.match(r"^\d+", body.strip()))
    if path.endswith(".hg/requires"):
        return "revlog" in body or "store" in body
    if path.endswith(".env"):
        return bool(re.search(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", body, re.M))
    if path.endswith("web.config"):
        return "<configuration" in body[:2000]
    if path.endswith("crossdomain.xml"):
        return "cross-domain-policy" in body
    if path.endswith("clientaccesspolicy.xml"):
        return "access-policy" in body
    if path.endswith("robots.txt"):
        return bool(re.search(r"^(user-agent|disallow|allow|sitemap)\s*:", body, re.I | re.M))
    if path.endswith(".xml"):
        return body.lstrip().startswith("<?xml") or "<" in body[:200]
    return True


def _parse_robots(body):
    directives = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() in ("disallow", "allow", "sitemap"):
            directives.append({"directive": key.strip().capitalize(), "value": value.strip()})
    return directives


def run(ctx):
    m = WSTG_ID
    baseline = ctx.http.get(ctx.root_url.rstrip("/") + "/wstg-baseline-" + secrets.token_hex(4) + ".txt")
    discovered = []
    findings = []
    manifest = []

    for path, severity, description in METAFILES:
        url = ctx.root_url.rstrip("/") + "/" + path
        resp = ctx.http.get(url)
        if resp is None:
            manifest.append({"path": path, "status": "unreachable"})
            continue
        status = resp.status_code
        entry = {"path": path, "status": status, "bytes": len(resp.content), "severity": severity}
        if status in (401, 403):
            manifest.append({**entry, "classification": "restricted"})
            findings.append(
                {
                    "path": path,
                    "severity": "info",
                    "title": f"{path} exists but is protected",
                    "summary": f"Server returned {status} for /{path}; the file exists but access is denied.",
                    "details": {"status": status},
                }
            )
            continue
        if status not in (200, 204) or is_soft_404(resp, baseline):
            manifest.append({**entry, "classification": "absent"})
            continue
        if not _text_valid(resp):
            manifest.append({**entry, "classification": "absent (content check failed)"})
            continue

        evidence = ctx.artifact(f"INFO-03.{safe_name(path)}.txt", resp.text[:20000])
        manifest.append({**entry, "classification": "exposed", "evidence": evidence})

        if path == "robots.txt":
            directives = _parse_robots(resp.text)
            for item in directives:
                if item["directive"] in ("Disallow", "Allow") and item["value"] not in ("", "/"):
                    discovered.append("/" + item["value"].lstrip("/"))
            flagged = [item for item in directives if any(word in item["value"].lower() for word in SENSITIVE_KEYWORDS)]
            ctx.finding(
                m,
                "robots.txt exposes path structure",
                "medium" if flagged else "info",
                f"{len(directives)} directive(s) parsed" + (f"; {len(flagged)} point at sensitive areas." if flagged else "."),
                {
                    "table": directives[:100],
                    "sensitive_entries": [item["value"] for item in flagged][:50],
                },
                [evidence],
            )
        elif path in (".git/HEAD", ".env", ".svn/entries", ".hg/requires", "web.config"):
            title = description or "Sensitive metadata exposed"
            summary = f"/{path} is publicly readable."
            if path == ".env":
                keys = re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=", resp.text, re.M)
                summary += f" Keys present: {', '.join(keys[:15]) or 'none parsed'}."
            ctx.finding(m, title, severity, summary, {"path": path, "status": status}, [evidence])
        elif path == "crossdomain.xml":
            permissive = "*" in resp.text
            ctx.finding(
                m,
                "Cross-domain policy file exposed",
                "low" if permissive else "info",
                "/crossdomain.xml is served" + (" and allows all domains (`*`)." if permissive else "."),
                {"permissive": permissive},
                [evidence],
            )
        elif path.endswith("security.txt"):
            contacts = re.findall(r"(?im)^contact:\s*(.+)$", resp.text)
            ctx.finding(m, "security.txt published", "info", f"Contact(s): {', '.join(contacts) or 'n/a'}.", {"path": path}, [evidence])
        else:
            ctx.finding(m, f"Metafile exposed: /{path}", "info", f"/{path} is reachable ({status}). Review content for leaked information.", {"path": path}, [evidence])

    for item in findings:
        ctx.finding(m, item["title"], item["severity"], item["summary"], item["details"], [])

    manifest_json = ctx.artifact("INFO-03.manifest.json", json.dumps(manifest, indent=2))
    ctx.finding(
        m,
        "Metafile probe summary",
        "info",
        f"{sum(1 for item in manifest if item.get('classification') == 'exposed')} exposed, "
        f"{sum(1 for item in manifest if item.get('classification') == 'restricted')} restricted, "
        f"{sum(1 for item in manifest if item.get('classification') == 'absent')} absent.",
        {"table": manifest},
        [manifest_json],
    )

    if discovered:
        ctx.data["discovered_paths"] = sorted(set(discovered))
        ctx.finding(
            m,
            "Paths discovered from robots.txt",
            "info",
            f"{len(set(discovered))} path(s) seeded for active enumeration (INFO-04).",
            {"paths": sorted(set(discovered))[:100]},
        )

    ctx.manual(m, "Browse every exposed metafile and look for emails, internal hostnames, build metadata, and credentials.")
    ctx.manual(m, "Check for additional metafiles relevant to the stack: /manifest.json, /asset-manifest.json, /browserconfig.xml, sitemaps referenced from robots.txt.")
