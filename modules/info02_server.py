import re
import secrets

WSTG_ID = "WSTG-INFO-02"
TITLE = "Fingerprint Web Server"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
ACTIVE = False

TECH_HEADERS = [
    "Server",
    "Via",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Backend-Server",
    "X-Runtime",
    "X-Drupal-Cache",
    "X-Served-By",
    "X-Server",
]

BANNER_SIGNATURES = [
    ("Microsoft-IIS", "Microsoft IIS"),
    ("nginx", "nginx"),
    ("openresty", "OpenResty"),
    ("Apache", "Apache HTTP Server"),
    ("LiteSpeed", "LiteSpeed"),
    ("Caddy", "Caddy"),
    ("cloudflare", "Cloudflare"),
    ("gunicorn", "Gunicorn"),
    ("uvicorn", "Uvicorn"),
    ("Werkzeug", "Werkzeug (Flask)"),
    ("Express", "Express"),
    ("SimpleHTTP", "Python SimpleHTTP"),
    ("Tomcat", "Apache Tomcat"),
    ("Jetty", "Jetty"),
    ("Kestrel", "Kestrel (ASP.NET Core)"),
]


def run(ctx):
    m = WSTG_ID
    resp = ctx.http.get(ctx.base_url)
    if resp is None:
        ctx.manual(m, "Homepage unreachable; server fingerprinting skipped.")
        return

    raw = [f"{resp.request.method} {resp.request.url} HTTP/1.1", ""]
    raw.append(f"HTTP {resp.status_code} {resp.reason}")
    raw.extend(f"{key}: {value}" for key, value in resp.headers.items())
    body_snippet = resp.text[:4000] if "text" in resp.headers.get("content-type", "") or "json" in resp.headers.get("content-type", "") else ""
    evidence = ctx.artifact("INFO-02.homepage.headers.txt", "\n".join(raw) + "\n\n" + body_snippet)

    tech = {header: resp.headers[header] for header in TECH_HEADERS if header in resp.headers}
    server = resp.headers.get("Server", "")
    if server:
        version_disclosed = bool(re.search(r"\d", server))
        ctx.finding(
            m,
            "Web server banner disclosed",
            "low" if version_disclosed else "info",
            f"`Server: {server}`. " + ("Version information is exposed, which helps attackers target known CVEs." if version_disclosed else "Banner present without an obvious version."),
            {"server": server, "discloses_version": version_disclosed},
            [evidence],
        )
    if tech:
        ctx.finding(
            m,
            "Technology-identifying response headers present",
            "info",
            f"{len(tech)} header(s) disclose backend technology.",
            {"table": [{"header": key, "value": value} for key, value in tech.items()]},
            [evidence],
        )

    version = {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2", 30: "HTTP/3"}.get(getattr(resp.raw, "version", None), "unknown")
    ctx.finding(m, "HTTP protocol version observed", "info", f"Server responded using {version}.", {"version": version})

    probe = ctx.root_url.rstrip("/") + "/wstg-" + secrets.token_hex(4) + ".txt"
    error_resp = ctx.http.get(probe)
    if error_resp is not None:
        combined = (error_resp.text[:6000] + " " + str(error_resp.headers)).lower()
        detected = sorted({name for token, name in BANNER_SIGNATURES if token.lower() in combined})
        error_raw = [f"GET {probe}", "", f"HTTP {error_resp.status_code} {error_resp.reason}"]
        error_raw.extend(f"{key}: {value}" for key, value in error_resp.headers.items())
        error_evidence = ctx.artifact("INFO-02.404.headers.txt", "\n".join(error_raw) + "\n\n" + error_resp.text[:4000])
        if detected:
            ctx.finding(
                m,
                "Server software leaked through error page",
                "low",
                f"404 page fingerprints server as: {', '.join(detected)}.",
                {"detected": detected, "status": error_resp.status_code},
                [error_evidence],
            )
        else:
            ctx.finding(
                m,
                "Error page fingerprint",
                "info",
                f"404 page returned status {error_resp.status_code} with no recognisable server signature.",
                {"status": error_resp.status_code},
                [error_evidence],
            )

    ctx.manual(m, "Confirm the server product/version with `whatweb`, `nmap -sV -p 80,443 <host>`, or Wappalyzer, since banners can be spoofed by proxies/CDNs.")
    ctx.manual(m, "Try malformed requests (long URI, invalid method, oversized headers) and compare error pages for version leaks.")
