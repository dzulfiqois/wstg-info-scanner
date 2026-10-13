import json
from urllib.parse import urlparse

from core.dns_tls import dns_records, tls_cert_info
from ._common import fetch

WSTG_ID = "WSTG-INFO-10"
TITLE = "Map Application Architecture"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture"
ACTIVE = False

CDN_TOKENS = ["cloudflare", "fastly", "akamai", "cloudfront", "azurefd", "sucuri", "incapdns", "edgekey", "edgesuite", "llnwd", "stackpath", "bunnycdn"]

WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-amz-cf-id": "AWS CloudFront",
    "x-fastly-request-id": "Fastly",
    "x-azure-ref": "Azure Front Door",
    "x-cdn": "Generic CDN",
    "x-cache": "CDN cache layer",
}

SERVER_TOKENS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "nginx": "nginx",
    "apache": "Apache",
    "iis": "Microsoft IIS",
    "openresty": "OpenResty",
    "envoy": "Envoy proxy",
    "istio": "Istio service mesh",
    "haproxy": "HAProxy",
    "lighttpd": "lighttpd",
}


def run(ctx):
    m = WSTG_ID
    layers = []
    findings_added = False
    records = {} if ctx.is_ip else dns_records(ctx.domain)

    if records:
        evidence = ctx.artifact("INFO-10.dns.json", json.dumps(records, indent=2))
        ctx.finding(
            m,
            "DNS records for the domain",
            "info",
            "Infrastructure hints from public DNS (nameservers, mail, TXT records).",
            {"table": [{"type": key, "values": ", ".join(str(v) for v in values[:6])} for key, values in records.items()]},
            [evidence],
        )
        findings_added = True
        txt_records = " ".join(records.get("TXT", []))
        if txt_records and "v=spf1" not in txt_records.lower():
            ctx.manual(m, f"No SPF record seen for {ctx.domain}; verify email security configuration manually.")
    nameservers = records.get("NS", [])
    if nameservers:
        layers.append("NS: " + ", ".join(str(ns)[:40] for ns in nameservers[:2]))

    cdn_detected = None
    cname_chain = records.get("CNAME", []) + records.get("CNAME_CHAIN", [])
    for entry in cname_chain:
        lowered = str(entry).lower()
        for token in CDN_TOKENS:
            if token in lowered:
                cdn_detected = token
                break
        if cdn_detected:
            break

    home = fetch(ctx, ctx.base_url)
    waf_headers = {}
    server_product = ""
    if home is not None:
        for header, product in WAF_HEADERS.items():
            if header in home.headers:
                waf_headers[header] = product
        server_header = home.headers.get("Server", "").lower()
        for token, product in SERVER_TOKENS.items():
            if token in server_header:
                server_product = product
                break
        if waf_headers or cdn_detected:
            provider = ", ".join(sorted(set(waf_headers.values()))) or cdn_detected
            ctx.finding(
                m,
                "CDN/WAF in front of the application",
                "info",
                f"Detected: {provider}. Origin protection, caching, and header handling should be tested manually.",
                {"waf_headers": waf_headers, "cname_chain": cname_chain[:10], "server": home.headers.get("Server", "")},
            )
            findings_added = True
            layers.append(f"CDN/WAF: {provider}")
        if server_product:
            layers.append(f"Origin server hint: {server_product}")

    cert = tls_cert_info(ctx.host, 443)
    if cert.get("error"):
        if urlparse(ctx.base_url).scheme == "https":
            ctx.manual(m, f"TLS certificate could not be retrieved: {cert['error']}")
    else:
        evidence = ctx.artifact("INFO-10.tls.pem", cert.pop("pem", ""))
        days_left = cert.get("days_left")
        severity = "info"
        if days_left is not None and days_left < 0:
            severity = "high"
        elif days_left is not None and days_left < 30:
            severity = "medium"
        if cert.get("verified") is False:
            severity = "medium" if severity == "info" else severity
        ctx.finding(
            m,
            "TLS certificate inventory",
            severity,
            f"Issuer: {cert.get('issuer', 'n/a')}; expires {cert.get('not_after', 'n/a')} ({days_left} days); verification: {'passed' if cert.get('verified') else cert.get('verify_error', 'unknown')}.",
            {
                "issuer": cert.get("issuer"),
                "subject": cert.get("subject"),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "days_left": days_left,
                "verified": cert.get("verified"),
                "verify_error": cert.get("verify_error"),
                "sans": (cert.get("sans") or [])[:30],
            },
            [evidence],
        )
        findings_added = True
        layers.append(f"TLS: {cert.get('issuer', 'unknown issuer')}")

    diagram = ["flowchart LR", '    C["Client / Attacker"]']
    previous = "C"
    for index, layer in enumerate(layers):
        node = f"L{index}"
        label = layer.replace('"', "'")
        diagram.append(f'    {node}["{label}"]')
        diagram.append(f"    {previous} --> {node}")
        previous = node
    diagram.append(f'    T["Target: {ctx.host}"]')
    diagram.append(f"    {previous} --> T")
    ctx.finding(m, "Architecture sketch (auto-generated)", "info", "Candidate architecture inferred from DNS, TLS and response headers. Validate against the real deployment.", {"mermaid": "\n".join(diagram)})
    if not findings_added and not layers:
        ctx.manual(m, "Architecture hints were sparse; map the deployment manually (hosting provider, load balancers, app servers, databases).")

    ctx.manual(m, "Check for origin exposure: historical DNS records, direct IP access bypassing the CDN, and alternate ports.")
    ctx.manual(m, "Document trust boundaries (client -> CDN -> app -> data) and validate which components are in scope before deeper testing.")
