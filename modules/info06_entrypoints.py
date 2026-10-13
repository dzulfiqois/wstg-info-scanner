import json
import re
from urllib.parse import parse_qsl, urljoin, urlparse

from ._common import extract_links, same_host, sample_pages

WSTG_ID = "WSTG-INFO-06"
TITLE = "Identify Application Entry Points"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points"
ACTIVE = False

FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.I)
METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']*)["']""", re.I)
INPUT_RE = re.compile(r"""<(input|select|textarea|button)\b([^>]*)>""", re.I)
NAME_RE = re.compile(r"""name\s*=\s*["']([^"']+)["']""", re.I)
TYPE_RE = re.compile(r"""type\s*=\s*["']([^"']+)["']""", re.I)
JS_FETCH_RE = re.compile(r"""(?:fetch|axios(?:\.\w+)?|XMLHttpRequest\s*\(\s*)\s*\(?['"`]([^'"`]+)['"`]""")
JS_URL_RE = re.compile(r"""url\s*:\s*['"`]([^'"`]+)['"`]""")
WEBSOCKET_RE = re.compile(r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""")


def _parse_forms_regex(html, base_url):
    forms = []
    for form_match in FORM_RE.finditer(html):
        attrs = html[form_match.start() : form_match.start() + 400]
        action_match = ACTION_RE.search(attrs)
        method_match = METHOD_RE.search(attrs)
        inputs = []
        for input_match in INPUT_RE.finditer(form_match.group(1)):
            tag = input_match.group(1).lower()
            attrs = input_match.group(2)
            name_match = NAME_RE.search(attrs)
            if not name_match:
                continue
            type_match = TYPE_RE.search(attrs)
            inputs.append({"name": name_match.group(1), "type": (type_match.group(1) if type_match else tag).lower()})
        forms.append(
            {
                "page": base_url,
                "method": (method_match.group(1) if method_match else "GET").upper(),
                "action": urljoin(base_url, action_match.group(1)) if action_match and action_match.group(1) else base_url,
                "inputs": inputs,
            }
        )
    return forms


def _parse_forms_bs4(html, base_url):
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for field in form.find_all(["input", "select", "textarea", "button"]):
            name = field.get("name")
            if name:
                inputs.append({"name": name, "type": (field.get("type") or field.name).lower()})
        forms.append(
            {
                "page": base_url,
                "method": (form.get("method") or "GET").upper(),
                "action": urljoin(base_url, form.get("action") or base_url),
                "inputs": inputs,
            }
        )
    return forms


def run(ctx):
    m = WSTG_ID
    pages = sample_pages(ctx, extra_limit=10)
    if not pages:
        ctx.manual(m, "Homepage unreachable; entry point discovery skipped.")
        return

    forms = []
    parameters = []
    endpoints = []

    for page_url, resp in pages:
        html = resp.text
        try:
            forms.extend(_parse_forms_bs4(html, page_url))
        except ImportError:
            forms.extend(_parse_forms_regex(html, page_url))
        for link in extract_links(html, page_url):
            if not same_host(link, ctx.host, urlparse(ctx.base_url).port):
                continue
            parsed = urlparse(link)
            if parsed.query:
                parameters.append(
                    {
                        "page": page_url,
                        "url": link,
                        "params": [{"name": name, "value": value[:60]} for name, value in parse_qsl(parsed.query, keep_blank_values=True)],
                    }
                )
        for pattern in (JS_FETCH_RE, JS_URL_RE, WEBSOCKET_RE):
            for match in pattern.finditer(html):
                target = match.group(1).strip()
                if target and not target.startswith(("http://", "https://", "//")):
                    endpoints.append({"page": page_url, "endpoint": target})

    unique_params = {}
    for item in parameters:
        key = item["url"].split("?")[0]
        unique_params.setdefault(key, item)

    if forms:
        ctx.finding(
            m,
            "Forms discovered",
            "info",
            f"{len(forms)} form(s) identified across {len(pages)} page(s); every input is a potential entry point.",
            {"table": [{"page": f["page"], "method": f["method"], "action": f["action"], "inputs": ", ".join(i["name"] for i in f["inputs"]) or "-"} for f in forms[:60]]},
        )
    if unique_params:
        ctx.finding(
            m,
            "URL parameters discovered",
            "info",
            f"{len(unique_params)} URL(s) carry query parameters.",
            {"table": [{"page": item["page"], "url": item["url"], "params": ", ".join(p["name"] for p in item["params"])} for item in list(unique_params.values())[:60]]},
        )
    if endpoints:
        deduped = {(e["page"], e["endpoint"]) for e in endpoints}
        ctx.finding(
            m,
            "Endpoints referenced in client-side JavaScript",
            "info",
            f"{len(deduped)} API/WebSocket endpoint reference(s) extracted from page scripts.",
            {"table": [{"page": page, "endpoint": endpoint} for page, endpoint in sorted(deduped)[:60]]},
        )

    entry_evidence = ctx.artifact(
        "INFO-06.entrypoints.json",
        json.dumps({"forms": forms, "parameters": list(unique_params.values()), "js_endpoints": sorted({e["endpoint"] for e in endpoints})}, indent=2),
    )
    if not forms and not unique_params and not endpoints:
        ctx.finding(m, "No entry points detected in sampled pages", "info", "Pages may be JavaScript-rendered; use a browser or proxy to enumerate entry points manually.", {}, [entry_evidence])

    ctx.manual(m, "Walk every form/parameter in a proxy (ZAP/Burp) and test each field for reflected input, validation bypass, and hidden fields.")
    ctx.manual(m, "For SPA/JS-heavy apps, render pages in a browser and capture XHR/fetch/WebSocket traffic in DevTools since regex parsing misses runtime-built endpoints.")
