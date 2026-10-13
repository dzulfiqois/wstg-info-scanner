import re
from urllib.parse import urljoin, urlparse

LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#][^"']*)["']""", re.I)
SCRIPT_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)


def same_host(url, host, port=None):
    parsed = urlparse(url)
    return (parsed.hostname or "").lower() == host and (port is None or parsed.port in (None, port))


def extract_links(html, base_url):
    links = []
    for match in LINK_RE.finditer(html or ""):
        raw = match.group(1).strip()
        if raw.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        links.append(urljoin(base_url, raw))
    return links


def extract_scripts(html, base_url):
    scripts = []
    for match in SCRIPT_RE.finditer(html or ""):
        scripts.append(urljoin(base_url, match.group(1)))
    return scripts


def fetch(ctx, url):
    resp = ctx.http.get(url)
    if resp is None or not resp.ok:
        return None
    content_type = resp.headers.get("content-type", "")
    if content_type and not any(token in content_type for token in ("text", "html", "json", "xml", "javascript")):
        return None
    return resp


def sample_pages(ctx, extra_limit=None):
    pages = []
    resp = fetch(ctx, ctx.base_url)
    if resp is None:
        return pages
    pages.append((ctx.base_url, resp))
    limit = extra_limit if extra_limit is not None else 5
    seen = {ctx.base_url}
    for link in extract_links(resp.text, ctx.base_url):
        if len(pages) >= limit + 1:
            break
        if link in seen:
            continue
        if not same_host(link, ctx.host, urlparse(ctx.base_url).port):
            continue
        parsed = urlparse(link)
        if parsed.path.lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico", ".pdf", ".zip", ".woff", ".woff2", ".ttf")
        ):
            continue
        child = fetch(ctx, link)
        seen.add(link)
        if child is not None:
            pages.append((link, child))
    return pages
