import json
import re
from urllib.parse import urlparse, urlunparse

from core.util import extract_title, looks_like_asset
from ._common import extract_links, extract_scripts

WSTG_ID = "WSTG-INFO-07"
TITLE = "Map Execution Paths Through Application"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application"
ACTIVE = False


def _normalize(url):
    parsed = urlparse(url)
    clean = parsed._replace(fragment="", params="")
    return urlunparse(clean)


def run(ctx):
    from collections import deque

    m = WSTG_ID
    origin = urlparse(ctx.base_url)
    start = _normalize(ctx.base_url)
    seen = {}
    edges = []
    queue = deque([(start, 0)])

    while queue and len(seen) < ctx.max_pages:
        url, depth = queue.popleft()
        if url in seen:
            continue
        resp = ctx.http.get(url)
        status = resp.status_code if resp is not None else None
        content_type = resp.headers.get("content-type", "") if resp is not None else ""
        title = ""
        if resp is not None and "html" in content_type:
            title = extract_title(resp.text)
        seen[url] = {"url": url, "status": status, "content_type": content_type.split(";")[0], "title": title, "depth": depth}
        if resp is None or "html" not in content_type or depth >= ctx.depth:
            continue
        for link in extract_links(resp.text, url) + extract_scripts(resp.text, url):
            link = _normalize(link)
            parsed = urlparse(link)
            if (parsed.hostname or "").lower() != ctx.host:
                continue
            if parsed.port not in (None, origin.port):
                continue
            if look_like := looks_like_asset(link):
                if link not in seen:
                    seen[link] = {"url": link, "status": None, "content_type": "asset", "title": "", "depth": depth + 1}
                continue
            edges.append({"from": url, "to": link})
            if link not in seen:
                queue.append((link, depth + 1))

    graph = {"nodes": list(seen.values()), "edges": edges}
    graph_evidence = ctx.artifact("INFO-07.graph.json", json.dumps(graph, indent=2))

    max_nodes = int(ctx.config.get("info07", {}).get("max_mermaid_nodes", 30))
    mermaid_lines = ["flowchart LR"]
    alias = {}
    for index, node in enumerate(list(seen.values())[:max_nodes]):
        alias[node["url"]] = f"n{index}"
        label = node["url"]
        if node["title"]:
            label = f"{node['title'][:40]}<br/>{node['url']}"
        mermaid_lines.append(f'    n{index}["{label[:80]}"]')
    for edge in edges[: max_nodes * 2]:
        if edge["from"] in alias and edge["to"] in alias:
            mermaid_lines.append(f"    {alias[edge['from']]} --> {alias[edge['to']]}")
    mermaid = "\n".join(mermaid_lines)

    ctx.finding(
        m,
        "Application map generated",
        "info",
        f"{len(seen)} URL(s) discovered, {len(edges)} link(s) mapped, crawler depth reached {min(ctx.depth, max((n['depth'] for n in seen.values()), default=0))}.",
        {"mermaid": mermaid, "truncated_to_nodes": max_nodes if len(seen) > max_nodes else None},
        [graph_evidence],
    )
    error_nodes = [node for node in seen.values() if node["status"] and node["status"] >= 500]
    if error_nodes:
        ctx.finding(
            m,
            "Error responses discovered while mapping",
            "info",
            f"{len(error_nodes)} URL(s) returned 5xx; review for stack traces (WSTG-ERRH).",
            {"table": [{"url": n["url"], "status": n["status"]} for n in error_nodes[:30]]},
        )
    if len(seen) >= ctx.max_pages:
        ctx.manual(m, f"Crawl hit the {ctx.max_pages}-page limit; raise --max-pages or map authenticated areas manually.")
    ctx.manual(m, "Compare the generated map with your own browsing session; JavaScript-rendered flows and multi-step processes need manual mapping (state machines, checkout flows, password reset).")
    ctx.manual(m, "Identify entry points that mutate state (POST/PUT/DELETE) and confirm they appear in the authorization test phase.")
