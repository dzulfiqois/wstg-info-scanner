#!/usr/bin/env python3
import argparse
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests  # noqa: F401
except ImportError:
    sys.exit("Missing dependency 'requests'. Install with: pip install -r requirements.txt")

from core import TOOL_NAME, VERSION
from core.dns_tls import is_ip
from core.engine import Context, run_modules
from core.http import HttpClient
from core.report import Report
from core.util import now_iso, registrable_domain
from modules import MODULES

DEFAULT_USER_AGENT = "wstg-info/0.1 (authorized security testing)"


def load_config(path):
    config_path = Path(path) if path else Path(__file__).resolve().parent / "config.yaml"
    if not config_path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        print(f"[warn] PyYAML not installed; ignoring {config_path}. Install with: pip install -r requirements.txt")
        return {}
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        print(f"[warn] Could not parse {config_path}: {exc}")
        return {}


def build_parser():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Automated OWASP WSTG Information Gathering (WSTG-INFO-01..10) reconnaissance runner.",
        epilog="Only run against systems you are authorized to test.",
    )
    parser.add_argument("-t", "--target", help="Target URL or host, e.g. https://example.com or example.com")
    parser.add_argument("-o", "--output", default=None, help="Base output directory (default: results)")
    parser.add_argument("--config", default=None, help="Path to config.yaml (default: alongside this script)")
    parser.add_argument("--only", default=None, help="Comma-separated WSTG IDs to run, e.g. INFO-01,INFO-03 (or INFO for all)")
    parser.add_argument("--skip", default=None, help="Comma-separated WSTG IDs to skip")
    parser.add_argument("--active", action="store_true", help="Enable active checks (INFO-04: enumeration, subdomain probing, optional port scan)")
    parser.add_argument("--depth", type=int, default=None, help="Crawler depth for INFO-07 (default 2)")
    parser.add_argument("--max-pages", type=int, default=None, help="Crawler page limit for INFO-07 (default 50)")
    parser.add_argument("--rate-limit", type=float, default=None, help="Max requests per second (default 10)")
    parser.add_argument("--threads", type=int, default=None, help="Worker threads for active checks (default 10)")
    parser.add_argument("--timeout", type=float, default=None, help="Per-request timeout in seconds (default 10)")
    parser.add_argument("--ports", default=None, help="Comma-separated ports to scan in INFO-04, e.g. 80,443,8080")
    parser.add_argument("--user-agent", default=None, help="Override the User-Agent header")
    parser.add_argument("--proxy", default=None, help="HTTP(S) proxy URL")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    parser.add_argument("--dry-run", action="store_true", help="Show requests without sending them")
    parser.add_argument("--show-secrets", action="store_true", help="Do not redact secrets/emails in reports")
    parser.add_argument("--list", action="store_true", help="List available modules and exit")
    return parser


def normalize_id(token):
    token = token.strip().upper()
    if token.isdigit():
        return f"WSTG-INFO-{int(token):02d}"
    if token.startswith("WSTG-"):
        suffix = token[5:]
    elif token.startswith("INFO-") or token == "INFO":
        suffix = token
    else:
        suffix = token
    parts = suffix.split("-")
    if len(parts) == 2 and parts[0] == "INFO" and parts[1].isdigit():
        return f"WSTG-INFO-{int(parts[1]):02d}"
    if suffix == "INFO":
        return "WSTG-INFO"
    return f"WSTG-{suffix}"


def select_modules(parser, only, skip):
    selected = list(MODULES)
    if only:
        normalized = {normalize_id(token) for token in only.split(",") if token.strip()}
        known = {mod.WSTG_ID for mod in MODULES}
        unknown = {token for token in normalized if token not in known and token != "WSTG-INFO"}
        if unknown:
            parser.error(f"unknown WSTG ID(s): {', '.join(sorted(unknown))}. Use --list to see supported tests.")
        if "WSTG-INFO" not in normalized:
            selected = [mod for mod in MODULES if mod.WSTG_ID in normalized]
    if skip:
        normalized = {normalize_id(token) for token in skip.split(",") if token.strip()}
        selected = [mod for mod in selected if mod.WSTG_ID not in normalized]
    return selected


def pick(cli_value, config, key, default):
    if cli_value is not None:
        return cli_value
    return config.get(key, default)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list:
        print(f"{TOOL_NAME} {VERSION} - available modules:\n")
        for mod in MODULES:
            flag = "active" if mod.ACTIVE else "passive"
            print(f"  {mod.WSTG_ID}  [{flag:7}]  {mod.TITLE}")
        return

    if not args.target:
        parser.error("--target is required (or use --list)")

    target = args.target if "://" in args.target else "https://" + args.target
    parsed = urlparse(target)
    if not parsed.hostname:
        parser.error(f"could not parse a host from target: {args.target}")
    host = parsed.hostname.lower()
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or host
    root_url = f"{scheme}://{netloc}"
    base_url = target

    config = load_config(args.config)
    http_config = config.get("http", {}) or {}
    scan_config = config.get("scan", {}) or {}

    timeout = float(pick(args.timeout, http_config, "timeout", 10))
    rate_limit = float(pick(args.rate_limit, http_config, "rate_limit", 10))
    threads = int(pick(args.threads, http_config, "threads", 10))
    user_agent = pick(args.user_agent, http_config, "user_agent", DEFAULT_USER_AGENT)
    depth = int(pick(args.depth, scan_config, "depth", 2))
    max_pages = int(pick(args.max_pages, scan_config, "max_pages", 50))
    max_js_files = int(scan_config.get("max_js_files", 25))
    output_base = Path(args.output or "results")

    if args.ports:
        config.setdefault("info04", {})
        config["info04"]["ports"] = [int(port) for port in args.ports.split(",") if port.strip().isdigit()]

    ip_target = is_ip(host)
    scope_hosts = {host}
    subdomain_root = None
    if not ip_target:
        domain = registrable_domain(host)
        scope_hosts.update({domain, f"www.{domain}"})
        if host.startswith("www."):
            scope_hosts.add(host[4:])
        subdomain_root = domain if args.active else None
    else:
        domain = host

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = output_base / f"{host}-{timestamp}"
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    started = now_iso()
    started_monotonic = time.monotonic()
    http = HttpClient(
        scope_hosts=scope_hosts,
        subdomain_root=subdomain_root,
        rate_limit=rate_limit,
        timeout=timeout,
        user_agent=user_agent,
        dry_run=args.dry_run,
        verify=not args.insecure,
        proxy=args.proxy,
    )
    project_root = Path(__file__).resolve().parent
    config["_project_root"] = str(project_root)
    report = Report(target=target, output_dir=output_dir, active=args.active, started=started)
    modules = select_modules(parser, args.only, args.skip)
    ctx = Context(
        target=target,
        base_url=base_url,
        root_url=root_url,
        host=host,
        domain=domain,
        is_ip=ip_target,
        project_root=project_root,
        output_dir=output_dir,
        raw_dir=raw_dir,
        http=http,
        report=report,
        config=config,
        active=args.active,
        depth=depth,
        max_pages=max_pages,
        threads=threads,
        max_js_files=max_js_files,
        dry_run=args.dry_run,
        show_secrets=args.show_secrets,
    )

    print(f"{TOOL_NAME} {VERSION}")
    print(f"  target      : {target}")
    print(f"  output      : {output_dir}")
    print(f"  modules     : {', '.join(mod.WSTG_ID.replace('WSTG-', '') for mod in modules)}")
    print(f"  active      : {'yes' if args.active else 'no'}")
    print(f"  rate limit  : {rate_limit} req/s, threads: {threads}, timeout: {timeout}s")
    if args.dry_run:
        print("  DRY RUN: no requests will be sent")
    print()

    run_modules(modules, ctx)

    duration_s = round(time.monotonic() - started_monotonic, 1)
    http.dump_history(raw_dir / "requests.jsonl")
    report.write_json(output_dir / "findings.json", duration_s)
    report.write_markdown(output_dir / "report.md", duration_s)

    data = report.to_dict(duration_s)
    by_sev = data["summary"]["by_severity"]
    print()
    print(f"Done in {duration_s}s. Findings: {data['summary']['findings_total']} "
          f"({', '.join(f'{count} {sev}' for sev, count in by_sev.items() if count) or 'none'})")
    print(f"  report   : {output_dir / 'report.md'}")
    print(f"  findings : {output_dir / 'findings.json'}")
    print(f"  evidence : {raw_dir}")


if __name__ == "__main__":
    main()
