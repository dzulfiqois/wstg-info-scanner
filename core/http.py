import threading
import time
from urllib.parse import urlparse

import requests

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

RECON_PROVIDERS = {
    "crt.sh",
    "web.archive.org",
    "archive.org",
    "index.commoncrawl.org",
    "urlscan.io",
    "otx.alienvault.com",
}


class RateLimiter:
    def __init__(self, rate_per_sec):
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self):
        if not self.min_interval:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_at:
                time.sleep(self._next_at - now)
                now = time.monotonic()
            self._next_at = now + self.min_interval


class HttpClient:
    def __init__(
        self,
        scope_hosts,
        subdomain_root=None,
        rate_limit=10.0,
        timeout=10.0,
        user_agent="wstg-info/0.1",
        dry_run=False,
        verify=True,
        proxy=None,
    ):
        self.scope_hosts = {h.lower() for h in scope_hosts}
        self.subdomain_root = subdomain_root.lower() if subdomain_root else None
        self.timeout = timeout
        self.dry_run = dry_run
        self.verify = verify
        self.rate = RateLimiter(rate_limit)
        self.history = []
        self._hist_lock = threading.Lock()
        self.current_module = "CORE"
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent
        self.session.headers["Accept"] = "*/*"
        self.session.max_redirects = 5
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def in_scope(self, url, external=False):
        host = (urlparse(url).hostname or "").lower()
        if external:
            return host in RECON_PROVIDERS
        if host in self.scope_hosts:
            return True
        if self.subdomain_root and (host == self.subdomain_root or host.endswith("." + self.subdomain_root)):
            return True
        return False

    def request(self, method, url, external=False, **kwargs):
        if not self.in_scope(url, external=external):
            self._record({"module": self.current_module, "method": method, "url": url, "blocked": "out-of-scope"})
            return None
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify)
        if self.dry_run:
            self._record({"module": self.current_module, "method": method, "url": url, "dry_run": True})
            print(f"    [dry-run] {method} {url}")
            return None
        self.rate.wait()
        started = time.monotonic()
        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            self._record({"module": self.current_module, "method": method, "url": url, "error": str(exc)})
            return None
        elapsed_ms = int((time.monotonic() - started) * 1000)
        content = getattr(resp, "_content", None)
        size = len(content) if content is not None else resp.headers.get("content-length")
        final_host = (urlparse(resp.url).hostname or "").lower()
        entry = {
            "module": self.current_module,
            "method": method,
            "url": url,
            "status": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "bytes": size,
            "content_type": resp.headers.get("content-type", ""),
        }
        if resp.url != url:
            entry["final_url"] = resp.url
        if resp.history:
            entry["redirects"] = [h.headers.get("Location") for h in resp.history]
        if final_host not in self.scope_hosts and not (self.subdomain_root and final_host.endswith("." + self.subdomain_root)):
            entry["off_scope_final"] = True
        self._record(entry)
        return resp

    def get(self, url, external=False, **kwargs):
        return self.request("GET", url, external=external, **kwargs)

    def head(self, url, external=False, **kwargs):
        return self.request("HEAD", url, external=external, **kwargs)

    def get_json(self, url, external=False, **kwargs):
        resp = self.request("GET", url, external=external, **kwargs)
        if resp is None or not resp.ok:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    def _record(self, entry):
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._hist_lock:
            self.history.append(entry)

    def dump_history(self, path):
        import json

        with open(path, "w", encoding="utf-8") as fh:
            for entry in self.history:
                fh.write(json.dumps(entry) + "\n")
