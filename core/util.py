import re
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "net.za", "gov.za",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk",
    "com.sg", "org.sg", "net.sg", "edu.sg", "gov.sg",
    "com.my", "org.my", "net.my", "edu.my", "gov.my",
    "co.in", "org.in", "net.in", "gov.in", "ac.in",
    "com.mx", "org.mx", "net.mx", "gob.mx",
    "com.tr", "org.tr", "net.tr", "gov.tr",
    "co.kr", "or.kr", "ne.kr", "go.kr",
    "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw",
    "co.il", "org.il", "net.il", "gov.il", "ac.il",
    "com.ar", "org.ar", "net.ar", "gob.ar",
    "com.co", "org.co", "net.co", "gov.co",
    "co.th", "or.th", "go.th", "ac.th",
    "com.vn", "org.vn", "net.vn", "gov.vn",
    "com.ph", "org.ph", "net.ph", "gov.ph",
    "com.pk", "org.pk", "net.pk", "gov.pk",
    "com.eg", "org.eg", "net.eg", "gov.eg",
    "com.sa", "org.sa", "net.sa", "gov.sa",
    "com.ua", "org.ua", "net.ua", "gov.ua",
    "co.id", "or.id", "ac.id", "go.id", "web.id",
    "com.pe", "org.pe", "net.pe", "gob.pe",
    "com.ec", "org.ec", "net.ec", "gob.ec",
    "com.uy", "org.uy", "net.uy", "gub.uy",
    "co.ke", "or.ke", "ac.ke", "go.ke",
    "com.ng", "org.ng", "net.ng", "gov.ng",
}


def registrable_domain(host):
    try:
        import tldextract

        extractor = tldextract.TLDExtract(suffix_list_urls=())
        ext = extractor(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def redact(value, show=False, keep=4, tail=2):
    if show:
        return value
    text = re.sub(r"\s+", " ", str(value))
    if len(text) <= keep + tail:
        return text[:1] + "***"
    return f"{text[:keep]}...{text[-tail:]} (len={len(text)})"


def safe_name(value):
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value))
    return name.strip("_")[:120] or "index"


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def extract_title(html, limit=200):
    match = TITLE_RE.search(html or "")
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:limit]


def is_soft_404(resp, baseline):
    if resp is None:
        return True
    if resp.status_code == 404:
        return True
    if baseline is None:
        return resp.status_code >= 400
    if resp.status_code != baseline.status_code:
        return False
    try:
        if abs(len(resp.content) - len(baseline.content)) < 16:
            return True
        return resp.text[:256] == baseline.text[:256]
    except Exception:
        return False


_ASSET_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|css|js|mjs|woff2?|ttf|eot|mp4|mp3|avi|pdf|zip|tar|gz|rar|7z|exe|dmg|iso)(?:[?#]|$)",
    re.I,
)


def looks_like_asset(url):
    return bool(_ASSET_EXT_RE.search(url.split("?")[0]))
