import re
from urllib.parse import urlparse

from ._common import extract_scripts, fetch

WSTG_ID = "WSTG-INFO-08"
TITLE = "Fingerprint Web Application Framework"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"
ACTIVE = False

COOKIE_SIGNATURES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Servlet container)",
    "ASP.NET_SessionId": "ASP.NET",
    "ARRAffinity": "Azure App Service",
    "laravel_session": "Laravel",
    "XSRF-TOKEN": "Laravel / Angular",
    "csrftoken": "Django",
    "sessionid": "Django",
    "_rails": "Ruby on Rails",
    "rack.session": "Rack",
    "connect.sid": "Express/Node.js",
    "wordpress_": "WordPress",
    "wp-settings": "WordPress",
    "ci_session": "CodeIgniter",
    "_shopify": "Shopify",
    "cfid": "Adobe ColdFusion",
    "cftoken": "Adobe ColdFusion",
    "plone": "Plone",
    "grav-site": "Grav",
}

HEADER_SIGNATURES = {
    "X-AspNet-Version": "ASP.NET",
    "X-AspNetMvc-Version": "ASP.NET MVC",
    "X-Drupal-Cache": "Drupal",
    "X-Drupal-Dynamic-Cache": "Drupal",
    "X-Generator": "CMS generator header",
    "X-Runtime": "Ruby on Rails",
    "X-Shopify-Stage": "Shopify",
    "X-Magento-Tags": "Magento",
    "X-Served-By": "CDN / reverse proxy",
}

BODY_SIGNATURES = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("/wp-json", "WordPress"),
    ("__NEXT_DATA__", "Next.js"),
    ("_next/static", "Next.js"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
    ("__NUXT__", "Nuxt.js"),
    ("_nuxt/", "Nuxt.js"),
    ("csrfmiddlewaretoken", "Django"),
    ("name=\"csrf-token\"", "Ruby on Rails"),
    ("data-v-", "Vue.js"),
    ("svelte-", "Svelte"),
    ("drupal-settings-json", "Drupal"),
    ("/sites/default/files", "Drupal"),
    ("joomla", "Joomla"),
    ("/typo3/", "TYPO3"),
    ("static/js/main.", "Create React App"),
]

SCRIPT_SIGNATURES = [
    ("jquery", "jQuery"),
    ("bootstrap", "Bootstrap"),
    ("react", "React"),
    ("vue", "Vue.js"),
    ("angular", "Angular"),
    ("backbone", "Backbone.js"),
    ("ember", "Ember.js"),
    ("moment", "Moment.js"),
    ("lodash", "Lodash"),
]


def run(ctx):
    m = WSTG_ID
    resp = ctx.http.get(ctx.base_url)
    if resp is None:
        ctx.manual(m, "Homepage unreachable; framework fingerprinting skipped.")
        return

    detected = {}

    for cookie in resp.cookies:
        for signature, technology in COOKIE_SIGNATURES.items():
            if cookie.name.lower().startswith(signature.lower()):
                detected.setdefault(technology, []).append(f"cookie `{cookie.name}`")

    for header, technology in HEADER_SIGNATURES.items():
        if header in resp.headers:
            detected.setdefault(technology, []).append(f"header `{header}: {resp.headers[header][:80]}`")

    body = resp.text
    for token, technology in BODY_SIGNATURES:
        if token in body:
            detected.setdefault(technology, []).append(f"body token `{token}`")

    scripts = extract_scripts(body, ctx.base_url)
    versions = []
    for script in scripts:
        for token, technology in SCRIPT_SIGNATURES:
            if token in script.lower():
                detected.setdefault(technology, []).append(f"script `{urlparse(script).path}`")
                version_match = re.search(rf"{token}[.-]?v?(\d+\.\d+(?:\.\d+)?)", script, re.I)
                if version_match:
                    versions.append(f"{technology} {version_match.group(1)} ({script})")
    for match in re.finditer(r"\?ver=(\d+(?:\.\d+)*)", body):
        versions.append(f"asset version query `ver={match.group(1)}`")

    if detected:
        ctx.finding(
            m,
            "Web application framework fingerprinted",
            "info",
            f"Detected: {', '.join(sorted(detected))}. Framework knowledge drives targeted testing (WSTG-CONF, WSTG-INPV).",
            {
                "table": [{"technology": tech, "evidence": "; ".join(items[:6])} for tech, items in sorted(detected.items())],
                "versions": sorted(set(versions))[:30],
            },
        )
    else:
        ctx.manual(m, "No framework signatures matched from passive checks; use Wappalyzer, response diffing with invalid paths, or session cookie naming to identify the framework.")

    if versions:
        ctx.finding(m, "Framework/library versions exposed", "low", f"{len(set(versions))} version string(s) found; check them against known CVEs.", {"versions": sorted(set(versions))[:30]})

    ctx.manual(m, "Confirm the framework with 404/500 error pages and by comparing default files (e.g. /wp-login.php for WordPress, /administrator for Joomla).")
    ctx.manual(m, "Once the framework is known, enumerate its advisories and default credentials during later phases.")
