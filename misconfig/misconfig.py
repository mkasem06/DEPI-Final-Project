"""
misconfig.py — Misconfiguration scan module for AI-Strike.

Checks a target for:
  - missing security response headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)
  - commonly-exposed sensitive paths (.git, .env, backup files, admin panels)
  - missing CSRF token fields on state-changing forms
  - cookies missing Secure / HttpOnly / SameSite flags

Every public function returns a list of finding dicts in the team's shared
JSON shape:
    {
        "module": "misconfig",
        "target": <url checked>,
        "finding": <short description>,
        "severity": "low" | "medium" | "high" | "critical",
        "evidence": <the specific proof>,
        "confidence": "confirmed" | "suspected",
        "timestamp": <ISO 8601 UTC>,
    }

run(target_url, recon_output) is the entry point the rest of the team calls.
recon_output is whatever Recon's run() returns: a dict with at least
"endpoints" (list[str]) and "params" (list of {"url", "method", "params"}),
the same shape recon/check_recon.py validates against.

Severities below are a reasonable starting point, not final — the AI layer
(module 5) re-assigns severity using the finding + evidence, so this module
just needs to get the facts right.
"""

from __future__ import annotations

import random
import string
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 10  

EXPOSED_PATHS = ["/.git/", "/.env", "/admin", "/backup.zip"]

CSRF_FIELD_HINTS = ["csrf", "xsrf", "authenticity_token", "csrfmiddlewaretoken"]

# header name -> starting severity if it's missing
# severity decision will be finalized by the ai in module 5 of the plan anyway
SECURITY_HEADERS = {
    "Content-Security-Policy": "medium",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "low",
    "Strict-Transport-Security": "medium",  # only checked on https targets
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# returns the final json output
def _finding(target: str, finding: str, severity: str, evidence: str, confidence: str) -> dict:
    return {
        "module": "misconfig",
        "target": target,
        "finding": finding,
        "severity": severity,
        "evidence": evidence,
        "confidence": confidence,
        "timestamp": _now(),
    }


# ---------------------------------------------------------------------------
def check_security_headers(url: str) -> list[dict]:
    """GET url once, flag each missing security header."""
    try:
        resp = requests.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        return [_finding(url, f"Could not reach target to check headers: {e}",
                          "low", str(e), "suspected")]

    headers = resp.headers  # case-insensitive dict
    is_https = urlparse(url).scheme == "https"

    findings = []
    for header, severity in SECURITY_HEADERS.items():
        if header == "Strict-Transport-Security" and not is_https:
            continue  # HSTS is meaningless over plain HTTP
        if header not in headers:
            findings.append(_finding(
                url,
                f"Missing '{header}' response header",
                severity,
                f"Response headers present: {dict(headers)}",
                "confirmed",
            ))
    return findings


def check_exposed_paths(url: str, paths: list[str] | None = None) -> list[dict]:
    """Try each sensitive path off the target root; flag any that return 200.
    
    Because some websites respond with a 200 http response code with a built in "Page not found"
    Page instrad of responding properly with a 404 code, we need to know if this website does so
    as well in order to filter out false positives
    """
    paths = paths or EXPOSED_PATHS
    root = url if url.endswith("/") else url + "/"

    # Testing a random surerly non-existant page to figure out  if this website returns a custom page
    # with a 200 code
    probe = "nonexistent-" + "".join(random.choices(string.ascii_lowercase, k=12))
    try:
        baseline = requests.get(urljoin(root, probe), timeout=TIMEOUT, allow_redirects=False)
        soft_404 = baseline.status_code == 200
        baseline_len = len(baseline.content)
    except requests.RequestException:
        soft_404 = False
        baseline_len = -1

    findings = []
    for path in paths:
        full_url = urljoin(root, path.lstrip("/"))
        try:
            resp = requests.get(full_url, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue

        if resp.status_code != 200:
            continue
        if soft_404 and abs(len(resp.content) - baseline_len) < 20:
            continue  # looks like the same catch-all page the baseline got

        findings.append(_finding(
            full_url,
            f"Potentially exposed path reachable: {path}",
            "high",
            f"GET {full_url} -> {resp.status_code}, {len(resp.content)} bytes",
            "suspected" if soft_404 else "confirmed",
        ))
    return findings


def check_csrf_tokens(form: dict) -> list[dict]:
    """form is one entry from recon's 'params' list:
    {"url": ..., "method": ..., "params": [field names]}.
    Only meaningful for state-changing methods — GET forms are skipped.
    """
    method = form.get("method", "GET").upper()
    if method == "GET":
        return []

    fields = form.get("params", [])

    has_token = any(hint in field.lower() 
                        for field in fields 
                            for hint in CSRF_FIELD_HINTS)
    if has_token:
        return []

    return [_finding(
        form.get("url", ""),
        f"Form ({method} {form.get('url', '')}) has no apparent CSRF token field",
        "medium",
        f"Form fields found: {fields}",
        # "suspected", not "confirmed": a token could still be delivered via
        # a cookie or a custom header instead of a form field.
        "suspected",
    )]


def check_cookie_flags(url: str) -> list[dict]:
    """GET url, inspect every Set-Cookie header for Secure/HttpOnly/SameSite."""

    try:
        resp = requests.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        return [_finding(url, f"Could not reach target to check cookies: {e}",
                          "low", str(e), "suspected")]

    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        single = resp.headers.get("Set-Cookie")
        raw_cookies = [single] if single else []
        # returns single as a truth value wrapped in a list if the header exists
        # otherwise return an empty set

    findings = []

    for cookie_str in raw_cookies:
        # extract the cookie name by spltting into two pieces at the first = sign then getting
        # the firt piece and stripping it of leading & trailing whitespaces
        name = cookie_str.split("=", 1)[0].strip()

        lowered = cookie_str.lower()

        missing = [
            flag for flag, needle in
            (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
            if needle not in lowered
        ]

        if missing:
            findings.append(_finding(
                url,
                f"Cookie '{name}' missing flag(s): {', '.join(missing)}",
                "medium",
                cookie_str,
                "confirmed",
            ))
            
    return findings


def run(target_url: str, recon_output: dict) -> list[dict]:
    """Entry point.

    recon_output: whatever Recon's run() returns — a dict with "endpoints"
    (list[str]) and "params" (list of form dicts), per the schema
    recon/check_recon.py validates.
    """
    findings: list[dict] = []
    findings += check_security_headers(target_url)
    findings += check_exposed_paths(target_url)
    findings += check_cookie_flags(target_url)

    for form in recon_output.get("params", []):
        findings += check_csrf_tokens(form)

    return findings
