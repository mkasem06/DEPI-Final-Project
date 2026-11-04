"""
XSS module: sends payloads into every parameter recon found and determines,
using parser-based context analysis (not raw string matching), whether the
payload reflects back in a context a browser would actually execute.

Functions:
  get_payload_list()                       Curated payload set, grouped by
                                            the HTML/JS context each one is
                                            designed to test, each carrying a
                                            random per-run "canary" marker.
  inject_payload(endpoint, param, payload)  Sends ONE request with `param`
                                            set to `payload`. Scope-checked,
                                            redirect-safe, failure-tolerant.
  check_reflection(response_text, payload)  Classifies the reflection using
                                            BeautifulSoup's parse tree:
                                            not reflected / escaped / inert
                                            text / live script / live
                                            attribute / inconclusive. The
                                            canary it checks for is always
                                            extracted from `payload` itself
                                            (see _extract_canary), never
                                            assumed to be the module-level
                                            CANARY constant.
  run(recon_output, test_stored_xss=None)   Reflected-XSS sweep over every
    -> findings_list                       param x payload (always runs),
                                            plus the stored-XSS workflow
                                            (opt-in - see its docstring
                                            block below) when enabled.
  run_stored_xss_checks(recon_output)       Standalone entry point for just
    -> findings_list                       the stored-XSS workflow.

Output shape of run() (shared format used by every module) - exactly these
six keys, nothing else:
  [
    {
      "module": "xss",
      "target": "https://site.com/search",
      "finding": "Reflected XSS in 'q' parameter",
      "severity": "low|medium|high|critical",
      "evidence": "...",
      "confidence": "confirmed|suspected",
      "timestamp": "..."
    },
    ...
  ]

=== Design notes / known limitations (read before trusting a "confirmed") ===

1. This module does deterministic, parser-based *static response analysis*.
   It parses each response with BeautifulSoup and checks whether the
   payload's own HTML (a <script> tag, an onerror= attribute, a
   javascript: URI) was parsed as *live markup* rather than inert text.
   That is a strong signal, but it is not a browser. It does NOT:
     - evaluate Content-Security-Policy, X-XSS-Protection, or other
       browser-side mitigations that could still block execution
       (the misconfig module checks CSP headers separately - cross-reference
       that module's findings for the same target before treating a
       "confirmed" XSS finding here as unconditionally exploitable),
     - execute JavaScript or render the DOM,
     - detect DOM-based XSS (payload reflected safely into HTML but later
       read and re-injected by client-side JavaScript),
     - guarantee that every real browser's HTML tokenizer agrees with
       BeautifulSoup's html.parser backend in every edge case.
   `confirmed` means "a standards-compliant HTML parser treated the
   injected markup as live", not "exploited in a real browser". Treat it as
   high-confidence evidence for a human reviewer, not as a court verdict.

2. Only `confirmed` and `suspected` are ever assigned as `confidence`
   (matching the shared schema, which has no third state). A reflection
   that cannot be classified with reasonable confidence - e.g. it only
   shows up inside an HTML comment, or the response couldn't be parsed at
   all - is still reported, but as `suspected` with an explicit note that
   manual review is needed, never upgraded to `confirmed` to force it into
   a binary classification.

3. A reflection that the parser resolves as ordinary escaped text, or as
   inert text sitting inside an existing attribute's value with no new
   attribute created, produces NO finding at all. Exact string match alone
   is never treated as proof of exploitability - see check_reflection()
   docstring for the full classification table.
"""

import html
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup, Comment
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

MODULE_NAME = "xss"

# ---------------------------------------------------------------------------
# Configurable limits (env-overridable, same convention as sqli.py's
# SQLMAP_TIMEOUT_SECONDS / SQLMAP_LEVEL). Defaults are conservative so a scan
# against a real target finishes in a bounded amount of time and traffic.
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT_SECONDS = int(os.getenv("XSS_REQUEST_TIMEOUT_SECONDS", "10"))
MAX_REDIRECTS = int(os.getenv("XSS_MAX_REDIRECTS", "3"))
MAX_REQUESTS_PER_RUN = int(os.getenv("XSS_MAX_REQUESTS_PER_RUN", "500"))
MAX_SECONDS_PER_RUN = int(os.getenv("XSS_MAX_SECONDS_PER_RUN", "600"))
DEFAULT_VALUE = "1"  # value used for untested query parameters without form metadata

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}

# A random marker embedded in every payload so a reflection can only match
# OUR request, not unrelated text already on the page. Generated once at
# import time so every payload in a run shares the same canary.
CANARY = "xss" + secrets.token_hex(4)  # e.g. "xss9f1c2a7b"

_CANARY_PATTERN = re.compile(r"xss[0-9a-f]{8}")


def _generate_unique_canary():
    """
    A fresh, single-use canary - deliberately NOT the shared module-level
    CANARY. Used for stored-XSS tests (see that section below), where each
    test's payload gets persisted by the target and could otherwise still
    be sitting there when a LATER, unrelated check runs later in the same
    scan. Giving every stored-XSS test its own canary means its persisted
    data can never be mistaken for a different test's reflection, and
    never collides with the single shared canary the reflected-testing
    phase uses for the whole run.
    """
    return "xss" + secrets.token_hex(4)


def _extract_canary(payload, fallback=None):
    """
    Pulls the canary actually embedded in `payload` (the same "xss" + 8 hex
    chars pattern CANARY and _generate_unique_canary() both produce).

    Classification MUST check for the canary that is actually IN this
    specific payload, never a module-level constant - otherwise a payload
    built with a different canary (get_payload_list(canary=...) with a
    custom value, or any payload from the stored-XSS phase, which always
    uses its own unique canary) would be checked against the wrong marker
    and silently misclassified as "not reflected" even when it clearly
    was. This was a real bug in an earlier version of this module:
    _classify_reflection() checked `CANARY in response_text` using the
    fixed module-level constant no matter which canary the payload
    argument actually contained.
    """
    match = _CANARY_PATTERN.search(payload)
    if match:
        return match.group(0)
    logger.warning(
        "could not find an embedded canary in payload (%r); falling back to the module-level "
        "CANARY, which may not be what was actually sent in this payload",
        payload[:80],
    )
    return fallback if fallback is not None else CANARY


_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


# ---------------------------------------------------------------------------
# Payload list
# ---------------------------------------------------------------------------

def get_payload_list(canary=CANARY):
    """
    Returns the payload set as a list of dicts, grouped by the context each
    payload is designed to land in:

      {"payload": "...", "context": "...", "description": "..."}

    `context` is informational (used in evidence text and by callers that
    want to group results) - detection itself does NOT trust this label; it
    is decided independently by check_reflection() from the actual parsed
    response, never assumed from which payload was sent.

    Groups:
      html_text      - raw tag injection into normal page content.
      html_attribute - breaking out of an existing attribute's quotes to
                        add a new event-handler attribute.
      uri_scheme     - javascript: URIs in href/src-style attributes.
      filter_bypass  - case/encoding variants meant to catch naive filters
                        that only match a lowercase "<script>" string.

    This list alone is reflection-probe coverage for the common contexts,
    not exhaustive XSS coverage - it does not cover DOM-based XSS, mutation
    XSS, or framework-specific template-injection sinks.
    """
    return [
        # -- html_text: raw tag injected directly into page content --
        {
            "payload": f"<script>alert('{canary}')</script>",
            "context": "html_text",
            "description": "Raw <script> tag into page body/text content.",
        },
        {
            "payload": f"<svg onload=alert('{canary}')>",
            "context": "html_text",
            "description": "Self-contained tag+event-handler, no closing tag needed.",
        },
        {
            "payload": f"<img src=x onerror=alert('{canary}')>",
            "context": "html_text",
            "description": "Classic broken-image event-handler trigger.",
        },
        {
            "payload": f"<body onload=alert('{canary}')>",
            "context": "html_text",
            "description": "Body-level event handler (only fires if reflected before </body>).",
        },

        # -- html_attribute: breaking out of an existing attribute value --
        {
            "payload": f"\"><script>alert('{canary}')</script>",
            "context": "html_attribute",
            "description": "Double-quote attribute breakout followed by a new <script>.",
        },
        {
            "payload": f"'><script>alert('{canary}')</script>",
            "context": "html_attribute",
            "description": "Single-quote attribute breakout followed by a new <script>.",
        },
        {
            "payload": f"\" onmouseover=alert('{canary}') x=\"",
            "context": "html_attribute",
            "description": "Double-quote breakout adding a new event-handler attribute.",
        },
        {
            "payload": f"' onmouseover=alert('{canary}') x='",
            "context": "html_attribute",
            "description": "Single-quote breakout adding a new event-handler attribute.",
        },

        # -- uri_scheme: javascript: URIs where the app accepts a URL --
        {
            "payload": f"javascript:alert('{canary}')",
            "context": "uri_scheme",
            "description": "Bare javascript: URI, for params reflected into href/src.",
        },
        {
            "payload": f"<a href=\"javascript:alert('{canary}')\">click</a>",
            "context": "uri_scheme",
            "description": "javascript: URI inside a freshly injected <a> tag.",
        },
        {
            "payload": f"<iframe src=\"javascript:alert('{canary}')\"></iframe>",
            "context": "uri_scheme",
            "description": "javascript: URI inside a freshly injected <iframe>.",
        },

        # -- filter_bypass: naive-filter evasion variants --
        {
            "payload": f"<ScRiPt>alert('{canary}')</sCrIpT>",
            "context": "filter_bypass",
            "description": "Mixed case, catches filters that only match lowercase '<script>'.",
        },
        {
            "payload": f"<script>alert(String.fromCharCode(88,83,83)+'{canary}')</script>",
            "context": "filter_bypass",
            "description": "No literal 'XSS' substring in the script body, catches naive keyword filters.",
        },
        {
            "payload": f"<<script>script>alert('{canary}')<</script>/script>",
            "context": "filter_bypass",
            "description": "Nested tags, catches filters that strip '<script>' only once.",
        },
    ]


# ---------------------------------------------------------------------------
# Scope enforcement (mirrors sqli.py's _in_scope, with corrected default-port
# handling: sqli.py's version compares requested.port to approved.port
# directly, which fails to match e.g. https://site.com against
# https://site.com:443/path even though those are the same origin)
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _effective_port(parsed):
    """
    Returns the explicit port, or the scheme's default port if none was
    given, or None if the port portion of the URL is malformed (non-numeric,
    e.g. "https://x:abc/", or out of the valid 0-65535 range, e.g.
    "https://x:999999/"). Accessing .port on a SplitResult can itself raise
    ValueError for either case - callers MUST treat None as "could not be
    determined, so never a scope match" and must not let that exception
    propagate (that would crash the scan instead of failing closed).
    """
    try:
        return parsed.port or _DEFAULT_PORTS.get(parsed.scheme)
    except ValueError:
        return None


def _in_scope(url):
    """
    True only if url has the same scheme, host and effective port as
    AUTHORIZED_TARGET, and neither URL embeds credentials. Fails closed:
    if AUTHORIZED_TARGET is unset or malformed, every URL is out of scope -
    this includes a malformed PORT on either side (e.g. a redirect Location
    header pointing at "https://example.com:999999/", which is attacker/
    target-controlled input and must never be allowed to crash the scan).
    """
    approved_raw = os.getenv("AUTHORIZED_TARGET", "")
    if not approved_raw:
        return False

    try:
        approved = urlsplit(approved_raw)
        requested = urlsplit(url)
    except ValueError:
        return False

    if requested.scheme not in ("http", "https"):
        return False
    if requested.hostname is None or approved.hostname is None:
        return False
    if requested.username is not None or requested.password is not None:
        return False
    if approved.username is not None or approved.password is not None:
        # A misconfigured AUTHORIZED_TARGET with embedded creds is treated
        # as invalid scope config rather than silently accepted.
        return False

    requested_port = _effective_port(requested)
    approved_port = _effective_port(approved)
    if requested_port is None or approved_port is None:
        # A malformed port on EITHER side can never be treated as a match,
        # even if both happen to be malformed in the same way (None ==
        # None would otherwise wrongly evaluate True here) - fail closed.
        return False

    return (
        requested.scheme == approved.scheme
        and requested.hostname == approved.hostname
        and requested_port == approved_port
    )


# ---------------------------------------------------------------------------
# Request sending
# ---------------------------------------------------------------------------

def _record_scan_issue(diagnostics, kind, message, endpoint=None, param=None):
    if diagnostics is None:
        return

    diagnostics.setdefault("issues", [])
    diagnostics.setdefault("_issue_keys", set())
    issue = {
        "kind": kind,
        "message": str(message),
    }
    if isinstance(endpoint, dict):
        for key in ("url", "page_url"):
            value = endpoint.get(key)
            issue[key] = value if isinstance(value, str) else None
        form_index = endpoint.get("form_index")
        issue["form_index"] = form_index if isinstance(form_index, int) else None
    if param is not None:
        issue["parameter"] = str(param)

    key = tuple(issue.items())
    if key not in diagnostics["_issue_keys"]:
        diagnostics["_issue_keys"].add(key)
        diagnostics["issues"].append(issue)


def _send_with_scope_safe_redirects(
    method, url, values, budget, session=None, diagnostics=None, endpoint=None, param=None
):
    """
    Sends one request with automatic redirect-following disabled, then
    manually follows up to MAX_REDIRECTS hops, re-validating scope AND the
    shared request budget before every single hop. A redirect to a
    host/scheme/port outside AUTHORIZED_TARGET stops the chain instead of
    being followed. TLS verification is never disabled.

    `budget` (a _ScanBudget) is checked before each individual HTTP attempt
    and incremented after each one actually fires - including every
    redirect hop and every failed attempt. This is deliberate: an earlier
    version of this module incremented the budget once per inject_payload()
    call, which undercounted real traffic whenever a response redirected,
    since one such call could cause up to MAX_REDIRECTS+1 actual requests
    to the target while only ever counting as one unit of budget.

    MAX_SECONDS_PER_RUN is enforced the same way: checked before starting
    each new attempt. It CANNOT interrupt a request already in flight -
    that request still runs to completion or to its own
    REQUEST_TIMEOUT_SECONDS socket/read timeout, whichever comes first. The
    deadline only ever prevents a NEW attempt from starting once it has
    passed; it is not a preemptive, mid-request interrupt.

    Returns the final requests.Response, or None if the request failed, the
    budget/deadline was hit, or a redirect left scope.
    """
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        if not _in_scope(current_url):
            logger.warning("refusing to request out-of-scope URL: %s", current_url)
            _record_scan_issue(
                diagnostics, "scope", "Request blocked because the URL is outside the authorized scope.",
                endpoint, param,
            )
            return None

        reason = budget.exhausted()
        if reason:
            logger.warning("xss: reached %s, refusing to start a request to %s", reason, current_url)
            _record_scan_issue(
                diagnostics, "budget", f"Request not sent because {reason} was reached.", endpoint, param,
            )
            return None

        try:
            if method == "POST":
                request = session.post if session is not None else requests.post
                response = request(
                    current_url, data=values, headers=HEADERS,
                    timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=False,
                )
            else:
                request = session.get if session is not None else requests.get
                response = request(
                    current_url, params=values, headers=HEADERS,
                    timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=False,
                )
        except requests.exceptions.RequestException as e:
            budget.record_request()  # a failed ATTEMPT still used up one unit of real traffic/time
            logger.warning("XSS request failed for %s: %s", current_url, e)
            _record_scan_issue(
                diagnostics, "request", f"HTTP request failed: {e}", endpoint, param,
            )
            return None

        budget.record_request()  # exactly one real HTTP attempt was just made - count it once, here, only

        if response.status_code not in _REDIRECT_STATUS_CODES:
            return response

        location = response.headers.get("Location")
        if not location:
            return response  # redirect status with no Location header; nothing to follow

        next_url = urljoin(current_url, location)
        if not _in_scope(next_url):
            logger.warning(
                "blocked redirect out of authorized scope: %s -> %s", current_url, next_url
            )
            _record_scan_issue(
                diagnostics, "redirect", "Redirect blocked because it left the authorized scope.",
                endpoint, param,
            )
            return None

        current_url = next_url
        # 307/308 preserve method AND body, same as a browser would do.
        # 301/302/303 conventionally become GET for a POST request - and
        # when that happens, the original POST body must be DISCARDED, not
        # resent as GET query parameters. A real browser following e.g. a
        # 303 redirect from a form POST does not resurrect the submitted
        # fields as a query string on the follow-up GET; it sends a bare
        # GET to the Location it was given. Keeping `values` unchanged
        # here was a real bug: it silently carried the entire original
        # POST body (including whatever payload was being tested) into the
        # URL as query parameters on the next hop.
        if method == "POST" and response.status_code in (301, 302, 303):
            method = "GET"
            values = {}

    logger.warning("too many redirects (> %d) following %s, aborting", MAX_REDIRECTS, url)
    _record_scan_issue(
        diagnostics, "redirect", f"Request aborted after more than {MAX_REDIRECTS} redirects.",
        endpoint, param,
    )
    return None


_CSRF_NAME_MARKERS = (
    "csrf",
    "xsrf",
    "requestverificationtoken",
    "authenticitytoken",
    "antiforgery",
    "verificationtoken",
)


def _is_csrf_token_name(name):
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(marker in normalized for marker in _CSRF_NAME_MARKERS)


def _add_form_value(values, name, value):
    if name not in values:
        values[name] = value
    elif isinstance(values[name], list):
        values[name].append(value)
    else:
        values[name] = [values[name], value]


def _successful_form_values(form):
    """Read browser-style successful control values, including hidden tokens."""
    values = {}
    field_names = set()

    for field in form.find_all(["input", "textarea", "select"]):
        name = field.get("name")
        if not name or field.has_attr("disabled"):
            continue
        field_names.add(name)

        if field.name == "input":
            input_type = (field.get("type") or "text").lower()
            if input_type in {"button", "file", "image", "reset", "submit"}:
                continue
            if input_type in {"checkbox", "radio"} and not field.has_attr("checked"):
                continue
            _add_form_value(values, name, field.get("value", "on" if input_type in {"checkbox", "radio"} else ""))
        elif field.name == "textarea":
            _add_form_value(values, name, field.get_text())
        else:
            options = field.find_all("option")
            selected = [option for option in options if option.has_attr("selected")]
            if not selected and not field.has_attr("multiple") and options:
                selected = [options[0]]
            for option in selected:
                _add_form_value(values, name, option.get("value", option.get_text()))

    return values, field_names


def _baseline_value(field):
    name = str(field.get("name", "")).lower()
    field_type = (field.get("type") or "text").lower() if field.name == "input" else "text"
    if field_type in {"hidden", "password", "file", "submit", "button", "reset", "image"}:
        return None
    if field_type in {"checkbox", "radio"}:
        return None
    if field_type == "email" or "email" in name:
        return "xss-scanner@example.invalid"
    if field_type == "url":
        return "https://example.invalid/"
    if field_type == "tel" or "phone" in name:
        return "5550100"
    if field_type in {"number", "range"}:
        return "1"
    if field_type in {"text", "search", "tel", "url"} or field.name == "textarea":
        if any(marker in name for marker in ("message", "comment", "description", "body")):
            return "XSS scanner baseline message"
        if "name" in name:
            return "XSS scanner"
        return "XSS scanner baseline"
    return None


def _set_safe_baseline_values(form, values, only_empty=False):
    """Replace user-entered values with neutral test values; retain hidden tokens and choices."""
    for field in form.find_all(["input", "textarea"]):
        name = field.get("name")
        if not name or field.has_attr("disabled") or _is_csrf_token_name(name):
            continue
        current = values.get(name)
        if only_empty and current and (
            not isinstance(current, list) or any(str(item).strip() for item in current)
        ):
            continue
        value = _baseline_value(field)
        if value is not None:
            values[name] = value


def _sensitive_form_values(values, session=None):
    sensitive = []

    def add_value(value):
        if isinstance(value, (list, tuple)):
            for item in value:
                add_value(item)
        elif isinstance(value, str) and value:
            sensitive.append(value)

    for value in values.values():
        add_value(value)

    if session is not None:
        for cookie in session.cookies:
            add_value(cookie.value)

    return sorted(set(sensitive), key=len, reverse=True)


def _sanitized_response_excerpt(response_text, values, session=None, limit=500):
    """Return a short text-only server error excerpt with submitted values/secrets redacted."""
    try:
        soup = BeautifulSoup(response_text or "", "html.parser")
        for element in soup.find_all(["script", "style", "noscript"]):
            element.decompose()
        excerpt = soup.get_text(" ", strip=True)
    except Exception:
        excerpt = re.sub(r"<[^>]*>", " ", str(response_text or ""))

    for value in _sensitive_form_values(values, session):
        excerpt = re.sub(re.escape(value), "[REDACTED]", excerpt, flags=re.IGNORECASE)

    excerpt = re.sub(
        r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+",
        "[REDACTED AUTHORIZATION]",
        excerpt,
    )
    excerpt = re.sub(
        r"(?i)\b(?:__requestverificationtoken|csrf(?:token)?|xsrf(?:token)?|"
        r"antiforgery(?:token)?|token|password|passwd|secret|cookie|authorization)"
        r"\b\s*[:=]\s*[^\s,;]+",
        "[REDACTED]",
        excerpt,
    )
    excerpt = re.sub(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "[REDACTED EMAIL]",
        excerpt,
        flags=re.IGNORECASE,
    )
    excerpt = re.sub(r"\s+", " ", excerpt).strip()
    if len(excerpt) > limit:
        excerpt = excerpt[:limit] + "..."
    return excerpt


def _record_http_error_response(response, values, session, diagnostics, endpoint, param=None, phase="payload"):
    if response.status_code < 400:
        return

    message = f"{phase.capitalize()} request returned HTTP {response.status_code}."
    content_type = response.headers.get("Content-Type", "")
    if content_type:
        message += f" Content-Type: {content_type}."
    if response.status_code >= 500:
        excerpt = _sanitized_response_excerpt(response.text, values, session=session)
        if excerpt:
            message += f" Sanitized response excerpt: {excerpt}"

    _record_scan_issue(diagnostics, "http", message, endpoint, param)


def _load_form_values(
    endpoint, session, budget, diagnostics=None, param=None, baseline=False, fill_empty=False,
):
    page_url = endpoint.get("page_url")
    form_index = endpoint.get("form_index")
    if not isinstance(page_url, str) or not page_url or not isinstance(form_index, int) or isinstance(form_index, bool):
        logger.warning("inject_payload: malformed form provenance on endpoint %r", endpoint.get("url"))
        _record_scan_issue(
            diagnostics, "form", "Form provenance is malformed; the form could not be loaded.",
            endpoint, param,
        )
        return None, None

    response = _send_with_scope_safe_redirects(
        "GET", page_url, {}, budget, session=session, diagnostics=diagnostics,
        endpoint=endpoint, param=param,
    )
    if response is None:
        logger.warning("inject_payload: could not fetch source form page %s", page_url)
        _record_scan_issue(
            diagnostics, "form", "Could not fetch the form source page.", endpoint, param,
        )
        return None, None
    if response.status_code < 200 or response.status_code >= 300:
        logger.warning(
            "inject_payload: source form page %s returned HTTP %s",
            page_url, response.status_code,
        )
        _record_scan_issue(
            diagnostics, "request",
            f"Form source page returned HTTP {response.status_code}.", endpoint, param,
        )
        return None, None

    try:
        forms = BeautifulSoup(response.text, "html.parser").find_all("form")
    except Exception as error:
        logger.warning("inject_payload: could not parse form source page %s: %s", page_url, error)
        _record_scan_issue(
            diagnostics, "parsing", f"Could not parse form source page: {error}", endpoint, param,
        )
        return None, None
    if form_index >= len(forms):
        logger.warning("inject_payload: form index %s no longer exists on %s", form_index, page_url)
        _record_scan_issue(
            diagnostics, "form", "The discovered form index no longer exists on the source page.",
            endpoint, param,
        )
        return None, None

    form = forms[form_index]
    actual_url = urljoin(response.url or page_url, form.get("action") or response.url or page_url)
    expected_url = endpoint["url"]
    actual_without_fragment = urlsplit(actual_url)._replace(fragment="").geturl()
    expected_without_fragment = urlsplit(expected_url)._replace(fragment="").geturl()
    if not _in_scope(actual_url) or actual_without_fragment != expected_without_fragment:
        logger.warning(
            "inject_payload: discovered form action changed or left scope: %s (expected %s)",
            actual_url, expected_url,
        )
        _record_scan_issue(
            diagnostics, "form",
            "The form action changed or is outside the authorized scope; no submission was sent.",
            endpoint, param,
        )
        return None, None

    actual_method = (form.get("method") or "get").strip().upper()
    if actual_method != str(endpoint.get("method", "GET")).upper():
        logger.warning("inject_payload: discovered form method changed on %s", page_url)
        _record_scan_issue(
            diagnostics, "form", "The form method changed since reconnaissance; no submission was sent.",
            endpoint, param,
        )
        return None, None

    values, field_names = _successful_form_values(form)
    if baseline:
        _set_safe_baseline_values(form, values)
    elif fill_empty:
        _set_safe_baseline_values(form, values, only_empty=True)
    return values, field_names


def _run_form_baseline(endpoint, budget, session, diagnostics=None):
    """Submit one neutral form body so server failures can be separated from payload failures."""
    starting_request_count = budget.request_count
    values, _ = _load_form_values(
        endpoint, session, budget, diagnostics=diagnostics, baseline=True,
    )
    if values is None:
        return {
            "status": "failed",
            "reason": "Could not load and validate the source form for a baseline submission.",
        }

    response = _send_with_scope_safe_redirects(
        "POST", endpoint["url"], values, budget, session=session,
        diagnostics=diagnostics, endpoint=endpoint,
    )
    if response is None:
        return {
            "status": "failed",
            "reason": "No response received for the baseline form submission.",
        }

    result = {
        "status": "passed" if 200 <= response.status_code < 300 else "failed",
        "status_code": response.status_code,
        "requests_attempted": budget.request_count - starting_request_count,
        "content_type": response.headers.get("Content-Type", ""),
        "request_content_type": (
            response.request.headers.get("Content-Type", "")
            if response.request is not None else ""
        ),
        "csrf_field_present": any(
            _is_csrf_token_name(name) and bool(value)
            for name, value in values.items()
        ),
        "session_cookie_count": len(session.cookies) if session is not None else 0,
    }
    if result["status"] == "failed":
        result["response_excerpt"] = _sanitized_response_excerpt(
            response.text, values, session=session,
        )
        _record_http_error_response(
            response, values, session, diagnostics, endpoint, phase="baseline",
        )
        result["reason"] = "The neutral form submission did not receive a successful 2xx response."
    return result


def _run_form_baselines(endpoints, budget, session, diagnostics=None):
    results = {}
    for endpoint_index, endpoint in enumerate(endpoints):
        if (
            not isinstance(endpoint, dict)
            or "page_url" not in endpoint
            or "form_index" not in endpoint
            or str(endpoint.get("method", "GET")).upper() != "POST"
            or not _in_scope(endpoint.get("url", ""))
        ):
            continue

        try:
            baseline = _run_form_baseline(
                endpoint, budget, session, diagnostics=diagnostics,
            )
        except Exception as error:
            logger.warning(
                "xss.run: neutral form submission failed for %s: %s",
                endpoint.get("url"), error,
            )
            _record_scan_issue(
                diagnostics, "baseline",
                f"Neutral form submission raised an error: {error}",
                endpoint,
            )
            baseline = {
                "status": "failed",
                "reason": "Neutral form submission raised an error.",
            }

        results[endpoint_index] = baseline
        if diagnostics is not None and endpoint_index < len(diagnostics["endpoints"]):
            diagnostics["endpoints"][endpoint_index]["baseline"] = baseline

    return results


def inject_payload(endpoint, param, payload, budget=None, session=None, diagnostics=None):
    """
    Sends one request with `param` set to `payload`; every other param on
    that endpoint is filled with its current form values where Recon provides
    form provenance. Query parameters without form metadata use DEFAULT_VALUE.

    `endpoint` is one of recon's param entries:
      {"url": "...", "method": "GET" or "POST", "params": ["q", ...]}

    Form-backed endpoints are re-fetched for every test using the same
    requests.Session as the submission, so cookies and fresh hidden fields
    (including anti-CSRF tokens) are preserved. Only GET and POST are
    supported, matching what the Recon module currently emits; any other
    method is rejected with a warning and no request is sent. Scope is
    re-validated here (not just in run()) so this function is safe to call
    directly. TLS verification is always on
    (verify is never set to False). Form cookies issued by the source page
    are reused; the scanner does not configure login credentials.

    `budget` is an optional _ScanBudget shared across a whole run() so
    request/time limits apply to the TOTAL work a scan does, counted per
    actual HTTP attempt (see _send_with_scope_safe_redirects). It defaults
    to None, in which case a fresh, throwaway budget scoped to just this
    one call is created - this keeps inject_payload(endpoint, param,
    payload) callable exactly as before (its documented public signature)
    for direct/standalone use outside run(), while run() itself always
    passes its own shared budget explicitly.

    Returns the final requests.Response, or None if the request could not
    be sent (malformed endpoint data, out of scope, network failure, a
    redirect that would leave scope, or the budget/deadline was hit).
    """
    if not isinstance(endpoint, dict):
        logger.warning("inject_payload: endpoint is not a dict (%r), skipping", type(endpoint))
        _record_scan_issue(diagnostics, "form", "Endpoint data is not an object.", None, param)
        return None

    url = endpoint.get("url")
    if not url or not isinstance(url, str):
        logger.warning("inject_payload: endpoint missing a valid 'url', skipping: %r", endpoint)
        _record_scan_issue(diagnostics, "form", "Endpoint has no valid URL.", endpoint, param)
        return None

    method = str(endpoint.get("method", "GET")).upper()
    if method not in ("GET", "POST"):
        logger.warning(
            "inject_payload: unsupported method '%s' for %s (only GET/POST are supported), skipping",
            method, url,
        )
        _record_scan_issue(
            diagnostics, "form", f"HTTP method {method} is unsupported; only GET and POST are scanned.",
            endpoint, param,
        )
        return None

    if not _in_scope(url):
        logger.warning("inject_payload: %s is not within AUTHORIZED_TARGET, skipping", url)
        _record_scan_issue(
            diagnostics, "scope", "Endpoint is outside the authorized scope.", endpoint, param,
        )
        return None

    if _is_csrf_token_name(param):
        logger.info("inject_payload: preserving anti-CSRF field '%s' on %s", param, url)
        _record_scan_issue(
            diagnostics, "parameter", "CSRF token fields are preserved but not selected for payload testing.",
            endpoint, param,
        )
        return None

    other_params = endpoint.get("params", [])
    if not isinstance(other_params, list):
        other_params = []

    if other_params and param not in other_params:
        # Not fatal - testing a parameter the endpoint didn't declare is a
        # legitimate thing to do deliberately (hidden fields, undocumented
        # params) - but it's worth surfacing so a caller notices if this
        # happens unintentionally.
        logger.warning(
            "inject_payload: param '%s' is not in endpoint %s's declared params %r; testing it anyway",
            param, url, other_params,
        )

    if budget is None:
        budget = _ScanBudget()

    if "page_url" in endpoint or "form_index" in endpoint:
        owns_session = session is None
        if owns_session:
            session = requests.Session()
        try:
            values, field_names = _load_form_values(
                endpoint, session, budget, diagnostics=diagnostics, param=param,
                fill_empty=True,
            )
            if values is None:
                return None
            if param not in field_names:
                logger.warning("inject_payload: parameter '%s' is absent from the current form on %s", param, url)
                _record_scan_issue(
                    diagnostics, "form", "Parameter is absent from the current form; no submission was sent.",
                    endpoint, param,
                )
                return None
            values[param] = payload
            response = _send_with_scope_safe_redirects(
                method, url, values, budget, session=session, diagnostics=diagnostics,
                endpoint=endpoint, param=param,
            )
            if response is not None:
                _record_http_error_response(
                    response, values, session, diagnostics, endpoint, param,
                )
            return response
        finally:
            if owns_session:
                session.close()

    values = {name: DEFAULT_VALUE for name in other_params if isinstance(name, str)}
    values[param] = payload

    response = _send_with_scope_safe_redirects(
        method, url, values, budget, session=session, diagnostics=diagnostics,
        endpoint=endpoint, param=param,
    )
    if response is not None:
        _record_http_error_response(
            response, values, session, diagnostics, endpoint, param,
        )
    return response


# ---------------------------------------------------------------------------
# Reflection classification
# ---------------------------------------------------------------------------

# Only these classifications produce a finding; everything else means "the
# payload either didn't reflect, or reflected somewhere inert" -> no finding.
_CONFIRMED_CLASSIFICATIONS = {
    "script_context": "Payload's own <script> tag was parsed as a live script element.",
    "event_handler_attribute": "Payload created a new on*= event-handler attribute on a real tag.",
    "uri_scheme_attribute": "Payload created a javascript: URI in a live href/src/action/formaction attribute.",
}
_SUSPECTED_CLASSIFICATIONS = {
    "unescaped_angle_bracket_in_text": (
        "A raw, un-encoded '<' from the payload survived inside what the parser "
        "resolved as plain text (it did not form a new element here, but a less "
        "tolerant parser or a different page position might treat it differently)."
    ),
    "inconclusive": (
        "The canary was reflected somewhere the parser could not cleanly classify "
        "(e.g. inside a comment, or the response could not be parsed as HTML)."
    ),
}


def _attr_value_as_text(value):
    """bs4 returns a list for multi-valued attrs like class=; normalize to one string."""
    if isinstance(value, list):
        return " ".join(value)
    return value if isinstance(value, str) else str(value)


# Generous slack added to the canary's own length when deciding whether an
# attribute's value "is essentially our payload" vs. "contains our canary
# as a small fragment of something much longer". Covers the short wrapper
# our own payloads use (e.g. alert('canary')) plus some margin, without
# being so generous that a genuinely long, pre-existing attribute value
# could slip under it.
_INJECTED_VALUE_SLACK_CHARS = 40


def _looks_like_injected_value(value_text, canary):
    """
    True if `value_text` is short enough to plausibly BE what a payload
    intended to inject (the canary plus a small wrapper like alert('...')),
    rather than the canary being a small fragment inside a much longer
    value that most likely already existed on the page independently of
    this specific request.
    """
    return len(value_text) <= len(canary) + _INJECTED_VALUE_SLACK_CHARS


def _classify_reflection(response_text, payload):
    """
    Parses response_text with BeautifulSoup and determines, structurally,
    where the canary landed. Returns (classification, detail, matched_snippet).

    Classification table:

      not_reflected                    canary never appears in the response.
      escaped_text                     reflected, but as ordinary escaped/
                                        inert content - NOT a finding.
      attribute_value_context          reflected inside an existing
                                        attribute's value with no new
                                        attribute created (i.e. it did not
                                        break out of the quoting) - NOT a
                                        finding; static analysis alone
                                        cannot rule out every real-browser
                                        edge case here, but the parser found
                                        no evidence of a break-out.
      script_context                   CONFIRMED - payload's own <script>
                                        tag was parsed as a real element.
      event_handler_attribute          CONFIRMED - payload created a new
                                        on*= attribute on a real tag.
      uri_scheme_attribute             CONFIRMED - javascript: URI landed in
                                        a live href/src/action/formaction.
      unescaped_angle_bracket_in_text  SUSPECTED - raw '<' survived in text
                                        without forming a new element.
      inconclusive                     SUSPECTED - reflected, but the parser
                                        couldn't classify it cleanly (e.g.
                                        inside a comment, or parse failure).
    """
    canary = _extract_canary(payload)

    if response_text is None or canary not in response_text:
        return "not_reflected", "Canary not found in response.", None

    try:
        soup = BeautifulSoup(response_text, "html.parser")
    except Exception as e:  # BeautifulSoup is tolerant, but never trust a 3rd-party parser blindly
        logger.warning("XSS: failed to parse response as HTML (%s)", e)
        return "inconclusive", f"Response could not be parsed as HTML ({e}); manual review required.", None

    # 1) Did the payload's own <script> tag become a real, parsed element?
    for tag in soup.find_all("script"):
        text = tag.get_text()
        if canary in text:
            snippet = str(tag)[:300]
            return "script_context", f"Canary found inside a parsed <script> element: {snippet}", snippet

    # 2) Did the payload create a new attribute on a real tag?
    #
    # Important distinction: an attribute NAMED on* (onclick, onmouseover,
    # ...) is only evidence of a successful breakout if its VALUE is
    # (close to) what our payload itself intended to inject - a short
    # wrapper around the canary, like alert('canary'). If the canary is
    # merely a small fragment sitting inside a MUCH LONGER value, that
    # value almost certainly already existed independently of our
    # injection (e.g. an onclick="logEvent('...', 'comment text: OUR DATA
    # HERE', ...)" the app renders for every item, with our data safely
    # interpolated into one of its JS-string arguments). The attribute's
    # NAME starting with "on" proves nothing by itself about whether WE
    # created it - only the shape of its value does.
    #
    # The SAME canary can land in MULTIPLE different attributes across the
    # response - a harmless one AND a genuinely dangerous one. This must
    # NOT return as soon as it finds the first (possibly harmless)
    # occurrence: doing so can hide a later, genuinely dangerous one. Every
    # attribute occurrence is examined; a dangerous one is reported
    # immediately (any single dangerous occurrence is sufficient evidence
    # regardless of what else is nearby), and only if NONE were dangerous
    # does this fall back to reporting the harmless occurrence.
    harmless_attribute_match = None
    for tag in soup.find_all(True):
        for attr_name, attr_value in tag.attrs.items():
            value_text = _attr_value_as_text(attr_value)
            if canary not in value_text:
                continue

            snippet = str(tag)[:300]
            lower_name = attr_name.lower()
            looks_newly_created = _looks_like_injected_value(value_text, canary)

            if lower_name.startswith("on") and looks_newly_created:
                return (
                    "event_handler_attribute",
                    f"Canary found inside a live '{attr_name}' event-handler attribute on <{tag.name}>, "
                    f"whose value is essentially just our payload ({len(value_text)} chars) rather than a "
                    f"long pre-existing value: {snippet}",
                    snippet,
                )
            if (lower_name in ("href", "src", "action", "formaction")
                    and "javascript:" in value_text.lower() and looks_newly_created):
                return (
                    "uri_scheme_attribute",
                    f"Canary found inside a javascript: URI in '{attr_name}' on <{tag.name}>, whose value is "
                    f"essentially just our payload ({len(value_text)} chars) rather than a long pre-existing "
                    f"value: {snippet}",
                    snippet,
                )
            # Either an ordinary (non-event, non-URI-scheme) attribute, or
            # an on*/javascript: attribute whose value is much longer than
            # our payload - i.e. the canary is a small fragment inside
            # something that was very likely already there, not evidence
            # we created or broke out into it. Remember it, but keep
            # scanning the REST of the document for a dangerous occurrence
            # before concluding this is harmless.
            if harmless_attribute_match is None:
                harmless_attribute_match = (
                    "attribute_value_context",
                    f"Canary found inside the value of attribute '{attr_name}' on <{tag.name}> "
                    f"({len(value_text)} chars), with no evidence of breaking out of or newly creating "
                    "that attribute: " + snippet,
                    snippet,
                )

    # 3) Reflected as ordinary text content somewhere. The SAME canary can
    # appear in MULTIPLE different text nodes (e.g. once safely escaped in
    # one place, once genuinely unescaped in another) - each occurrence
    # must be checked against its OWN position in the raw response, never
    # against a different occurrence's position.
    #
    # This fixes a real bug: the previous version used
    # response_text.find(canary) unconditionally, which always returns the
    # position of the FIRST occurrence in the entire document regardless
    # of which node the loop was currently examining. That meant a later,
    # genuinely unescaped occurrence could be checked against an earlier,
    # safely-escaped occurrence's surrounding text (or vice versa),
    # producing a classification based on the wrong location entirely.
    # Proven concretely: a canary reflected once safely-escaped early in a
    # document and once with a raw unescaped '<' later in the document was
    # classified "escaped_text" (a false negative) before this fix.
    search_cursor = 0
    saw_any_text_occurrence = False
    for node in soup.find_all(string=True):
        if node.parent is not None and node.parent.name in ("script", "style"):
            continue  # already handled in step 1, or not page content
        if isinstance(node, Comment):
            continue  # HTML comments are never rendered/executed by a browser
        if canary not in str(node):
            continue

        saw_any_text_occurrence = True

        # str(node) is bs4's DECODED text, so it can't tell us whether the
        # original source was entity-encoded. Go back to the raw response,
        # advancing a cursor so each successive text node's occurrence is
        # matched to its own distinct position in document order, instead
        # of always re-checking whichever occurrence is first overall.
        raw_pos = response_text.find(canary, search_cursor)
        if raw_pos == -1:
            # Cursor-based search came up empty after this point (can
            # happen with duplicate canaries plus entity-length
            # differences shifting apparent offsets) - fall back to a
            # document-wide search rather than skip this node entirely.
            raw_pos = response_text.find(canary)
        search_cursor = raw_pos + len(canary)

        # The window used to check for an unescaped '<' must be sized to
        # OUR PAYLOAD's own structure around the canary, not a flat
        # generous radius - a flat 80-char radius can reach far enough to
        # pick up a DIFFERENT, unrelated occurrence's escaped form nearby
        # in a short document, making this occurrence look safe because
        # SOME other occurrence's "&lt;" happens to also fall inside the
        # window. (Proven concretely: two occurrences ~90 chars apart, one
        # escaped and one not, were both misjudged as safe before this
        # fix, because each one's 80-char window reached into the other's
        # text.) Using the payload's own prefix/suffix length around the
        # canary, plus a small fixed margin for minor transformations,
        # keeps the window tied to what COULD plausibly be our payload's
        # own surviving characters, not whatever else happens to be
        # nearby.
        canary_offset_in_payload = payload.find(canary)
        if canary_offset_in_payload == -1:
            canary_offset_in_payload = 0  # shouldn't happen - canary came from this payload
        prefix_len = canary_offset_in_payload
        suffix_len = len(payload) - canary_offset_in_payload - len(canary)
        margin = 10
        check_window = response_text[
            max(0, raw_pos - prefix_len - margin): raw_pos + len(canary) + suffix_len + margin
        ]

        if "<" in payload and "<" in check_window and "&lt;" not in check_window:
            # A literal '<' sits in the raw source immediately around THIS
            # occurrence (within the bounds our own payload could plausibly
            # reach), yet the parser still resolved it as plain text here
            # (likely because it wasn't followed by a valid tag name). Any
            # ONE dangerous occurrence is enough to report immediately,
            # regardless of whether other occurrences of the same canary
            # elsewhere in the response happen to be safely escaped.
            evidence_window = response_text[max(0, raw_pos - 80): raw_pos + 80]
            snippet = evidence_window[:200]
            return "unescaped_angle_bracket_in_text", (
                "A raw '<' character from the payload appears unescaped near the canary in the "
                f"response, but did not form a recognizable element: {snippet}"
            ), snippet

    if saw_any_text_occurrence:
        return "escaped_text", "Canary reflected as ordinary, properly-escaped text content (all occurrences checked).", None

    # No text-node occurrence at all - if step 2 found a harmless
    # (non-dangerous) attribute occurrence, that is the correct, specific
    # classification to report here, not the generic "inconclusive"
    # catch-all below. (A real gap this fixes: when the canary ONLY ever
    # appears inside an attribute and never as plain text, falling through
    # to "inconclusive" would have discarded a perfectly good, already-
    # determined attribute_value_context classification.)
    if harmless_attribute_match is not None:
        return harmless_attribute_match

    # Canary is present somewhere BeautifulSoup didn't surface via the tree
    # walk above (e.g. inside an HTML comment, or a parsing quirk).
    idx = response_text.find(canary)
    snippet = response_text[max(0, idx - 80): idx + 80]
    occurrence_count = response_text.count(canary)
    return "inconclusive", (
        f"Canary reflected in an unclassified location ({occurrence_count} occurrence(s) total); "
        f"example: {snippet}"
    ), snippet


def check_reflection(response_text, payload):
    """
    Classifies how `payload` reflects in `response_text` using
    _classify_reflection() (see its docstring for the full table) and maps
    that classification onto a reporting decision.

    Returns a dict:
      {
        "reflected": bool,        # canary appeared anywhere in the response
        "vulnerable": bool,       # should this be reported as a finding
        "confidence": str | None, # "confirmed" | "suspected" | None
        "classification": str,    # one of the labels from _classify_reflection
        "detail": str,            # human-readable evidence, safe to put in the shared schema's evidence field
      }

    IMPORTANT: this performs static, parser-based analysis only. See the
    module docstring's "Design notes / known limitations" section before
    treating `confirmed` as a guarantee of real-world exploitability.
    """
    classification, detail, _snippet = _classify_reflection(response_text, payload)

    if classification == "not_reflected":
        return {"reflected": False, "vulnerable": False, "confidence": None,
                "classification": classification, "detail": detail}

    if classification in _CONFIRMED_CLASSIFICATIONS:
        return {"reflected": True, "vulnerable": True, "confidence": "confirmed",
                "classification": classification, "detail": detail}

    if classification in _SUSPECTED_CLASSIFICATIONS:
        return {"reflected": True, "vulnerable": True, "confidence": "suspected",
                "classification": classification, "detail": detail}

    # escaped_text, attribute_value_context: reflected, but not a finding.
    return {"reflected": True, "vulnerable": False, "confidence": None,
            "classification": classification, "detail": detail}


def _timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_SEVERITY_BY_CLASSIFICATION = {
    "script_context": "high",
    "event_handler_attribute": "high",
    "uri_scheme_attribute": "high",
    "unescaped_angle_bracket_in_text": "medium",
    "inconclusive": "low",
}


class _ScanBudget:
    """
    Tracks request count and wall-clock deadline shared across BOTH the
    reflected and stored-XSS phases of one run(), so adding the stored-XSS
    phase doesn't silently double the effective MAX_REQUESTS_PER_RUN /
    MAX_SECONDS_PER_RUN a caller configured - the two phases draw from the
    same pool.
    """

    def __init__(self):
        self.request_count = 0
        self.deadline = time.monotonic() + MAX_SECONDS_PER_RUN

    def exhausted(self):
        if self.request_count >= MAX_REQUESTS_PER_RUN:
            return "MAX_REQUESTS_PER_RUN"
        if time.monotonic() >= self.deadline:
            return "MAX_SECONDS_PER_RUN"
        return None

    def record_request(self):
        self.request_count += 1


def _parse_endpoints(recon_output):
    """
    Normalizes recon_output into a list of endpoint dicts, or None if the
    input isn't a recognizable shape at all (caller should return [] then).
    """
    if isinstance(recon_output, dict):
        return recon_output.get("params", [])
    if isinstance(recon_output, list):
        return recon_output
    return None


def _run_reflected_phase(
    endpoints, budget, session=None, diagnostics=None, baseline_results=None
):
    """
    The original reflected-XSS sweep: every param x every payload (shared
    CANARY for the whole phase, since each check is a self-contained
    request/response cycle with no persistence involved).
    """
    payload_entries = get_payload_list()
    findings = []
    tested = set()

    for endpoint_index, endpoint in enumerate(endpoints):
        endpoint_report = (
            diagnostics["endpoints"][endpoint_index]
            if diagnostics is not None else None
        )
        if not isinstance(endpoint, dict) or not endpoint.get("url"):
            logger.warning("xss.run: skipping malformed endpoint entry: %r", endpoint)
            if endpoint_report is not None:
                endpoint_report["status"] = "skipped"
                endpoint_report["reason"] = "Malformed endpoint entry."
            continue

        url = endpoint["url"]
        method = str(endpoint.get("method", "GET")).upper()
        param_names = endpoint.get("params", [])
        if not isinstance(param_names, list):
            logger.warning("xss.run: endpoint %s has non-list 'params', skipping", url)
            if endpoint_report is not None:
                endpoint_report["status"] = "skipped"
                endpoint_report["reason"] = "Endpoint parameters are not a list."
            continue

        if not _in_scope(url):
            logger.warning("xss.run: skipping %s, not within AUTHORIZED_TARGET", url)
            if endpoint_report is not None:
                endpoint_report["status"] = "skipped"
                endpoint_report["reason"] = "Endpoint is outside the authorized scope."
            continue

        baseline = (baseline_results or {}).get(endpoint_index)
        if baseline is not None and baseline["status"] != "passed":
            if endpoint_report is not None:
                endpoint_report["status"] = "failed"
                endpoint_report["reason"] = (
                    "Neutral form submission failed; payload testing was not started."
                )
            continue

        if not param_names:
            if endpoint_report is not None:
                endpoint_report["status"] = "skipped"
                endpoint_report["reason"] = "No parameters were discovered for this endpoint."
            continue

        endpoint_incomplete = False
        for param in param_names:
            parameter_report = None
            if endpoint_report is not None:
                parameter_report = {
                    "name": param if isinstance(param, str) else repr(param),
                    "status": "skipped",
                    "payload_attempts": 0,
                    "responses": 0,
                    "successful_responses": 0,
                    "http_status_counts": {},
                }
                endpoint_report["parameters"].append(parameter_report)

            if not isinstance(param, str) or not param:
                if parameter_report is not None:
                    parameter_report["reason"] = "Parameter name is missing or invalid."
                continue
            if _is_csrf_token_name(param):
                logger.info("xss.run: preserving anti-CSRF field '%s' on %s", param, url)
                if parameter_report is not None:
                    parameter_report["reason"] = "CSRF token is preserved and excluded from payload testing."
                continue

            key = (
                url,
                method,
                param,
                endpoint.get("page_url"),
                endpoint.get("form_index"),
            )
            if key in tested:
                if parameter_report is not None:
                    parameter_report["reason"] = "Duplicate endpoint parameter; already covered."
                continue
            tested.add(key)
            parameter_incomplete = False

            for entry in payload_entries:
                reason = budget.exhausted()
                if reason:
                    logger.warning("xss.run: reached %s, stopping reflected-XSS phase", reason)
                    endpoint_incomplete = True
                    parameter_incomplete = True
                    if parameter_report is not None:
                        parameter_report["status"] = "incomplete"
                        parameter_report["reason"] = f"Scan stopped because {reason} was reached."
                    _record_scan_issue(
                        diagnostics, "budget", f"Scan stopped because {reason} was reached.",
                        endpoint, param,
                    )
                    if endpoint_report is not None:
                        endpoint_report["status"] = "incomplete"
                        endpoint_report["reason"] = f"Scan stopped because {reason} was reached."
                    return findings

                payload = entry["payload"]
                if parameter_report is not None:
                    parameter_report["payload_attempts"] += 1
                issue_count = len(diagnostics["issues"]) if diagnostics is not None else 0
                try:
                    # budget is passed through so every real HTTP attempt
                    # (including redirect hops) counts exactly once, inside
                    # _send_with_scope_safe_redirects - NOT counted again here.
                    response = inject_payload(
                        endpoint, param, payload, budget=budget, session=session,
                        diagnostics=diagnostics,
                    )
                    if response is None:
                        if diagnostics is not None and len(diagnostics["issues"]) == issue_count:
                            _record_scan_issue(
                                diagnostics, "request",
                                "No response was received for this parameter test.",
                                endpoint, param,
                            )
                        endpoint_incomplete = True
                        parameter_incomplete = True
                        continue

                    if parameter_report is not None:
                        parameter_report["responses"] += 1
                        status_key = str(response.status_code)
                        parameter_report["http_status_counts"][status_key] = (
                            parameter_report["http_status_counts"].get(status_key, 0) + 1
                        )
                    if response.status_code < 200 or response.status_code >= 300:
                        endpoint_incomplete = True
                        parameter_incomplete = True
                        _record_scan_issue(
                            diagnostics, "request",
                            f"Payload request returned HTTP {response.status_code}.",
                            endpoint, param,
                        )
                        continue

                    if parameter_report is not None:
                        parameter_report["successful_responses"] += 1

                    result = check_reflection(response.text, payload)
                    if (
                        diagnostics is not None
                        and result.get("classification") == "inconclusive"
                        and str(result.get("detail", "")).startswith("Response could not be parsed as HTML")
                    ):
                        endpoint_incomplete = True
                        parameter_incomplete = True
                        _record_scan_issue(
                            diagnostics, "parsing", result["detail"], endpoint, param,
                        )
                except Exception as e:
                    # One bad request/response should never kill the whole
                    # scan; log and move on to the next payload.
                    logger.warning("xss.run: error testing param '%s' on %s: %s", param, url, e)
                    endpoint_incomplete = True
                    parameter_incomplete = True
                    _record_scan_issue(
                        diagnostics, "scanner", f"Parameter test failed: {e}", endpoint, param,
                    )
                    continue

                if result["vulnerable"]:
                    logger.info(
                        "XSS finding ('%s' confidence) on '%s' of %s: %s",
                        result["confidence"], param, url, result["classification"],
                    )
                    findings.append({
                        "module": MODULE_NAME,
                        "target": url,
                        "finding": f"Reflected XSS in '{param}' parameter ({entry['context']} context)",
                        "severity": _SEVERITY_BY_CLASSIFICATION.get(result["classification"], "medium"),
                        "evidence": (
                            f"Payload sent via {method} to {url}. "
                            f"Payload: {html.escape(payload)[:200]}. "
                            f"{result['detail']}"
                        ),
                        "confidence": result["confidence"],
                        "timestamp": _timestamp(),
                    })
                    if parameter_report is not None:
                        parameter_report["status"] = (
                            "incomplete" if parameter_incomplete else "tested"
                        )
                    break  # this param is already proven reflective; move on

            if parameter_report is not None and parameter_report["status"] != "tested":
                if parameter_report["payload_attempts"] > 0:
                    if parameter_report["successful_responses"] == 0:
                        parameter_report["status"] = "failed"
                    elif parameter_incomplete:
                        parameter_report["status"] = "incomplete"
                    else:
                        parameter_report["status"] = "tested"
                else:
                    parameter_report["status"] = "skipped"
                if parameter_report["status"] in ("failed", "incomplete"):
                    endpoint_incomplete = True

        if endpoint_report is not None and endpoint_report["status"] == "pending":
            tested_parameters = [
                item for item in endpoint_report["parameters"]
                if item["status"] == "tested"
            ]
            failed_parameters = [
                item for item in endpoint_report["parameters"]
                if item["status"] in ("failed", "incomplete")
            ]
            if tested_parameters and not failed_parameters and not endpoint_incomplete:
                endpoint_report["status"] = "tested"
            elif tested_parameters:
                endpoint_report["status"] = "incomplete"
                endpoint_report["reason"] = "One or more parameter tests did not complete."
            elif any(item["status"] == "failed" for item in failed_parameters):
                endpoint_report["status"] = "failed"
                endpoint_report["reason"] = "One or more eligible parameter tests failed."
            elif failed_parameters:
                endpoint_report["status"] = "incomplete"
                endpoint_report["reason"] = "One or more parameter tests did not complete."
            else:
                endpoint_report["status"] = "skipped"
                endpoint_report["reason"] = "No eligible non-CSRF parameters were available to test."

    return findings


# ---------------------------------------------------------------------------
# Stored XSS
# ---------------------------------------------------------------------------
#
# === What this does ===
# For each POST-method form recon found, submits one proof-of-concept
# payload (with a canary unique to that test - see _generate_unique_canary),
# then makes a SEPARATE, fresh GET request back to the form's own URL and
# runs it through the exact same check_reflection() engine used for
# reflected testing. If the payload shows up unescaped in that second,
# independent request - one that carried no payload of its own - that is
# evidence CONSISTENT WITH the value having been stored by the target and
# re-rendered unsafely. It is not proof of database persistence
# specifically: the same observation would also result from, for example,
# a cache, a session-scoped echo, or any other server-side mechanism that
# re-serves a previous submission without the client resending it. This
# module has no way to distinguish those from genuine storage, and does
# not claim to - findings are worded as "possible stored XSS", and
# `confidence` carries the same meaning it does for reflected findings
# (whether the HTML/JS context is parser-confirmed dangerous), not a
# separate claim about the persistence mechanism.
#
# === The heuristic this relies on, and its limitation ===
# Recon records each form's source page and position, allowing this module
# to re-fetch it with the same session before submission. The stored-state
# check still assumes the submission URL is the page that displays the
# result. For forms with no explicit `action` (or action=""), those URLs
# are the same, which covers a common comment-box or guestbook pattern.
# Recon does not map a storage-input endpoint to a separate display page,
# and this module does not work around that gap by guessing.
#
# CONCRETELY: this WILL catch a stored XSS where submitting the form and
# viewing its effect happen on the same URL. It will MISS a stored XSS
# where, e.g., a profile-bio form at /settings persists content that is
# actually rendered on a completely different /profile/<id> page - this
# module has no information linking those two URLs and does not claim any
# coverage of that case.
#
# === Why this is opt-in, not run by default ===
# Unlike reflected testing, every stored-XSS test here WRITES real data
# into the target's persistent storage. This module has no generic,
# known-safe way to delete that data afterward (no cleanup endpoint is
# available via the current interfaces), so running it is a deliberate,
# explicit choice - see run()'s test_stored_xss parameter and the
# XSS_TEST_STORED_XSS environment variable. Every stored-XSS finding's
# evidence explicitly names the canary left behind so the target owner can
# find and remove it after the engagement.
#
# === Scope limits on this phase specifically ===
# Only ONE canonical payload (a raw <script> tag) is submitted per param,
# not the full payload list reflected testing uses - each submission is a
# real write to the target, so this phase deliberately makes the minimum
# number of persistent writes needed to get a yes/no answer, rather than
# sweeping every context variant the way reflected testing does.
# ---------------------------------------------------------------------------

_TRUE_STRINGS = {"1", "true", "yes", "on"}


def _stored_xss_enabled(explicit):
    """explicit True/False always wins; None reads XSS_TEST_STORED_XSS (default: off)."""
    if explicit is not None:
        return bool(explicit)
    return os.getenv("XSS_TEST_STORED_XSS", "false").strip().lower() in _TRUE_STRINGS


def _fetch_plain(url, budget=None, session=None):
    """
    A scope-checked, redirect-safe GET with no injected parameters at all -
    used to re-fetch a page's current, already-persisted state.
    Deliberately separate from inject_payload() (which always sends a
    payload/marker value): this function sends nothing, so that a later
    match is evidence the target itself is re-serving the earlier
    submission, not an artifact of this particular request.

    Goes through the exact same _send_with_scope_safe_redirects() machinery
    inject_payload() uses (scope re-validated on every hop, shared budget,
    no auto-redirect-following), rather than a bare requests.get(). A bare
    requests.get() defaults to allow_redirects=True with NO per-hop scope
    revalidation at all - using that here was a real bug: if the display
    page redirected anywhere (e.g. a login wall, or a totally unrelated
    host), this function would previously have silently followed it
    outside AUTHORIZED_TARGET with no check whatsoever. Stored-XSS
    verification must get exactly the same scope protection as reflected
    scanning, not a weaker path.

    `budget` works the same way as in inject_payload(): optional, defaults
    to a fresh throwaway _ScanBudget for standalone calls.
    """
    if budget is None:
        budget = _ScanBudget()
    return _send_with_scope_safe_redirects("GET", url, {}, budget, session=session)


def _run_stored_phase(endpoints, budget, session=None):
    """
    The engine behind the stored-XSS workflow described above. Only
    POST-method endpoints are treated as storage-input candidates (GET
    parameters are already fully covered by the reflected phase, and POST
    is the conventional submission method for comments/profile
    fields/messages this module targets). See the module-level "Stored
    XSS" docstring block above for the full design and its limitations.
    """
    findings = []
    tested = set()

    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or not endpoint.get("url"):
            continue

        method = str(endpoint.get("method", "GET")).upper()
        if method != "POST":
            continue  # see module docstring: only POST forms are storage-input candidates

        url = endpoint["url"]
        param_names = endpoint.get("params", [])
        if not isinstance(param_names, list):
            continue
        if not _in_scope(url):
            continue

        for param in param_names:
            if not isinstance(param, str) or not param:
                continue
            if _is_csrf_token_name(param):
                logger.info("xss.run (stored): preserving anti-CSRF field '%s' on %s", param, url)
                continue

            key = (url, param)
            if key in tested:
                continue
            tested.add(key)

            reason = budget.exhausted()
            if reason:
                logger.warning("xss.run: reached %s, stopping stored-XSS phase", reason)
                return findings

            unique_canary = _generate_unique_canary()
            payload = f"<script>alert('{unique_canary}')</script>"

            try:
                # budget passed through - each actual HTTP attempt this
                # causes (including any redirect hops) is counted exactly
                # once, inside _send_with_scope_safe_redirects.
                submit_response = inject_payload(endpoint, param, payload, budget=budget, session=session)
            except Exception as e:
                logger.warning("xss.run (stored): submission failed for '%s' on %s: %s", param, url, e)
                continue

            if submit_response is None:
                continue  # out of scope, malformed, budget exhausted, or network failure - already logged

            reason = budget.exhausted()
            if reason:
                logger.warning("xss.run: reached %s, stopping stored-XSS phase", reason)
                return findings

            try:
                # Same shared budget threaded through the re-fetch, and the
                # same scope-safe redirect handling as the submission above
                # (see _fetch_plain's docstring for why a bare requests.get()
                # here would have been a scope-bypass risk).
                display_response = _fetch_plain(url, budget=budget, session=session)
            except Exception as e:
                logger.warning("xss.run (stored): re-fetch failed for %s: %s", url, e)
                continue

            if display_response is None:
                continue

            try:
                result = check_reflection(display_response.text, payload)
            except Exception as e:
                logger.warning("xss.run (stored): classification failed for '%s' on %s: %s", param, url, e)
                continue

            if result["vulnerable"]:
                logger.info(
                    "Stored XSS finding ('%s' confidence) on '%s' of %s: %s",
                    result["confidence"], param, url, result["classification"],
                )
                findings.append({
                    "module": MODULE_NAME,
                    "target": url,
                    "finding": f"Possible stored XSS in '{param}' parameter (unescaped on a later, separate request)",
                    # Deliberately the SAME table reflected findings use
                    # (_SEVERITY_BY_CLASSIFICATION), not an automatically
                    # upgraded one. The classification already reflects the
                    # concrete parser-confirmed context (script/attribute/
                    # URI vs. ambiguous text); persistence widens how many
                    # people a real exploit could reach, but this module
                    # cannot independently confirm persistence (see
                    # docstring above) and so does not use that as grounds
                    # to auto-upgrade severity. A human reviewer with
                    # access to the target's actual architecture is better
                    # placed to make that call than a heuristic is.
                    "severity": _SEVERITY_BY_CLASSIFICATION.get(result["classification"], "medium"),
                    "evidence": (
                        f"Marker submitted via POST to {url} (param '{param}'); a SEPARATE, later GET request "
                        f"to the same URL - carrying no payload of its own - rendered it back unescaped. "
                        f"Payload: {html.escape(payload)[:200]}. {result['detail']} This is consistent with "
                        "the value being stored and re-served by the target, but is not independent proof of "
                        "database persistence specifically - a cache or session-scoped echo could produce the "
                        "same observation. This finding also relies on the heuristic that the submission URL "
                        "itself displays previously-submitted content; it will miss stored XSS that displays "
                        "on a different page (see xss.py's Stored XSS docstring for this limitation). No "
                        "cleanup mechanism is available via the current project interfaces - please manually "
                        f"remove test data containing marker '{unique_canary}' from the target after this "
                        "engagement."
                    ),
                    "confidence": result["confidence"],
                    "timestamp": _timestamp(),
                })

    return findings


def run_stored_xss_checks(recon_output):
    """
    Standalone entry point for the stored-XSS workflow, for a caller who
    wants to run ONLY stored-XSS testing (e.g. as a deliberate, separate,
    explicitly-authorized step) without the reflected sweep. run() calls
    the same underlying engine when test_stored_xss is enabled; this
    function exists so stored-XSS testing can also be invoked on its own.
    Subject to the same MAX_REQUESTS_PER_RUN / MAX_SECONDS_PER_RUN limits
    (its own fresh budget, not shared with a separate run() call). See the
    "Stored XSS" docstring block above before using this - it writes real
    data to the target with no automated cleanup.
    """
    if not os.getenv("AUTHORIZED_TARGET"):
        raise RuntimeError("AUTHORIZED_TARGET is not set in .env. Refusing to run XSS tests.")

    endpoints = _parse_endpoints(recon_output)
    if endpoints is None:
        logger.warning("run_stored_xss_checks: recon_output is neither a dict nor a list (%r)", type(recon_output))
        return []

    budget = _ScanBudget()
    session = requests.Session() if _has_form_provenance(endpoints) else None
    try:
        return _run_stored_phase(endpoints, budget, session=session)
    finally:
        if session is not None:
            session.close()


def _has_form_provenance(endpoints):
    return any(
        isinstance(endpoint, dict) and "page_url" in endpoint and "form_index" in endpoint
        for endpoint in endpoints
    )


def _initialize_scan_diagnostics(endpoints, diagnostics):
    diagnostics.clear()
    diagnostics.update({
        "status": "incomplete",
        "endpoint_count": len(endpoints),
        "form_count": 0,
        "forms_tested": 0,
        "forms_skipped": 0,
        "forms_failed": 0,
        "forms_incomplete": 0,
        "requests_attempted": 0,
        "endpoints": [],
        "issues": [],
        "_issue_keys": set(),
    })

    for endpoint in endpoints:
        is_form = (
            isinstance(endpoint, dict)
            and "page_url" in endpoint
            and "form_index" in endpoint
        )
        report = {
            "is_form": is_form,
            "url": endpoint.get("url") if isinstance(endpoint, dict) else None,
            "method": endpoint.get("method", "GET") if isinstance(endpoint, dict) else None,
            "page_url": endpoint.get("page_url") if is_form else None,
            "form_index": endpoint.get("form_index") if is_form else None,
            "status": "pending",
            "parameters": [],
        }
        diagnostics["endpoints"].append(report)
        if is_form:
            diagnostics["form_count"] += 1


def _finalize_scan_diagnostics(diagnostics, budget):
    if diagnostics is None:
        return

    for endpoint in diagnostics["endpoints"]:
        if endpoint["status"] == "pending":
            endpoint["status"] = "incomplete"
            endpoint["reason"] = "The scan ended before this endpoint was tested."

    form_reports = [item for item in diagnostics["endpoints"] if item["is_form"]]
    diagnostics["forms_tested"] = sum(item["status"] == "tested" for item in form_reports)
    diagnostics["forms_skipped"] = sum(item["status"] == "skipped" for item in form_reports)
    diagnostics["forms_failed"] = sum(item["status"] == "failed" for item in form_reports)
    diagnostics["forms_incomplete"] = sum(item["status"] == "incomplete" for item in form_reports)
    diagnostics["requests_attempted"] = budget.request_count
    diagnostics["status"] = (
        "completed"
        if diagnostics["endpoints"]
        and all(item["status"] == "tested" for item in diagnostics["endpoints"])
        and not diagnostics["issues"]
        else "incomplete"
    )
    if not diagnostics["endpoints"]:
        diagnostics["issues"].append({
            "kind": "recon",
            "message": "Reconnaissance did not discover any parameterized endpoints to test.",
        })
    diagnostics.pop("_issue_keys", None)


def run(recon_output, test_stored_xss=None, diagnostics=None):
    """
    Tests every param recon found against every payload and returns the
    list of findings, in the exact shared schema (module, target, finding,
    severity, evidence, confidence, timestamp - no extra keys).

    Validates and tolerates malformed input: a bad endpoint entry is skipped
    with a warning rather than crashing the whole scan. Bounded by
    MAX_REQUESTS_PER_RUN and MAX_SECONDS_PER_RUN so a scan can't run away
    against a large site; both are configurable via environment variables,
    and both apply to the TOTAL work done across reflected and stored-XSS
    testing combined, not separately per phase.

    `test_stored_xss` controls whether the stored-XSS phase (see that
    section below) also runs. It defaults to None, which reads the
    XSS_TEST_STORED_XSS environment variable (default: disabled). Pass
    True/False to override the environment explicitly. This is OFF by
    default because, unlike reflected testing, stored-XSS testing writes
    real data into the target's persistent storage (comments, profile
    fields, etc.) that this module has no way to clean up afterward - see
    the stored-XSS section's docstring. Running it is a deliberate choice
    the operator should make, not an automatic side effect of calling
    run(recon_output) the same way every other module's run() is called.

    Before reflected testing, each in-scope POST form with Recon provenance
    receives one neutral baseline submission using synthetic values for
    visible text controls. Hidden fields (including antiforgery tokens),
    checked controls, and selected options are preserved. This can trigger
    the form's ordinary application behavior; it is used to distinguish a
    server-side form failure from failures caused by test payloads. Failed
    baselines stop payload testing for that form.
    """
    if not os.getenv("AUTHORIZED_TARGET"):
        raise RuntimeError("AUTHORIZED_TARGET is not set in .env. Refusing to run XSS tests.")

    endpoints = _parse_endpoints(recon_output)
    if endpoints is None:
        logger.warning("xss.run: recon_output is neither a dict nor a list (%r); nothing to scan", type(recon_output))
        if diagnostics is not None:
            diagnostics.clear()
            diagnostics.update({
                "status": "incomplete",
                "endpoint_count": 0,
                "form_count": 0,
                "forms_tested": 0,
                "forms_skipped": 0,
                "forms_failed": 0,
                "forms_incomplete": 0,
                "requests_attempted": 0,
                "endpoints": [],
                "issues": [{
                    "kind": "recon",
                    "message": "Reconnaissance output was not a supported object or list.",
                }],
            })
        return []

    if not isinstance(endpoints, list):
        logger.warning("xss.run: recon_output params are not a list; nothing to scan")
        endpoints = []

    if diagnostics is not None:
        _initialize_scan_diagnostics(endpoints, diagnostics)

    budget = _ScanBudget()
    session = requests.Session() if _has_form_provenance(endpoints) else None
    try:
        baseline_results = _run_form_baselines(
            endpoints, budget, session, diagnostics=diagnostics,
        )
        findings = _run_reflected_phase(
            endpoints, budget, session=session, diagnostics=diagnostics,
            baseline_results=baseline_results,
        )

        if _stored_xss_enabled(test_stored_xss):
            findings.extend(_run_stored_phase(endpoints, budget, session=session))
            if diagnostics is not None:
                diagnostics["stored_xss"] = "enabled; reflected-form coverage is reported above"
        else:
            logger.info(
                "xss.run: stored-XSS phase skipped (disabled). Pass test_stored_xss=True or set "
                "XSS_TEST_STORED_XSS=true to enable it - see run_stored_xss_checks()'s docstring first."
            )
            if diagnostics is not None:
                diagnostics["stored_xss"] = "disabled"

        return findings
    finally:
        if session is not None:
            session.close()
        _finalize_scan_diagnostics(diagnostics, budget)


if __name__ == "__main__":
    # Quick manual smoke test: python -m xss.xss
    # Requires AUTHORIZED_TARGET in .env and a fake param list, since this
    # module normally gets its input from recon's output.
    import json

    target = os.getenv("AUTHORIZED_TARGET")
    if not target:
        print("[!] ERROR: AUTHORIZED_TARGET is not set. Check your .env file.")
    else:
        fake_recon_output = {
            "params": [
                {"url": target, "method": "GET", "params": ["q"]},
            ]
        }
        print(json.dumps(run(fake_recon_output), indent=2))
