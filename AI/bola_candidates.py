"""
Builds BOLA test candidates directly from what recon.py actually returns:
a flat list of crawled URLs ("endpoints") and a list of query/form params
("params": [{"url", "method", "params": [field names]}]).

This is deterministic — no AI call, no network request — same reliability
guarantee as the rest of the pipeline. It replaces bola_tester.py's
suggest_bola_targets() for real scans, because recon doesn't give you
pre-made "/orders/{id}" templates; it gives you "/orders/102" and you have
to spot the id yourself. (suggest_bola_targets is still in bola_tester.py
and still works fine against hand-built endpoint lists like in the test
harness — it's just not what recon's real output needs.)

Two detection strategies, both feeding into the same candidate shape
run_bola_test()/run_bola_agent() already expect:

  1. Path-based: a URL segment that's purely numeric, or long enough to be
     an opaque id/slug (hex ids, UUID-ish strings), gets generalized into
     an {id} template. Method is assumed GET (recon's "endpoints" list
     only comes from following links, i.e. GET requests).

  2. Query/body-based: any param field whose name matches a small set of
     id-ish keywords (id, user_id, order_id, profile_id, account_id, pk,
     item_id, doc_id...) becomes a candidate on that endpoint, using the
     method recon already recorded for it.

Usage:

    from bola_candidates import build_candidates_from_recon

    candidates = build_candidates_from_recon(target_url, recon_output)
    # candidates is a list in the exact shape bola_tester.run_bola_test()
    # and bola_agent.run_bola_agent() already expect:
    #   {"method": ..., "path": ..., "id_param": ..., "id_location": ..., "rationale": ...}
"""

import re
from urllib.parse import urlparse

_ID_KEYWORDS = (
    "id", "user_id", "order_id", "profile_id", "account_id", "pk",
    "item_id", "doc_id", "document_id", "invoice_id", "cart_id",
    "message_id", "booking_id", "ticket_id", "uid", "uuid",
)

# A path segment counts as an "id" if it's purely numeric, or if it's a
# long-ish alphanumeric/hex/UUID-looking token (not an ordinary word).
_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_OPAQUE_SEGMENT = re.compile(r"^[0-9a-fA-F-]{8,}$")  # hex ids, UUIDs, long digit/hyphen tokens


def _looks_like_id(segment: str) -> bool:
    return bool(_NUMERIC_SEGMENT.match(segment) or _OPAQUE_SEGMENT.match(segment))


def _path_candidates(target_url: str, endpoints: list) -> list:
    candidates = {}  # path_template -> candidate dict, deduplicated

    for url in endpoints or []:
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        segments = [s for s in parsed.path.split("/") if s]
        if not segments:
            continue

        for i, segment in enumerate(segments):
            if not _looks_like_id(segment):
                continue
            templated = segments.copy()
            templated[i] = "{id}"
            path_template = "/" + "/".join(templated)

            if path_template in candidates:
                continue  # already have this template from an earlier URL

            candidates[path_template] = {
                "method": "GET",
                "path": path_template,
                "id_param": "id",
                "id_location": "path",
                "rationale": f"Path segment '{segment}' in {url} looks like an object id.",
            }

    return list(candidates.values())


def _query_body_candidates(params: list) -> list:
    candidates = {}  # (path, method, id_param) -> candidate dict, deduplicated

    for entry in params or []:
        url = entry.get("url")
        method = (entry.get("method") or "GET").upper()
        fields = entry.get("params", [])
        if not url or not isinstance(fields, list):
            continue

        path = urlparse(url).path or "/"

        for field in fields:
            if not isinstance(field, str):
                continue
            lowered = field.lower()
            if not any(keyword == lowered or lowered.endswith("_" + keyword) or lowered == keyword
                       for keyword in _ID_KEYWORDS):
                continue

            key = (path, method, field)
            if key in candidates:
                continue

            candidates[key] = {
                "method": method,
                "path": path,
                "id_param": field,
                "id_location": "query" if method == "GET" else "body",
                "rationale": f"Field '{field}' on {method} {url} looks like an object id parameter.",
            }

    return list(candidates.values())


def build_candidates_from_recon(target_url: str, recon_output: dict) -> list:
    """
    recon_output: whatever recon.run() returned (tech_stack, endpoints, params).

    Returns a deduplicated list of candidate dicts in the shape
    bola_tester.run_bola_test() and bola_agent.run_bola_agent() expect:
    {"method", "path", "id_param", "id_location", "rationale"}.

    Returns [] (never raises) if recon_output is missing or malformed —
    fails closed, same convention as the rest of the pipeline.
    """
    if not isinstance(recon_output, dict):
        return []

    endpoints = recon_output.get("endpoints", [])
    params = recon_output.get("params", [])

    candidates = _path_candidates(target_url, endpoints)
    candidates += _query_body_candidates(params)
    return candidates
def build_candidates_from_paths(paths: list) -> list:
    """Manual fallback: turn path templates like '/api/orders/{id}' into candidates."""
    candidates = []
    for path in paths or []:
        if isinstance(path, str) and path.startswith("/") and "{id}" in path:
            candidates.append({
                "method": "GET",
                "path": path,
                "id_param": "id",
                "id_location": "path",
                "rationale": "Manually supplied candidate path.",
            })

    return candidates
