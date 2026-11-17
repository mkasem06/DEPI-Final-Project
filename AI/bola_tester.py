"""
BOLA (Broken Object-Level Authorization) testing module.

Unlike SQLi/XSS/misconfig, there's no deterministic scanner for this bug
class (sqlmap, reflection probes, etc. don't apply) — the AI has to help
decide WHAT to test. So this module splits the work the same way the rest
of the tool treats AI: AI proposes, deterministic code confirms.

    1. suggest_bola_targets(endpoints)  -> AI looks at the endpoint list
       (from the recon module) and flags which ones look like per-user
       resources worth testing, and what to swap to test them.
    2. run_bola_test(...)               -> actually sends the real HTTP
       requests and only returns a finding if a cross-user leak/mutation
       was OBSERVED. This part never "trusts" the AI — it checks.

Every finding this module produces is in the same shared schema the rest
of the team uses (module, target, finding, severity, evidence, confidence,
timestamp), so it drops straight into analyze_finding() from ai_layer.py
with zero changes there.

Usage:

    from bola_tester import suggest_bola_targets, run_bola_test, TestUser
    from ai_layer import analyze_finding

    user_a = TestUser("User A", "Bearer <token_a>", owned_resource_id="101")
    user_b = TestUser("User B", "Bearer <token_b>", owned_resource_id="102")

    candidates = suggest_bola_targets(recon_endpoints)
    findings = []
    for c in candidates:
        finding = run_bola_test(base_url, c, user_a, user_b)
        if finding:
            findings.append(analyze_finding(finding))  # same AI layer as the other modules
"""

import json
import requests
from datetime import datetime, timezone

OLLAMA_URL = "http://localhost:11434/api/chat"
PRIMARY_MODEL = "qwen2.5:7b-instruct"
FALLBACK_MODEL = "qwen2.5-coder:3b"
TIMEOUT_SECONDS = 300

# ---------------------------------------------------------------------------
# Step 1: AI suggests which endpoints to test and how
# ---------------------------------------------------------------------------

SUGGEST_SYSTEM_PROMPT = """You are the AI co-pilot inside an authorized web application penetration
testing tool, specifically the module that looks for Broken Object-Level
Authorization (BOLA / IDOR) candidates. You are given a list of discovered
API endpoints (from the recon module) against a target the team has written
authorization to test. You do not call these endpoints yourself — you only
decide which ones are worth testing and what parameter to swap.

For each endpoint you consider promising, respond with a JSON array (even
if empty), no prose before or after it, no markdown code fences, where each
element matches exactly this shape:

{
  "method": "GET"|"POST"|"PUT"|"PATCH"|"DELETE",
  "path": string,
  "id_param": string,
  "id_location": "path"|"query"|"body",
  "rationale": string
}

Rules:
- Only include endpoints that reference what looks like a per-user or
  per-owner resource (an order, profile, message, invoice, document, cart,
  etc.) identified by an id/slug a client controls.
- Skip endpoints that are clearly public (no id) or clearly admin-only by
  name alone.
- id_param is the exact name of the id in the path/query/body, e.g. "id" in
  "/api/orders/{id}".
- Output valid JSON only. No trailing commentary."""


def suggest_bola_targets(endpoints: list) -> list:
    """
    endpoints: list of dicts like {"method": "GET", "path": "/api/orders/{id}"}
    (whatever the recon module already has).

    Returns a list of candidate dicts (see SUGGEST_SYSTEM_PROMPT shape), or
    [] if the AI call fails or returns something unusable — this is a
    suggestion layer, so failing closed (no candidates) is the safe default,
    never a crash.
    """
    user_prompt = "Here are the discovered endpoints:\n\n" + json.dumps(endpoints, indent=2)

    for model in (PRIMARY_MODEL, FALLBACK_MODEL):
        try:
            resp = requests.post(
                OLLAMA_URL,
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SUGGEST_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.2, "num_ctx": 2048},
                },
                timeout=TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            raw = resp.json()["message"]["content"]
            parsed = json.loads(_strip_code_fences(raw))
            if not isinstance(parsed, list):
                continue
            valid = [c for c in parsed if _valid_candidate(c)]
            return valid
        except Exception:
            continue

    return []


def _valid_candidate(c) -> bool:
    required = {"method", "path", "id_param", "id_location", "rationale"}
    return isinstance(c, dict) and required.issubset(c.keys())


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


# ---------------------------------------------------------------------------
# Step 2: deterministic confirmation — the part that actually proves it
# ---------------------------------------------------------------------------

class TestUser:
    """One authenticated identity to test with."""

    def __init__(self, label: str, token: str, owned_resource_id: str, auth_header: str = "Authorization"):
        self.label = label                           # e.g. "User A"
        self.token = token                            # e.g. "Bearer eyJ..."
        self.owned_resource_id = owned_resource_id    # the id THIS user owns, e.g. their own order id
        self.auth_header = auth_header


def run_bola_test(base_url: str, candidate: dict, user_a: TestUser, user_b: TestUser,
                   extra_headers: dict = None, timeout: int = 15):
    """
    Confirms (or rules out) BOLA on one candidate endpoint by actually
    swapping identities: request user_b's resource using user_a's token.

    Returns a finding dict in the shared schema if the swap leaked or let
    user_a mutate user_b's resource, or None if it didn't (not every AI
    suggestion is actually vulnerable — that's the point of this step).
    """
    extra_headers = extra_headers or {}
    method = candidate["method"].upper()
    path = candidate["path"]

    def build(id_value, as_user: TestUser):
        url = base_url.rstrip("/") + path.replace("{" + candidate["id_param"] + "}", str(id_value))
        headers = {as_user.auth_header: as_user.token, **extra_headers}
        kwargs = {"headers": headers, "timeout": timeout}
        if candidate["id_location"] == "query":
            kwargs["params"] = {candidate["id_param"]: id_value}
        elif candidate["id_location"] == "body":
            kwargs["json"] = {candidate["id_param"]: id_value}
        return url, kwargs

    try:
        baseline_url, baseline_kwargs = build(user_b.owned_resource_id, user_b)
        baseline_resp = requests.request(method, baseline_url, **baseline_kwargs)

        attack_url, attack_kwargs = build(user_b.owned_resource_id, user_a)
        attack_resp = requests.request(method, attack_url, **attack_kwargs)
    except requests.RequestException:
        return None  # couldn't even reach it — not a confirmed finding

    leaked = (
        attack_resp.status_code < 400
        and attack_resp.text.strip()
        and attack_resp.text.strip() == baseline_resp.text.strip()
    )
    # For mutating methods, succeeding (2xx) on A touching B's resource is
    # itself the vulnerability, regardless of whether bodies match.
    mutated = method in ("POST", "PUT", "PATCH", "DELETE") and attack_resp.status_code < 300

    if not (leaked or mutated):
        return None

    return {
        "module": "bola",
        "target": attack_url,
        "finding": (
            f"Broken Object-Level Authorization: {user_a.label}'s token could "
            f"{'read' if leaked else 'modify'} a resource belonging to {user_b.label} "
            f"via {method} {path} (id_param='{candidate['id_param']}')."
        ),
        "severity": "high" if mutated else "medium",
        "evidence": {
            "rationale": candidate.get("rationale", ""),
            "request": {"method": method, "url": attack_url},
            "baseline_status": baseline_resp.status_code,
            "attack_status": attack_resp.status_code,
            "attack_response_snippet": attack_resp.text[:500],
        },
        "confidence": "confirmed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
