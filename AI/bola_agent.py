"""
Autonomous BOLA agent.

Unlike bola_tester.py (AI suggests a candidate -> deterministic code sends
exactly two requests and diffs them -> code decides vulnerable or not),
THIS version gives the AI the actual decision + action loop:

    1. The AI is told the candidate endpoint and the two test identities.
    2. On each turn it replies with ONE JSON action: either
       {"action": "send_request", ...}  -> your script actually sends that
       real HTTP request and feeds the real response back to it, or
       {"action": "verdict", ...}        -> it's done, here's its decision.
    3. The AI decides what to send, how many requests to send (up to a cap),
       and whether what came back proves a BOLA. Your code never computes
       vulnerable/not-vulnerable itself here — the AI does.

The one guardrail kept: whatever request IDs the AI cites as evidence in
its verdict MUST correspond to requests your script actually sent and
logged. It cannot cite a response that was never really received — but
"is this response actually a privacy leak" is the AI's judgment call, not
a string comparison. That's the trade you're choosing by using this file
instead of (or alongside) bola_tester.py.

Output is in the same shared finding schema (module, target, finding,
severity, evidence, confidence, timestamp) PLUS "ai_decided": True so a
human reviewing the final report can tell this one wasn't code-verified
the way the other modules' findings are.

Usage:

    from bola_agent import TestUser, run_bola_agent

    user_a = TestUser("User A", "Bearer user_101", owned_resource_id="101")
    user_b = TestUser("User B", "Bearer user_102", owned_resource_id="102")

    finding = run_bola_agent(
        base_url="http://localhost:5055",
        candidate_path="/api/orders/{id}",
        user_a=user_a,
        user_b=user_b,
    )
    if finding:
        findings.append(finding)   # can still go through generate_report() as-is
"""

import json
import requests
from datetime import datetime, timezone

OLLAMA_URL = "http://localhost:11434/api/chat"
PRIMARY_MODEL = "qwen2.5:7b-instruct"
FALLBACK_MODEL = "qwen2.5-coder:3b"
TIMEOUT_SECONDS = 300
MAX_TURNS = 6  # hard cap on how many requests the agent can send before it must give a verdict

AGENT_SYSTEM_PROMPT = """You are an autonomous security-testing agent inside an authorized web
application penetration testing tool. Your job right now is to investigate
ONE candidate endpoint for Broken Object-Level Authorization (BOLA/IDOR):
can one user's credentials access or modify a resource that belongs to a
different user?

You are given the base URL, the candidate path (with an {id} placeholder),
and two real test identities: user_a and user_b, each with their own
token and the id of a resource they legitimately own. You do NOT know in
advance exactly which request will expose the bug — you decide what to
try.

On every turn, respond with ONLY one JSON object, no prose before or
after it, no markdown code fences. Two possible shapes:

To send a real HTTP request (your script will actually send it and give
you the real response on the next turn):
{
  "action": "send_request",
  "method": "GET"|"POST"|"PUT"|"PATCH"|"DELETE",
  "url": string,
  "headers": object,
  "body": object or null
}

When you have enough evidence to decide, stop sending requests and give
your final answer:
{
  "action": "verdict",
  "vulnerable": boolean,
  "confidence": "low"|"medium"|"high",
  "severity": "low"|"medium"|"high"|"critical",
  "explanation": string,
  "evidence_request_ids": [integer, ...]
}

Rules:
- evidence_request_ids must only reference requests you actually sent via
  send_request in this conversation (numbered 1, 2, 3... in the order you
  sent them). Never cite a request number you didn't actually send.
- Only send requests to the given base_url. Never invent a different host.
- You get at most {max_turns} send_request turns before you must give a
  verdict with whatever evidence you have.
- A reasonable strategy: first confirm what user_b's own resource looks
  like with user_b's own token, then try user_a's token against user_b's
  resource id, and compare. But you decide the actual strategy.
- If nothing you tried showed a leak or an unauthorized write, say
  vulnerable: false and explain what you tried.
- Output valid JSON only. No trailing commentary, ever."""


class TestUser:
    def __init__(self, label: str, token: str, owned_resource_id: str, auth_header: str = "Authorization"):
        self.label = label
        self.token = token
        self.owned_resource_id = owned_resource_id
        self.auth_header = auth_header


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _call_model(model: str, messages: list) -> str:
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.2, "num_ctx": 4096},
        },
        timeout=TIMEOUT_SECONDS,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _execute_send_request(action: dict, timeout: int = 15):
    """Actually performs the HTTP request the AI asked for. Never raises —
    network failures are reported back to the AI as data, not crashes."""
    try:
        resp = requests.request(
            action.get("method", "GET"),
            action["url"],
            headers=action.get("headers") or {},
            json=action.get("body"),
            timeout=timeout,
        )
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body_snippet": resp.text[:800],
        }
    except requests.RequestException as exc:
        return {"error": str(exc)}


def run_bola_agent(base_url: str, candidate_path: str, user_a: TestUser, user_b: TestUser,
                    id_param: str = "id"):
    """
    Runs the autonomous agent loop against one candidate endpoint. Returns a
    finding dict (shared schema + ai_decided: True) if the AI concluded it's
    vulnerable, or None if it decided it wasn't, or if the AI couldn't be
    reached / never produced a usable verdict (fails closed — no finding
    rather than a crash or a fabricated one).
    """
    system_prompt = AGENT_SYSTEM_PROMPT.replace("{max_turns}", str(MAX_TURNS))
    context = {
        "base_url": base_url,
        "candidate_path": candidate_path,
        "id_param": id_param,
        "user_a": {"label": user_a.label, "token": user_a.token, "owned_resource_id": user_a.owned_resource_id,
                   "auth_header": user_a.auth_header},
        "user_b": {"label": user_b.label, "token": user_b.token, "owned_resource_id": user_b.owned_resource_id,
                   "auth_header": user_b.auth_header},
    }

    for model in (PRIMARY_MODEL, FALLBACK_MODEL):
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Investigate this candidate:\n\n" + json.dumps(context, indent=2)},
        ]
        request_log = {}  # request_id -> {"action": ..., "result": ...}

        try:
            verdict = _run_turns(model, messages, request_log)
        except Exception:
            continue  # this model failed outright, try the fallback model

        if verdict is None:
            continue  # this model never gave a usable verdict, try the fallback model

        if not verdict.get("vulnerable"):
            return None  # AI decided: not vulnerable — no finding, don't report it

        # Guardrail: every cited piece of evidence must be a request we actually logged.
        cited_ids = verdict.get("evidence_request_ids", [])
        valid_cited = [i for i in cited_ids if i in request_log]
        if not valid_cited:
            continue  # AI said "vulnerable" but cited no real evidence — don't trust it, try fallback model

        return {
            "module": "bola_agent",
            "target": base_url.rstrip("/") + candidate_path,
            "finding": f"[AI-decided, not code-verified] {verdict.get('explanation', '')}",
            "severity": verdict.get("severity", "medium"),
            "evidence": {
                "cited_requests": {i: request_log[i] for i in valid_cited},
                "all_requests_sent": request_log,
            },
            "confidence": verdict.get("confidence", "medium"),
            "ai_decided": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    return None  # both models failed to produce a trustworthy verdict


def _run_turns(model: str, messages: list, request_log: dict):
    """Runs the send_request/verdict loop for one model. Returns the parsed
    verdict dict, or None if MAX_TURNS is hit with no verdict."""
    for turn in range(1, MAX_TURNS + 1):
        raw = _call_model(model, messages)
        try:
            action = json.loads(_strip_code_fences(raw))
        except Exception:
            return None  # model didn't return valid JSON — don't guess, bail to fallback model

        if action.get("action") == "verdict":
            return action

        if action.get("action") == "send_request":
            result = _execute_send_request(action)
            request_log[turn] = {"request": action, "result": result}
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": f"Result of request #{turn}:\n" + json.dumps(result, indent=2)})
            continue

        return None  # unrecognized action shape

    return None  # hit MAX_TURNS without a verdict
