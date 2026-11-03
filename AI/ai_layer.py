"""
AI layer — the one function Kenzy's backend calls for the "Use AI" button.

Usage from her FastAPI code:

    from ai_layer import analyze_finding

    @app.post("/findings/{finding_id}/analyze")
    def analyze(finding_id: int):
        finding = get_finding_from_db(finding_id)   # her code
        result = analyze_finding(finding)             # your code
        save_ai_result_to_db(finding_id, result)      # her code
        return result

analyze_finding() takes one finding dict (the shared schema: module, target,
finding, severity, evidence, confidence, timestamp) and always returns a
dict — either the AI's analysis, or a safe fallback if the AI call failed,
so the backend never crashes because of this layer. It never raises an
exception itself.
"""

import json
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
PRIMARY_MODEL = "qwen2.5:7b-instruct"
FALLBACK_MODEL = "qwen2.5-coder:3b"
TIMEOUT_SECONDS = 300

SYSTEM_PROMPT = """You are the AI analysis layer inside an authorized web application penetration
testing tool. You are a co-pilot, not a scanner: all findings you receive were
already produced by deterministic scan modules (recon, SQLi via sqlmap, XSS
reflection testing, or misconfiguration checks) against a target the team has
written authorization to test. You do not run tests, you do not browse the
web, and you must never invent a finding that was not given to you.

For every finding you receive, respond with ONLY a single JSON object, no
prose before or after it, no markdown code fences, matching exactly this
shape:

{
  "plain_english": string,
  "ai_severity": "low"|"medium"|"high"|"critical",
  "severity_agrees_with_module": boolean,
  "severity_reasoning": string,
  "fix_suggestion": string,
  "payload_suggestions": [string]
}

Rules:
- Base every field only on the "finding", "evidence", "target", "module" and
  "confidence" fields you are given. Do not assume details not present.
- If confidence is "suspected", hedge your language in plain_english and
  fix_suggestion accordingly, and prefer payload_suggestions that would help
  confirm it.
- If the finding describes an absence of a problem, set ai_severity to "low",
  severity_agrees_with_module to true, payload_suggestions to [], and say so
  plainly in plain_english.
- Never suggest a payload against any target other than the one given.
- Output valid JSON only. No trailing commentary."""

REQUIRED_KEYS = {
    "plain_english": str,
    "ai_severity": str,
    "severity_agrees_with_module": bool,
    "severity_reasoning": str,
    "fix_suggestion": str,
    "payload_suggestions": list,
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _call_ollama(model: str, finding: dict) -> str:
    user_prompt = (
        f"Analyze this finding from the {finding['module']} module.\n\n"
        + json.dumps(finding, indent=2)
    )
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.2, "num_ctx": 2048},
        },
        timeout=TIMEOUT_SECONDS,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _validate(parsed: dict) -> list:
    errors = []
    for key, expected_type in REQUIRED_KEYS.items():
        if key not in parsed:
            errors.append(f"missing key: {key}")
            continue
        if not isinstance(parsed[key], expected_type):
            errors.append(f"{key}: wrong type")
    if "ai_severity" in parsed and parsed["ai_severity"] not in VALID_SEVERITIES:
        errors.append("ai_severity has invalid value")
    return errors


def _fallback_result(reason: str) -> dict:
    """Returned when the AI couldn't be reached or gave an unusable answer —
    the dashboard should show this as 'AI analysis unavailable', not crash."""
    return {
        "plain_english": f"AI analysis is unavailable right now ({reason}). "
                          f"Please review this finding manually.",
        "ai_severity": None,
        "severity_agrees_with_module": None,
        "severity_reasoning": None,
        "fix_suggestion": None,
        "payload_suggestions": [],
        "ai_ok": False,
    }


def analyze_finding(finding: dict) -> dict:
    """
    The one function the backend calls. Takes a finding dict (the shared
    schema), returns a dict with the AI's analysis merged with "ai_ok": True,
    or a safe fallback dict with "ai_ok": False if anything went wrong.
    Never raises — always returns something the API can send straight back
    to the frontend.
    """
    for model in (PRIMARY_MODEL, FALLBACK_MODEL):
        try:
            raw = _call_ollama(model, finding)
            cleaned = _strip_code_fences(raw)
            parsed = json.loads(cleaned)
        except Exception:
            continue  # try the next model, if any are left

        errors = _validate(parsed)
        if errors:
            continue  # bad shape from this model, try the next one

        parsed["ai_ok"] = True
        parsed["model_used"] = model
        return parsed

    return _fallback_result("both models failed or returned an invalid response")
