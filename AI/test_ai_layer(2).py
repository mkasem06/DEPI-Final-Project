"""
Test harness for the AI layer's finding-analysis prompt template.

Sends each mock finding through Ollama (qwen2.5:7b-instruct, falling back to
qwen2.5-coder:3b), validates the JSON response against the agreed schema, and
prints a pass/fail summary plus the raw output for your test report.

Requires: `pip install requests` and a running local Ollama with at least one
of the two models pulled (`ollama pull qwen2.5:7b-instruct`).
"""

import json
import re
import sys
import time
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
PRIMARY_MODEL = "qwen2.5:7b-instruct"
FALLBACK_MODEL = "qwen2.5-coder:3b"
TIMEOUT_SECONDS = 300  # 5 minutes — first load on limited RAM can be slow

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
- Never use a literal backslash character anywhere in your output (not in
  file paths, not in regex, not anywhere). If you need to reference a
  Windows-style path or an escape sequence, rephrase using forward slashes
  or words instead, because a stray backslash breaks JSON parsing.
- Output valid JSON only. No trailing commentary."""

MOCK_FINDINGS = [
    {
        "module": "sqli",
        "target": "https://friend-site.example/login",
        "finding": "SQL injection in 'username' parameter",
        "severity": "critical",
        "evidence": "sqlmap confirmed boolean-based blind SQLi; back-end: MySQL 8.0; "
                     "dumped table names from information_schema with --dbs",
        "confidence": "confirmed",
        "timestamp": "2026-10-20T10:00:00Z",
    },
    {
        "module": "xss",
        "target": "https://friend-site.example/search?q=",
        "finding": "Reflected input in 'q' parameter not consistently encoded",
        "severity": "medium",
        "evidence": "Payload <script>alert(1)</script> reflected inside an HTML attribute "
                     "context in 60% of requests; inconsistent under different "
                     "Accept-Language headers",
        "confidence": "suspected",
        "timestamp": "2026-10-20T10:05:00Z",
    },
    {
        "module": "misconfig",
        "target": "https://friend-site.example/",
        "finding": "Exposed .git directory and missing security headers",
        "severity": "high",
        "evidence": ".git/HEAD returned 200 with valid git ref; Content-Security-Policy, "
                     "X-Frame-Options, and Strict-Transport-Security headers absent on all "
                     "tested responses",
        "confidence": "confirmed",
        "timestamp": "2026-10-20T10:10:00Z",
    },
    {
        "module": "recon",
        "target": "https://friend-site.example/",
        "finding": "Crawled 14 endpoints, 3 forms, identified tech stack: nginx, PHP 8.1, "
                   "no WAF detected",
        "severity": "low",
        "evidence": "Endpoints and forms enumerated via crawl; Server header and response "
                     "timing used for stack fingerprint; no WAF challenge pages observed "
                     "across 20 probe requests",
        "confidence": "confirmed",
        "timestamp": "2026-10-20T09:55:00Z",
    },
]

REQUIRED_KEYS = {
    "plain_english": str,
    "ai_severity": str,
    "severity_agrees_with_module": bool,
    "severity_reasoning": str,
    "fix_suggestion": str,
    "payload_suggestions": list,
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def call_ollama(model: str, finding: dict) -> str:
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
            # num_ctx trims how much memory Ollama reserves up front. Our
            # findings + prompts are short, so a small context window is
            # plenty and it noticeably lowers the RAM needed to load the
            # model on machines with limited free memory.
            "options": {"temperature": 0.2, "num_ctx": 2048},
        },
        timeout=TIMEOUT_SECONDS,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def fix_invalid_escapes(text: str) -> str:
    """Safety net: the model sometimes writes a backslash that isn't a valid
    JSON escape (e.g. a stray \\ in a path or regex-like text). This finds
    any backslash NOT followed by one of the characters JSON allows after a
    backslash, and escapes it properly so json.loads doesn't choke on it."""
    return re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", text)


def validate(parsed: dict) -> list:
    errors = []
    for key, expected_type in REQUIRED_KEYS.items():
        if key not in parsed:
            errors.append(f"missing key: {key}")
            continue
        if not isinstance(parsed[key], expected_type):
            errors.append(
                f"{key}: expected {expected_type.__name__}, got {type(parsed[key]).__name__}"
            )
    if "ai_severity" in parsed and parsed["ai_severity"] not in VALID_SEVERITIES:
        errors.append(f"ai_severity has invalid value: {parsed['ai_severity']!r}")
    if "payload_suggestions" in parsed and isinstance(parsed["payload_suggestions"], list):
        if not all(isinstance(p, str) for p in parsed["payload_suggestions"]):
            errors.append("payload_suggestions contains non-string entries")
    return errors


def run_one(finding: dict, model: str) -> dict:
    raw = call_ollama(model, finding)
    cleaned = fix_invalid_escapes(strip_code_fences(raw))
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        return {"finding": finding, "raw": raw, "parsed": None, "errors": [f"invalid JSON: {e}"]}
    errors = validate(parsed)
    return {"finding": finding, "raw": raw, "parsed": parsed, "errors": errors}


def main():
    model = PRIMARY_MODEL
    results = []
    for finding in MOCK_FINDINGS:
        print(f"--- {finding['module']} ({finding['confidence']}) ---")
        try:
            result = run_one(finding, model)
        except Exception as primary_err:
            print(f"  primary model failed ({primary_err}); trying fallback {FALLBACK_MODEL}")
            try:
                model = FALLBACK_MODEL
                result = run_one(finding, model)
            except Exception as fallback_err:
                result = {
                    "finding": finding,
                    "raw": None,
                    "parsed": None,
                    "errors": [f"both models failed: {fallback_err}"],
                }
        result["model_used"] = model
        results.append(result)
        status = "PASS" if not result["errors"] else "FAIL"
        print(f"  [{status}] model={result['model_used']}")
        if result["errors"]:
            for e in result["errors"]:
                print(f"    - {e}")
        if result["parsed"]:
            print(json.dumps(result["parsed"], indent=2))
        elif result["raw"]:
            print("  raw output:", result["raw"][:500])
        print()
        time.sleep(0.5)

    print("=== Summary ===")
    passed = sum(1 for r in results if not r["errors"])
    print(f"{passed}/{len(results)} mock findings produced schema-valid output")
    for r in results:
        status = "PASS" if not r["errors"] else "FAIL"
        print(f"  {r['finding']['module']:<10} {r['finding']['confidence']:<10} {status}")

    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
