"""
AI report generator — the function Kenzy's "Generate Report" / "Download
Report" button calls on the backend.

Usage from her FastAPI code:

    from report_generator import generate_report

    @app.get("/report")
    def report():
        findings = get_all_analyzed_findings_from_db()   # her code — each one
                                                           # is a finding dict
                                                           # ALREADY merged with
                                                           # analyze_finding()'s
                                                           # output
        return generate_report(findings)                 # her JS takes it from here

generate_report() takes the list of findings (shared schema + whatever
analyze_finding() added: plain_english, ai_severity, fix_suggestion,
payload_suggestions, ai_ok, ...) and returns ONE dict: an AI-written
executive summary plus a clean per-finding breakdown with severity,
explanation and PoC, ready for her frontend to render/print/download.
It never raises — on any failure it still returns a usable report with a
fallback summary.
"""

import json
import requests
from datetime import datetime, timezone
from collections import Counter

OLLAMA_URL = "http://localhost:11434/api/chat"
PRIMARY_MODEL = "qwen2.5:7b-instruct"
FALLBACK_MODEL = "qwen2.5-coder:3b"
TIMEOUT_SECONDS = 300

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SUMMARY_SYSTEM_PROMPT = """You are the AI co-pilot inside an authorized web application penetration
testing tool, writing the executive summary at the top of the final report.
You are given the full list of CONFIRMED findings from this engagement
(each one already individually analyzed and triaged). You do not invent
findings, you only summarize the ones you are given.

Respond with ONLY a single JSON object, no prose before or after it, no
markdown code fences, matching exactly this shape:

{
  "overview": string,
  "key_risks": [string],
  "overall_recommendation": string
}

Rules:
- Base this only on the findings list you are given (module, target,
  severity, finding text, confidence).
- "overview" is 2-4 sentences, written for someone who may not be technical
  (e.g. the client or professor), describing the overall security posture
  found.
- "key_risks" is the 3-5 most important findings to fix first, in plain
  language, ordered by severity.
- "overall_recommendation" is 1-2 sentences on what to do next.
- If the findings list is empty, say so plainly and do not invent risks.
- Output valid JSON only. No trailing commentary."""


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _display_severity(f: dict) -> str:
    """Prefer the AI's severity if the analysis succeeded, otherwise fall
    back to the module's own severity."""
    if f.get("ai_ok") and f.get("ai_severity") in SEVERITY_ORDER:
        return f["ai_severity"]
    return f.get("severity", "low")


def _build_finding_entry(f: dict) -> dict:
    return {
        "module": f.get("module"),
        "target": f.get("target"),
        "severity": _display_severity(f),
        "confidence": f.get("confidence"),
        "explanation": f.get("plain_english") or f.get("finding"),
        "fix_suggestion": f.get("fix_suggestion"),
        "poc": {
            "raw_finding": f.get("finding"),
            "evidence": f.get("evidence"),
            "payload_suggestions": f.get("payload_suggestions", []),
        },
    }


def _ai_summary(findings: list) -> dict:
    slim = [
        {
            "module": f.get("module"),
            "target": f.get("target"),
            "finding": f.get("finding"),
            "severity": _display_severity(f),
            "confidence": f.get("confidence"),
        }
        for f in findings
    ]
    user_prompt = "Confirmed findings from this engagement:\n\n" + json.dumps(slim, indent=2)

    for model in (PRIMARY_MODEL, FALLBACK_MODEL):
        try:
            resp = requests.post(
                OLLAMA_URL,
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
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
            if {"overview", "key_risks", "overall_recommendation"}.issubset(parsed.keys()):
                parsed["ai_ok"] = True
                return parsed
        except Exception:
            continue

    return _fallback_summary(findings)


def _fallback_summary(findings: list) -> dict:
    counts = Counter(_display_severity(f) for f in findings)
    overview = (
        f"AI-written summary is unavailable right now. {len(findings)} confirmed "
        f"finding(s) were found: " + ", ".join(f"{v} {k}" for k, v in counts.items())
        if findings else
        "AI-written summary is unavailable right now. No confirmed findings."
    )
    return {
        "overview": overview,
        "key_risks": [],
        "overall_recommendation": "Review the findings list below manually.",
        "ai_ok": False,
    }


def generate_report(findings: list) -> dict:
    """
    findings: list of finding dicts, each already run through
    analyze_finding() from ai_layer.py (so each has the shared schema fields
    PLUS plain_english / ai_severity / fix_suggestion / payload_suggestions /
    ai_ok). A finding that never got AI analysis still works — it just falls
    back to its module's own severity/finding text.

    Returns one dict:

    {
      "generated_at": ISO timestamp,
      "summary": { overview, key_risks, overall_recommendation, ai_ok },
      "stats": { "total": int, "by_severity": {severity: count} },
      "findings": [ { module, target, severity, confidence, explanation,
                       fix_suggestion, poc }, ... ]   # sorted by severity
    }

    This is exactly what Kenzy's button hands to her JS to render into the
    printable/downloadable report.
    """
    findings = findings or []
    entries = [_build_finding_entry(f) for f in findings]
    entries.sort(key=lambda e: SEVERITY_ORDER.get(e["severity"], 99))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": _ai_summary(findings),
        "stats": {
            "total": len(entries),
            "by_severity": dict(Counter(e["severity"] for e in entries)),
        },
        "findings": entries,
    }
