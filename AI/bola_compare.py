"""
Runs BOTH BOLA checks on the same candidate endpoint — the deterministic
one (bola_tester.run_bola_test) and the autonomous AI agent
(bola_agent.run_bola_agent) — and reconciles them. This is "trust but
verify": you still get the bigger, decision-making AI role you wanted, but
an AI-only "vulnerable" claim doesn't get auto-reported as confirmed —
only flagged for a human to glance at. A claim backed by BOTH methods is
the strongest possible finding to put in the report.

Usage:

    from bola_compare import run_bola_comparison

    result = run_bola_comparison(base_url, candidate, user_a, user_b)
    if result["recommended_finding"]:
        findings.append(analyze_finding(result["recommended_finding"]))
    print(result["agreement"])   # for your demo/report narrative
"""

from datetime import datetime, timezone

from AI.bola_tester import run_bola_test
from AI.bola_agent import run_bola_agent


def run_bola_comparison(base_url: str, candidate: dict, user_a, user_b) -> dict:
    """
    candidate: same shape bola_tester expects
               (method, path, id_param, id_location, rationale).

    Returns:
    {
      "target": string,
      "deterministic_finding": dict or None,
      "ai_finding": dict or None,
      "agreement": "both_confirmed" | "deterministic_only" | "ai_only" | "both_clear",
      "recommended_finding": dict or None,   # what to actually put in the report
      "timestamp": ISO string
    }

    Reconciliation rule:
      - both confirmed      -> report the deterministic finding (it has
                                machine-checked evidence), tagged as
                                AI-independently-agreed too
      - deterministic only  -> report it. The deterministic check is ground
                                truth regardless of what the agent decided —
                                it's the one with hard proof.
      - AI only             -> do NOT auto-report as confirmed. The agent's
                                own judgment with no independent check is
                                exactly the false-positive risk the rest of
                                the tool is designed to avoid. Surface it for
                                a human to look at instead.
      - both clear          -> nothing to report.
    """
    det_finding = run_bola_test(base_url, candidate, user_a, user_b)
    ai_finding = run_bola_agent(
        base_url, candidate["path"], user_a, user_b, id_param=candidate.get("id_param", "id")
    )

    det_says_vuln = det_finding is not None
    ai_says_vuln = ai_finding is not None

    if det_says_vuln and ai_says_vuln:
        agreement = "both_confirmed"
        recommended = dict(det_finding)
        recommended["ai_independently_agreed"] = True
    elif det_says_vuln:
        agreement = "deterministic_only"
        recommended = det_finding
    elif ai_says_vuln:
        agreement = "ai_only"
        recommended = None  # flagged, not auto-reported — see ai_finding for the raw claim
    else:
        agreement = "both_clear"
        recommended = None

    return {
        "target": base_url.rstrip("/") + candidate["path"],
        "deterministic_finding": det_finding,
        "ai_finding": ai_finding,
        "agreement": agreement,
        "recommended_finding": recommended,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
