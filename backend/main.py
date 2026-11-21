import ipaddress
import os
import socket
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.database import (
    init_db,
    save_scan,
    get_scan_history,
    get_scan_by_id,
)

from recon.recon import run as run_recon

from sqli.sqli import run as run_sqli
from misconfig.misconfig import run as run_misconfig
from xss.xss import run as run_xss

from AI.bola_candidates import build_candidates_from_recon, build_candidates_from_paths
from AI.bola_tester import run_bola_test, TestUser
from AI.bola_compare import run_bola_comparison
from AI.ai_layer import analyze_finding
from AI.report_generator import generate_report
from AI.report_html import render_report_html


# Off by default. Set ALLOW_LOCAL_TARGETS=1 ONLY on a dev/demo machine to
# allow scanning 127.0.0.1 / private IPs (needed for the local vulnerable app).
ALLOW_LOCAL = os.getenv("ALLOW_LOCAL_TARGETS") == "1"


# ---------------------------------------
# INITIALIZE FASTAPI
# ---------------------------------------

app = FastAPI(
    title="DEPI Pentesting Dashboard",
    description="Web Application Security Scanner",
    version="1.0.0"
)

init_db()

app.mount(
    "/static",
    StaticFiles(directory="frontend"),
    name="static"
)


# ---------------------------------------
# REQUEST MODELS
# ---------------------------------------

class ReconRequest(BaseModel):
    target_url: str


class FullScanRequest(BaseModel):
    target_url: str
    bola_user_a_token: Optional[str] = None
    bola_user_a_resource_id: Optional[str] = None
    bola_user_b_token: Optional[str] = None
    bola_user_b_resource_id: Optional[str] = None
    bola_auth_header: Optional[str] = "Authorization"
    # Off: code check only. On: runs code check + AI agent on every candidate
    # and tags each finding with who detected it.
    use_ai_agent_for_bola: Optional[bool] = False
    # Fallback if recon doesn't crawl the API links, e.g. ["/api/orders/{id}"]
    bola_extra_paths: Optional[List[str]] = None


# ---------------------------------------
# VALIDATE TARGET URL
# ---------------------------------------

def validate_target(url: str):

    parsed = urlparse(url)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid HTTP or HTTPS URL"
        )

    try:
        port = parsed.port

        if port is not None and not (1 <= port <= 65535):
            raise ValueError("Invalid port")

        addresses = socket.getaddrinfo(
            parsed.hostname,
            port or (
                443 if parsed.scheme == "https" else 80
            ),
            type=socket.SOCK_STREAM
        )

        if not addresses or (
            not ALLOW_LOCAL
            and any(
                not ipaddress.ip_address(item[4][0]).is_global
                for item in addresses
            )
        ):
            raise ValueError("Non-public target")

    except (ValueError, socket.gaierror):
        raise HTTPException(
            status_code=400,
            detail="Only public HTTP/HTTPS websites are supported"
        )

    return parsed


# ---------------------------------------
# HOME ENDPOINT
# ---------------------------------------

@app.get("/")
def home():

    return {
        "message": "DEPI Pentesting API is running",
        "status": "online"
    }


# ---------------------------------------
# RECON
# ---------------------------------------

@app.post("/api/scans/recon")
def start_recon(request: ReconRequest):

    validate_target(request.target_url)

    try:
        results = run_recon(request.target_url)

        if "error" in results.get("tech_stack", {}):
            raise RuntimeError("Target could not be reached")

        save_scan(
            target_url=request.target_url,
            scan_type="recon",
            status="completed"
        )

        return {
            "tech_stack": results.get("tech_stack", {}),
            "endpoints": results.get("endpoints", []),
            "params": results.get("params", [])
        }

    except Exception as error:

        print(f"[!] Recon scan failed: {error}")

        save_scan(
            target_url=request.target_url,
            scan_type="recon",
            status="failed"
        )

        raise HTTPException(
            status_code=500,
            detail="Reconnaissance scan failed"
        )


# ---------------------------------------
# FULL SCAN
# ---------------------------------------

@app.post("/api/scans/full")
def full_scan(request: FullScanRequest):

    validate_target(request.target_url)
    target_url = request.target_url

    os.environ["AUTHORIZED_TARGET"] = target_url

    try:
        recon_output = run_recon(target_url)
    except Exception as error:
        print(f"[!] Recon failed: {error}")
        save_scan(target_url, "full", "failed", results={"error": "Recon failed"})
        raise HTTPException(status_code=500, detail="Reconnaissance failed")

    if "error" in recon_output.get("tech_stack", {}):
        save_scan(target_url, "full", "failed", results={"error": "Target unreachable"})
        raise HTTPException(status_code=500, detail="Target unreachable")

    all_findings = []

    try:
        all_findings += run_sqli(recon_output)
    except Exception as error:
        print(f"[!] SQLi module failed: {error}")

    try:
        all_findings += run_xss(recon_output)
    except Exception as error:
        print(f"[!] XSS module failed: {error}")

    try:
        all_findings += run_misconfig(target_url, recon_output)
    except Exception as error:
        print(f"[!] Misconfig module failed: {error}")

    if request.bola_user_a_token and request.bola_user_b_token:
        try:
            user_a = TestUser(
                "User A", request.bola_user_a_token,
                request.bola_user_a_resource_id, request.bola_auth_header,
            )
            user_b = TestUser(
                "User B", request.bola_user_b_token,
                request.bola_user_b_resource_id, request.bola_auth_header,
            )

            candidates = build_candidates_from_recon(target_url, recon_output)

            # Fallback: add manually supplied paths that recon didn't find
            known_paths = {c["path"] for c in candidates}
            for extra in build_candidates_from_paths(request.bola_extra_paths):
                if extra["path"] not in known_paths:
                    candidates.append(extra)

            print(f"[BOLA] {len(candidates)} candidate(s): {[c['path'] for c in candidates]}")

            for candidate in candidates:
                if request.use_ai_agent_for_bola:
                    cmp = run_bola_comparison(target_url, candidate, user_a, user_b)
                    det = cmp.get("deterministic_finding")
                    ai = cmp.get("ai_finding")
                    print(
                        f"[BOLA] {candidate['path']} -> "
                        f"code={'VULN' if det else 'no'} | "
                        f"AI={'VULN' if ai else 'no'} | "
                        f"agreement={cmp.get('agreement')}"
                    )

                    if det and ai:
                        det["detected_by"] = "code + AI agent (both agree)"
                        det["finding"] = "[CODE + AI] " + det["finding"]
                        det["ai_reasoning"] = ai.get("finding")
                        all_findings.append(det)
                    elif det:
                        det["detected_by"] = "code only"
                        det["finding"] = "[CODE ONLY] " + det["finding"]
                        all_findings.append(det)
                    elif ai:
                        ai["detected_by"] = "AI agent only (unverified)"
                        ai["needs_review"] = True
                        ai["finding"] = "[AI ONLY - UNVERIFIED] " + ai["finding"]
                        all_findings.append(ai)
                else:
                    finding = run_bola_test(target_url, candidate, user_a, user_b)
                    print(f"[BOLA] {candidate['path']} -> code={'VULN' if finding else 'no'}")
                    if finding:
                        finding["detected_by"] = "code only"
                        finding["finding"] = "[CODE ONLY] " + finding["finding"]
                        all_findings.append(finding)
        except Exception as error:
            print(f"[!] BOLA module failed: {error}")
    else:
        print("[*] Skipping BOLA: no test-user credentials were provided for this scan.")

    analyzed = [{**finding, **analyze_finding(finding)} for finding in all_findings]

    scan_id = save_scan(target_url, "full", "completed", results=analyzed)

    return {
        "scan_id": scan_id,
        "tech_stack": recon_output.get("tech_stack", {}),
        "endpoint_count": len(recon_output.get("endpoints", [])),
        "findings": analyzed,
    }


# ---------------------------------------
# FINDINGS
# ---------------------------------------

@app.get("/api/findings")
def get_findings(scan_id: Optional[int] = None, module: Optional[str] = None):

    if scan_id is not None:
        scan = get_scan_by_id(scan_id)
        findings = (scan.get("results") or []) if scan else []
    else:
        history = get_scan_history()
        latest_full = next(
            (row for row in history if row.get("scan_type") == "full"), None
        )
        if latest_full is None:
            return []
        scan = get_scan_by_id(latest_full["id"])
        findings = (scan.get("results") or []) if scan else []

    if isinstance(findings, dict):
        return []

    if module is not None:
        findings = [
            finding
            for finding in findings
            if finding.get("module") == module
        ]

    return findings


# ---------------------------------------
# STATS
# ---------------------------------------

@app.get("/api/stats")
def get_stats(scan_id: Optional[int] = None):

    findings = get_findings(scan_id=scan_id)

    total = len(findings)

    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }


# ---------------------------------------
# REPORT
# ---------------------------------------

@app.get("/api/scans/{scan_id}/report")
def scan_report(scan_id: int):

    scan = get_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.get("results")
    if not isinstance(findings, list):
        raise HTTPException(status_code=400, detail="This scan has no usable findings to report")

    return generate_report(findings)


@app.get("/api/scans/{scan_id}/report/html", response_class=HTMLResponse)
def scan_report_html(scan_id: int):

    scan = get_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.get("results")
    if not isinstance(findings, list):
        raise HTTPException(status_code=400, detail="This scan has no usable findings to report")

    report = generate_report(findings)
    return render_report_html(report, target_url=scan.get("target_url", ""))


# ---------------------------------------
# SCAN HISTORY
# ---------------------------------------

@app.get("/api/scans/history")
def scan_history():

    return get_scan_history()


# ---------------------------------------
# DASHBOARD PAGE
# ---------------------------------------

@app.get("/dashboard")
def dashboard():

    return FileResponse("frontend/index.html")