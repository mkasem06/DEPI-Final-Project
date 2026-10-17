
import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.database import (
    init_db,
    save_scan,
    get_scan_history
)

from recon.recon import run as run_recon


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
# REQUEST MODEL
# ---------------------------------------

class ReconRequest(BaseModel):
    target_url: str


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

        if port not in (None, 80, 443):
            raise ValueError("Unsupported port")

        addresses = socket.getaddrinfo(
            parsed.hostname,
            port or (
                443 if parsed.scheme == "https" else 80
            ),
            type=socket.SOCK_STREAM
        )

        if not addresses or any(
            not ipaddress.ip_address(item[4][0]).is_global
            for item in addresses
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
# REAL RECONNAISSANCE SCAN
# ---------------------------------------


@app.post("/api/scans/recon")
def start_recon(request: ReconRequest):

    # Validate the entered URL
    validate_target(request.target_url)

    try:

        # Call the actual reconnaissance module
        results = run_recon(request.target_url)

        # Check if reconnaissance failed
        if "error" in results.get("tech_stack", {}):
            raise RuntimeError("Target could not be reached")

        # Save successful scan in SQLite
        save_scan(
            target_url=request.target_url,
            scan_type="recon",
            status="completed"
        )

        # Return real reconnaissance results
        return {
            "tech_stack": results.get("tech_stack", {}),
            "endpoints": results.get("endpoints", []),
            "params": results.get("params", [])
        }

    except Exception as error:

        print(f"[!] Recon scan failed: {error}")

        # Save failed scan in SQLite
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
# VULNERABILITY FINDINGS
# ---------------------------------------

@app.get("/api/findings")
def get_findings(module: Optional[str] = None):

    # Real vulnerability scanner modules
    # will populate this in the future.
    # No mock vulnerabilities.

    findings = []

    if module is not None:
        findings = [
            finding
            for finding in findings
            if finding.get("module") == module
        ]

    return findings


# ---------------------------------------
# VULNERABILITY STATISTICS
# ---------------------------------------

@app.get("/api/stats")
def get_stats():

    findings = get_findings()

    total = len(findings)

    critical = sum(
        1 for finding in findings
        if finding.get("severity") == "critical"
    )

    high = sum(
        1 for finding in findings
        if finding.get("severity") == "high"
    )

    medium = sum(
        1 for finding in findings
        if finding.get("severity") == "medium"
    )

    low = sum(
        1 for finding in findings
        if finding.get("severity") == "low"
    )

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }


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
