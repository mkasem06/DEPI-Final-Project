
import os
from backend.database import init_db, save_scan, get_scan_history
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Optional
from urllib.parse import urlparse
from fastapi import HTTPException
from fastapi import FastAPI
from pydantic import BaseModel #Pydantic helps FastAPI validate incoming request data.
from recon.recon import run as run_recon
# Create an instance of the FastAPI application
app = FastAPI()
init_db()
app.mount("/static",StaticFiles(directory="frontend"),name="static")
# Read the authorized target from an environment variable
AUTHORIZED_TARGET = os.getenv("AUTHORIZED_TARGET", "")

# Check whether the requested URL is authorized
def is_authorized_target(url: str):
    requested = urlparse(url)
    approved = urlparse(AUTHORIZED_TARGET)

    return (
        requested.scheme in ("http", "https")
        and requested.hostname is not None
        and requested.hostname == approved.hostname
        and requested.port == approved.port
        and requested.scheme == approved.scheme
        and requested.username is None
        and requested.password is None
        and bool(AUTHORIZED_TARGET)
    )
# Defines the JSON data required to request a Recon scan
class ReconRequest(BaseModel):
    target_url: str

# GET endpoint for the home page (/)
# When someone visits http://127.0.0.1:8000/,
# FastAPI automatically executes the home() function
def home():
    return {"message": "DEPI Pentesting API is running"}

# GET endpoint to retrieve vulnerability findings
# Full URL: http://127.0.0.1:8000/api/findings
# GET is used to request data from the server
# /api/findings is the path we chose for scan results
@app.get("/api/findings")
def get_findings(module: Optional[str] = None):
    findings = [
        {
            "module": "xss",
            "target": "https://example.com/search",
            "finding": "Reflected XSS",
            "severity": "high",
            "evidence": "Input reflected without escaping",
            "confidence": "suspected",
            "timestamp": "2026-10-15T12:00:00Z"
        },
        {
            "module": "sqli",
            "target": "https://example.com/login",
            "finding": "SQL injection",
            "severity": "critical",
            "evidence": "Mock SQLi finding",
            "confidence": "suspected",
            "timestamp": "2026-10-15T12:05:00Z"
        }
    ]

    if module is not None:
        findings = [
            finding for finding in findings
            if finding["module"] == module
        ]

    return findings


@app.post("/api/scans/recon")
def start_recon(request: ReconRequest):

    # Reject targets outside our approved scope
    if not is_authorized_target(request.target_url):
        raise HTTPException(
            status_code=403,
            detail="Target is not authorized for scanning"
        )

    # Return mock results until real scanning is enabled
    results = {
        "tech_stack": {"server": "Apache"},
        "endpoints": [request.target_url],
        "params": []
    }

    return results


# GET endpoint to return vulnerability statistics
@app.get("/api/stats")
def get_stats():

    # Get all findings without filtering
    findings = get_findings()

    # Count all findings
    total = len(findings)

    # Count findings based on severity
    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")

    # Return statistics as JSON
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }

@app.get("/dashboard")
def dashboard():
    return FileResponse("frontend/index.html")


@app.post("/api/demo/recon")
def demo_recon(request: ReconRequest):

    # Save a simulated scan in SQLite
    save_scan(
        target_url="https://demo.invalid",
        scan_type="recon-demo",
        status="completed"
    )

    # Return simulated reconnaissance results
    return {
        "tech_stack": {
            "server": "Apache"
        },
        "endpoints": [
            "https://demo.invalid/"
        ],
        "params": [],
        "mode": "demo"
    }


@app.get("/api/scans/history")
def scan_history():
    return get_scan_history()
