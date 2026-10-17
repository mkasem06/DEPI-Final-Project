"""SQLi module: runs sqlmap on each parameter recon found and returns findings."""

import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

MODULE_NAME = "sqli"
SQLMAP_CMD = os.getenv("SQLMAP_CMD", "sqlmap").split()
SQLMAP_TIMEOUT_SECONDS = 600
SQLMAP_LEVEL = 1
SQLMAP_RISK = 1
DEFAULT_VALUE = "1"
EVIDENCE_PAYLOAD_LIMIT = 300

TECHNIQUE_RATING = {
    "stacked queries": ("confirmed", "critical"),
    "UNION query": ("confirmed", "critical"),
    "error-based": ("confirmed", "high"),
    "boolean-based blind": ("confirmed", "high"),
    "inline query": ("confirmed", "high"),
    "time-based blind": ("suspected", "medium"),
}
SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# sqlmap still prints screen-control codes, so they are removed before lines are matched
_TERMINAL_CODES = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][0-9A-Za-z]|[\x0e\x0f]")
_PARAMETER_LINE = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<where>.+)\)$")
_DBMS_LINE = re.compile(r"^\s*back-end DBMS:\s*(?:active fingerprint:\s*)?(?P<dbms>.+)$", re.MULTILINE)
_DBMS_SENTENCE = re.compile(r"the back-end DBMS is (?P<dbms>.+)$", re.MULTILINE)


def _timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _as_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _shorten(text, limit=EVIDENCE_PAYLOAD_LIMIT):
    return text if len(text) <= limit else text[:limit] + "..."


def _in_scope(url):
    """True only if url has the same scheme, host and port as AUTHORIZED_TARGET."""
    approved = urlsplit(os.getenv("AUTHORIZED_TARGET", ""))
    requested = urlsplit(url)
    return (
        requested.scheme in ("http", "https")
        and requested.hostname is not None
        and requested.hostname == approved.hostname
        and requested.port == approved.port
        and requested.scheme == approved.scheme
        and requested.username is None
        and requested.password is None
    )


def run_sqlmap(endpoint, param):
    """Run sqlmap against one parameter and return its raw output as text."""
    url = endpoint["url"]
    method = endpoint.get("method", "GET").upper()

    values = {name: DEFAULT_VALUE for name in endpoint.get("params", [])}
    values.setdefault(param, DEFAULT_VALUE)

    command = SQLMAP_CMD + [
        "--batch",
        "--flush-session",
        "--disable-coloring",
        "--level", str(SQLMAP_LEVEL),
        "--risk", str(SQLMAP_RISK),
        "--timeout", "10",
        "--retries", "1",
        "-p", param,
    ]

    if method == "POST":
        command += ["-u", url, "--data", urlencode(values)]
    else:
        parts = urlsplit(url)
        merged = dict(parse_qsl(parts.query, keep_blank_values=True))
        for name, value in values.items():
            merged.setdefault(name, value)
        query_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(merged), ""))
        command += ["-u", query_url]

    logger.info("sqlmap: testing parameter '%s' of %s (%s)", param, url, method)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            timeout=SQLMAP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as expired:
        logger.warning("sqlmap timed out on '%s' of %s", param, url)
        partial = _as_text(expired.stdout) + _as_text(expired.stderr)
        return partial + f"\n[ERROR] sqlmap timed out after {SQLMAP_TIMEOUT_SECONDS} seconds\n"
    except FileNotFoundError:
        raise RuntimeError(
            f"sqlmap was not found (SQLMAP_CMD={' '.join(SQLMAP_CMD)}). See SETUP.md step 6."
        )

    if completed.returncode != 0:
        logger.warning("sqlmap exited with code %s on '%s' of %s",
                       completed.returncode, param, url)
    return completed.stdout + completed.stderr


def _injection_blocks(raw_output):
    blocks = []
    current = None
    for line in raw_output.splitlines():
        stripped = line.strip()
        if stripped == "---":
            if current is None:
                current = []
            else:
                blocks.append(current)
                current = None
        elif current is not None:
            current.append(stripped)
    return blocks


def _parse_injection_points(raw_output):
    points = []
    for block in _injection_blocks(raw_output):
        parameter, where, current = None, None, None
        for line in block:
            if line.startswith("Parameter:"):
                match = _PARAMETER_LINE.match(line)
                parameter = match.group("name") if match else line[len("Parameter:"):].strip()
                where = match.group("where") if match else "unknown"
                current = None
            elif line.startswith("Type:"):
                current = {
                    "parameter": parameter,
                    "where": where,
                    "technique": line[len("Type:"):].strip(),
                    "title": "",
                    "payload": "",
                }
                points.append(current)
            elif current is not None and line.startswith("Title:"):
                current["title"] = line[len("Title:"):].strip()
            elif current is not None and line.startswith("Payload:"):
                current["payload"] = line[len("Payload:"):].strip()
    return points


def _find_dbms(raw_output):
    match = _DBMS_LINE.search(raw_output) or _DBMS_SENTENCE.search(raw_output)
    return match.group("dbms").strip() if match else "unknown"


def _rate_technique(technique):
    lowered = technique.lower()
    for name, rating in TECHNIQUE_RATING.items():
        if name.lower() in lowered:
            return rating
    logger.warning("unrecognised sqlmap technique '%s'; rating it suspected/high", technique)
    return ("suspected", "high")


def parse_sqlmap_output(raw_output, target, param):
    """Turn sqlmap output into one finding dict, or None if no injection was confirmed."""
    raw_output = _TERMINAL_CODES.sub("", raw_output)
    points = _parse_injection_points(raw_output)
    if not points:
        return None

    confidence = "suspected"
    severities = []
    details = []
    for point in points:
        point_confidence, point_severity = _rate_technique(point["technique"])
        if point_confidence == "confirmed":
            confidence = "confirmed"
        severities.append(point_severity)
        details.append(f"{point['technique']} (payload: {_shorten(point['payload'])})")

    severity = max(severities, key=SEVERITY_ORDER.index)
    where = points[0]["where"]
    dbms = _find_dbms(raw_output)

    return {
        "module": MODULE_NAME,
        "target": target,
        "finding": f"SQL injection in '{param}' parameter",
        "severity": severity,
        "evidence": (
            f"Parameter sent via {where}. Back-end DBMS: {dbms}. "
            f"Techniques found: {'; '.join(details)}."
        ),
        "confidence": confidence,
        "timestamp": _timestamp(),
    }


def run(recon_output):
    """Test every parameter recon found and return the list of findings."""
    if not os.getenv("AUTHORIZED_TARGET"):
        raise RuntimeError("AUTHORIZED_TARGET is not set in .env. Refusing to run sqlmap.")

    if isinstance(recon_output, dict):
        endpoints = recon_output.get("params", [])
    else:
        endpoints = recon_output

    findings = []
    tested = set()
    for endpoint in endpoints:
        url = endpoint["url"]
        method = endpoint.get("method", "GET").upper()
        if not _in_scope(url):
            logger.warning("skipping %s: not the AUTHORIZED_TARGET", url)
            continue

        for param in endpoint.get("params", []):
            key = (url, method, param)
            if key in tested:
                continue
            tested.add(key)

            raw_output = run_sqlmap(endpoint, param)
            finding = parse_sqlmap_output(raw_output, target=url, param=param)
            if finding is not None:
                logger.info("SQLi found: '%s' on %s", param, url)
                findings.append(finding)

    return findings
