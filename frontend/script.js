
let currentScanId = null;
console.log("NEW JAVASCRIPT VERSION LOADED");
function scanUrl(path, module = "") {
    const params = new URLSearchParams();

    if (currentScanId != null) {
        params.set("scan_id", currentScanId);
    }

    if (module) {
        params.set("module", module);
    }

    return params.size ? `${path}?${params}` : path;
}

function displayValue(value) {
    if (value == null || value === "") {
        return "N/A";
    }

    return typeof value === "object"
        ? JSON.stringify(value, null, 2)
        : String(value);
}


/* ==========================================
   DASHBOARD STATISTICS
========================================== */

async function loadStats() {
    try {
        const response = await fetch(scanUrl("/api/stats"), {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("Failed to load statistics");
        }

        const data = await response.json();
        const statsDiv = document.getElementById("stats");

        statsDiv.innerHTML = `
            <div class="stat-card total">
                <span class="stat-label">TOTAL FINDINGS</span>
                <span class="stat-number">${data.total}</span>
                <div class="stat-bar"></div>
            </div>

            <div class="stat-card critical">
                <span class="stat-label">CRITICAL</span>
                <span class="stat-number">${data.critical}</span>
                <div class="stat-bar"></div>
            </div>

            <div class="stat-card high">
                <span class="stat-label">HIGH RISK</span>
                <span class="stat-number">${data.high}</span>
                <div class="stat-bar"></div>
            </div>

            <div class="stat-card medium">
                <span class="stat-label">MEDIUM</span>
                <span class="stat-number">${data.medium}</span>
                <div class="stat-bar"></div>
            </div>

            <div class="stat-card low">
                <span class="stat-label">LOW RISK</span>
                <span class="stat-number">${data.low}</span>
                <div class="stat-bar"></div>
            </div>
        `;

    } catch (error) {
        document.getElementById("stats").textContent =
            "Unable to load statistics.";

        console.error(error);
    }
}


/* ==========================================
   VULNERABILITY FINDINGS
========================================== */

async function loadFindings(module = "") {

    const findingsDiv = document.getElementById("findings");

    try {
        const url = scanUrl("/api/findings", module);

        const response = await fetch(url, {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("Failed to load findings");
        }

        const findings = await response.json();

        findingsDiv.replaceChildren();

        if (findings.length === 0) {
            findingsDiv.textContent = "No vulnerabilities found.";
            return;
        }

        findings.forEach(function (finding) {

            const card = document.createElement("div");
            card.className = "finding-card";

            const header = document.createElement("div");
            header.className = "finding-header";

            const name = document.createElement("h3");

            name.textContent =
                finding.finding || "Unknown vulnerability";

            const severity = document.createElement("span");

            const level = String(
                finding.severity || "unknown"
            ).toLowerCase();

            severity.className = "severity-badge " + level;
            severity.textContent = level.toUpperCase();

            header.append(name, severity);

            const target = document.createElement("p");
            target.textContent =
                "Target: " + (finding.target || "N/A");

            const moduleText = document.createElement("p");
            moduleText.textContent =
                "Module: " + (finding.module || "N/A");

            const evidence = document.createElement("p");

            evidence.textContent =
                "Evidence: " + displayValue(finding.evidence);

            evidence.style.whiteSpace = "pre-wrap";
            evidence.style.overflowWrap = "anywhere";

            const confidence = document.createElement("p");

            confidence.textContent =
                "Confidence: " + (finding.confidence ?? "N/A");

            card.append(
                header,
                target,
                moduleText,
                evidence,
                confidence
            );

            findingsDiv.appendChild(card);
        });

    } catch (error) {
        findingsDiv.textContent =
            "Unable to load findings.";

        console.error(error);
    }
}


/* ==========================================
   MODULE FILTER
========================================== */

document.getElementById("module-filter").addEventListener(
    "change",
    function (event) {
        loadFindings(event.target.value);
    }
);


/* ==========================================
   RECONNAISSANCE SCAN
========================================== */

const reconForm = document.getElementById("recon-form");

reconForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    const targetUrl = document
        .getElementById("target-url")
        .value.trim();

    const resultsDiv = document.getElementById("recon-results");

    resultsDiv.textContent = "Scanning target...";

    try {
        const response = await fetch("/api/scans/recon", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                target_url: targetUrl
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                displayValue(data.detail || "Recon request failed")
            );
        }

        resultsDiv.replaceChildren();

        function createSection(title, items) {

            const section = document.createElement("div");
            section.className = "recon-result-card";

            const heading = document.createElement("h3");
            heading.textContent = title;

            section.appendChild(heading);

            if (items.length === 0) {

                const empty = document.createElement("p");
                empty.textContent = "None discovered";

                section.appendChild(empty);

            } else {

                items.forEach(function (item) {

                    const line = document.createElement("p");
                    line.textContent = displayValue(item);

                    section.appendChild(line);
                });
            }

            resultsDiv.appendChild(section);
        }

        const technologies = Object.entries(
            data.tech_stack || {}
        ).map(([key, value]) => `${key}: ${value}`);

        createSection(
            "Detected Technologies",
            technologies
        );

        createSection(
            "Discovered Endpoints",
            data.endpoints || []
        );

        const paramLines = (data.params || []).map(function(p) {
            const method = p.method || "GET";
            const url = p.url || "unknown URL";
            const fields = Array.isArray(p.params) ? p.params.join(", ") : "none";
            return `${method} ${url} — fields: ${fields}`;
        });

        createSection("Discovered Parameters", paramLines);

        await loadScanHistory();

    } catch (error) {

        resultsDiv.textContent =
            "Error: " + error.message;

        console.error(error);
    }
});


/* ==========================================
   SCAN HISTORY
========================================== */

async function loadScanHistory() {

    const historyBody = document.getElementById("history-body");

    try {
        const response = await fetch("/api/scans/history", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("Failed to load scan history");
        }

        const scans = await response.json();

        historyBody.replaceChildren();

        if (scans.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 5;
            cell.textContent = "No scans recorded yet.";

            row.appendChild(cell);
            historyBody.appendChild(row);

            return;
        }

        scans.forEach(function (scan) {

            const row = document.createElement("tr");

            const values = [
                "#" + scan.id,
                scan.target_url,
                scan.scan_type,
                scan.status,
                scan.created_at
            ];

            values.forEach(function (value, index) {

                const cell = document.createElement("td");

                cell.textContent = value ?? "N/A";

                if (index === 0) {
                    cell.className = "history-id";
                }

                if (index === 3) {
                    cell.className = "history-status";
                }

                row.appendChild(cell);
            });

            historyBody.appendChild(row);
        });

    } catch (error) {

        historyBody.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 5;
        cell.textContent = "Unable to load scan history.";

        row.appendChild(cell);
        historyBody.appendChild(row);

        console.error(error);
    }
}


/* ==========================================
   FULL VULNERABILITY SCAN
========================================== */

const fullScanButton = document.getElementById("full-scan-btn");

if (fullScanButton) {

    fullScanButton.addEventListener("click", async function () {

        const targetUrl = document
            .getElementById("target-url")
            .value.trim();

        const resultsDiv = document.getElementById("recon-results");

        if (!targetUrl) {
            resultsDiv.textContent = "Please enter a target URL.";
            return;
        }

        const originalButton = fullScanButton.innerHTML;

        fullScanButton.disabled = true;

        resultsDiv.textContent =
            "Full scan running. Please wait...";

        try {

            const response = await fetch("/api/scans/full", {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    target_url: targetUrl
                }),

                cache: "no-store"
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    typeof data.detail === "string"
                        ? data.detail
                        : JSON.stringify(
                            data.detail || "Full scan failed"
                        )
                );
            }

            currentScanId = data.scan_id;

            resultsDiv.textContent =
                "Full scan completed. Refreshing results...";

            await Promise.all([
                loadStats(),

                loadFindings(
                    document.getElementById("module-filter")?.value || ""
                ),

                loadScanHistory()
            ]);

            resultsDiv.textContent =
                "Scan request completed. Check the findings and scan history.";

        } catch (error) {

            resultsDiv.textContent =
                "Error: " + error.message;

            console.error(error);

        } finally {

            fullScanButton.disabled = false;
            fullScanButton.innerHTML = originalButton;
        }
    });
}


/* ==========================================
   PRINT REPORT FOR CURRENT SCAN
========================================== */

document.getElementById("print-dashboard")
    ?.addEventListener("click", function () {

        if (currentScanId == null) {
            alert("Please complete a full scan first.");
            return;
        }

        window.open(
            `/api/scans/${currentScanId}/report/html`,
            "_blank"
        );
    });


/* ==========================================
   BOLA ASSESSMENT PANEL
========================================== */

const bolaForm = document.getElementById("bola-form");
const bolaResults = document.getElementById("bola-results");
const bolaScanBtn = document.getElementById("bola-scan-btn");


function bolaElement(tag, text, className) {

    const element = document.createElement(tag);

    if (text !== undefined && text !== null) {
        element.textContent = String(text);
    }

    if (className) {
        element.className = className;
    }

    return element;
}


function bolaAddField(parent, label, value) {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {
        return;
    }

    const row = bolaElement("p");
    const heading = bolaElement("strong", `${label}: `);

    row.appendChild(heading);

    row.appendChild(
        document.createTextNode(displayValue(value))
    );

    parent.appendChild(row);
}


function bolaClearResults() {
    bolaResults.replaceChildren();
}


function bolaShowMessage(message) {

    bolaClearResults();

    bolaResults.appendChild(
        bolaElement("p", message)
    );
}


/* ==========================================
   DISPLAY BOLA FINDINGS
========================================== */

function bolaRenderFindings(data) {

    bolaClearResults();

    const scanId = data.scan_id ?? "Unknown";

    const findings = Array.isArray(data.findings)
        ? data.findings.filter(f =>
            ["bola", "bola_agent"].includes(
                String(f.module || "").toLowerCase()
            )
        )
        : [];

    bolaResults.appendChild(
        bolaElement("h3", `BOLA Scan #${scanId}`)
    );

    bolaResults.appendChild(
        bolaElement(
            "p",
            `BOLA findings: ${findings.length}`
        )
    );

    if (findings.length === 0) {

        bolaResults.appendChild(
            bolaElement("p", "No BOLA vulnerabilities found.")
        );

        return;
    }

    findings.forEach(function (finding) {

        const card = bolaElement(
            "div",
            null,
            "finding-card"
        );

        card.appendChild(
            bolaElement(
                "h3",
                finding.finding || "Unnamed finding"
            )
        );

        const level = String(
            finding.severity || "unknown"
        ).toLowerCase();

        const severity = bolaElement(
            "span",
            level.toUpperCase(),
            "severity-badge " + level
        );

        card.appendChild(severity);

        bolaAddField(card, "Target", finding.target);
        bolaAddField(card, "Module", finding.module);
        bolaAddField(card, "Confidence", finding.confidence);

        if (finding.detected_by) {

            bolaAddField(
                card,
                "Detected by",
                finding.detected_by
            );
        }

        if (finding.needs_review === true) {

            const warning = bolaElement(
                "p",
                "NEEDS HUMAN REVIEW",
                "bola-review-warning"
            );

            warning.style.fontWeight = "bold";
            warning.style.color = "#ffb347";

            card.appendChild(warning);
        }

        if (
            finding.evidence !== undefined &&
            finding.evidence !== null
        ) {

            card.appendChild(
                bolaElement("h4", "Evidence")
            );

            const evidence = bolaElement(
                "pre",
                displayValue(finding.evidence)
            );

            evidence.style.whiteSpace = "pre-wrap";
            evidence.style.overflowWrap = "anywhere";

            card.appendChild(evidence);
        }

        if (finding.plain_english) {

            bolaAddField(
                card,
                "Explanation",
                finding.plain_english
            );
        }

        if (finding.fix_suggestion) {

            bolaAddField(
                card,
                "Suggested Fix",
                finding.fix_suggestion
            );
        }

        if (finding.ai_reasoning) {

            bolaAddField(
                card,
                "AI Reasoning",
                finding.ai_reasoning
            );
        }

        bolaResults.appendChild(card);
    });
}


/* ==========================================
   BOLA SCAN REQUEST
========================================== */

if (bolaForm && bolaResults && bolaScanBtn) {

    bolaForm.addEventListener("submit", async function (event) {

        event.preventDefault();

        if (!bolaForm.reportValidity()) {
            return;
        }

        const extraPaths = document
            .getElementById("bola-extra-paths")
            .value
            .split(/\r?\n/)
            .map(path => path.trim())
            .filter(Boolean);

        const payload = {

            target_url: document
                .getElementById("bola-target-url")
                .value.trim(),

            bola_user_a_token: document
                .getElementById("bola-user-a-token")
                .value.trim(),

            bola_user_a_resource_id: document
                .getElementById("bola-user-a-resource")
                .value.trim(),

            bola_user_b_token: document
                .getElementById("bola-user-b-token")
                .value.trim(),

            bola_user_b_resource_id: document
                .getElementById("bola-user-b-resource")
                .value.trim(),

            bola_auth_header: document
                .getElementById("bola-auth-header")
                .value.trim() || "Authorization",

            use_ai_agent_for_bola: document
                .getElementById("bola-use-ai")
                .checked,

            bola_extra_paths: extraPaths.length
                ? extraPaths
                : null
        };

        // Preserve the original button and SVG icon.

        const originalBolaButton = bolaScanBtn.innerHTML;

        bolaScanBtn.disabled = true;
        bolaScanBtn.textContent = "SCANNING...";

        bolaShowMessage(
            "BOLA scan running... this can take several minutes."
        );

        try {

            const response = await fetch("/api/scans/full", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(payload),

                cache: "no-store"
            });

            const data = await response.json();

            if (!response.ok) {

                const detail = data.detail;

                let message = "BOLA scan failed";

                if (typeof detail === "string") {

                    message = detail;

                } else if (detail !== undefined) {

                    message = JSON.stringify(detail);
                }

                throw new Error(message);
            }

            currentScanId = data.scan_id;
                console.log("BOLA FINDINGS:", data.findings);

            console.table(data.findings.map(f => ({
                module: f.module,
                detected_by: f.detected_by,
                finding: f.finding
            })));

            bolaRenderFindings(data);

            await Promise.all([
                loadStats(),

                loadFindings(
                    document.getElementById("module-filter")?.value || ""
                ),

                loadScanHistory()
            ]);

        } catch (error) {

            bolaShowMessage(
                `Error: ${error.message}`
            );

            console.error("BOLA scan error:", error);

        } finally {

            // Restore the original SVG icon and button text.

            bolaScanBtn.disabled = false;
            bolaScanBtn.innerHTML = originalBolaButton;
        }
    });
}


/* ==========================================
   INITIALIZE DASHBOARD
========================================== */

async function initializeDashboard() {

    try {

        const response = await fetch("/api/scans/history", {
            cache: "no-store"
        });

        if (response.ok) {

            const scans = await response.json();

            const latest = scans.find(scan =>

                ["full", "xss"].includes(scan.scan_type) &&

                ["completed", "incomplete"].includes(scan.status)
            );

            if (currentScanId == null && latest) {
                currentScanId = latest.id;
            }
        }

    } catch (error) {

        console.error(
            "Unable to select latest scan",
            error
        );
    }

    await Promise.all([
        loadStats(),

        loadFindings(
            document.getElementById("module-filter")?.value || ""
        ),

        loadScanHistory()
    ]);
}


initializeDashboard();
