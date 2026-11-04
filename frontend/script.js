
async function loadStats() {
    try {
        // Get statistics from FastAPI
        const response = await fetch("/api/stats");

        if (!response.ok) {
            throw new Error("Failed to load statistics");
        }

        // Convert JSON to a JavaScript object
        const data = await response.json();

        // Find our statistics container
        const statsDiv = document.getElementById("stats");

        // Create a separate card for each statistic
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


async function loadFindings(module = "") {

    // Find the findings container in HTML
    const findingsDiv = document.getElementById("findings");

    try {
        // Start with the findings API endpoint
        let url = "/api/findings";

        // If a module is selected, filter the findings
        if (module !== "") {
            url += "?module=" + encodeURIComponent(module);
        }

        // Send a GET request to FastAPI
        const response = await fetch(url);

        // Check if the request was successful
        if (!response.ok) {
            throw new Error("Failed to load findings");
        }

        // Convert JSON response into JavaScript data
        const findings = await response.json();

        // Remove the previous findings from the page
        findingsDiv.replaceChildren();

        // Check if there are no vulnerabilities
        if (findings.length === 0) {
            findingsDiv.textContent = "No vulnerabilities found.";
            return;
        }

        // Loop through every vulnerability
        findings.forEach(function(finding) {

            // Create a new vulnerability card
            const card = document.createElement("div");
            card.className = "finding-card";

            // Create the card header
            const header = document.createElement("div");
            header.className = "finding-header";

            // Create the vulnerability name
            const name = document.createElement("h3");
            name.textContent = finding.finding || "Unknown vulnerability";

            // Create the severity badge
            const severity = document.createElement("span");

            const level = String(
                finding.severity || "unknown"
            ).toLowerCase();

            severity.className = "severity-badge " + level;
            severity.textContent = level.toUpperCase();

            // Add the name and severity to the header
            header.append(name, severity);

            // Create the target information
            const target = document.createElement("p");
            target.textContent =
                "Target: " + (finding.target || "N/A");

            // Create the module information
            const moduleText = document.createElement("p");
            moduleText.textContent =
                "Module: " + (finding.module || "N/A");

            // Create the evidence information
            const evidence = document.createElement("p");
            evidence.textContent =
                "Evidence: " + (finding.evidence || "N/A");

            // Create the confidence information
            const confidence = document.createElement("p");
            confidence.textContent =
                "Confidence: " + (finding.confidence ?? "N/A");

            // Add everything inside the card
            card.append(
                header,
                target,
                moduleText,
                evidence,
                confidence
            );

            // Add the card to the webpage
            findingsDiv.appendChild(card);
        });

    } catch (error) {
        findingsDiv.textContent = "Unable to load findings.";
        console.error(error);
    }
}


// Load statistics when the page opens
loadStats();

// Load findings when the page opens
loadFindings();

// Listen for changes in the module dropdown
document.getElementById("module-filter").addEventListener(
    "change",
    function(event) {

        // Get the selected module and reload findings
        loadFindings(event.target.value);
    }
);


// Find the Recon form in our HTML
const reconForm = document.getElementById("recon-form");

// Listen for the user submitting the form
reconForm.addEventListener("submit", async function(event) {

    // Prevent the browser from refreshing the page
    event.preventDefault();

    // Read the URL entered by the user
    const targetUrl = document.getElementById("target-url").value;

    // Find the results container
    const resultsDiv = document.getElementById("recon-results");

    // Display a loading message
    resultsDiv.textContent = "Scanning target...";
    try {
        // Send a POST request to FastAPI
        const response = await fetch("/api/scans/recon", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                target_url: targetUrl
            })
        });

        // Read the JSON response
        const data = await response.json();

        // Check for API errors
        if (!response.ok) {
            throw new Error(data.detail || "Recon request failed");
        }

        // Display the mock Recon response safely as text

// Clear previous results
resultsDiv.replaceChildren();

// Helper function to create a result section
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
        items.forEach(function(item) {
            const line = document.createElement("p");
            line.textContent = String(item);
            section.appendChild(line);
        });
    }

    resultsDiv.appendChild(section);
}

// Show technologies, endpoints, and parameters
const technologies = Object.entries(data.tech_stack || {})
    .map(([key, value]) => `${key}: ${value}`);

createSection("Detected Technologies", technologies);

createSection("Discovered Endpoints", data.endpoints || []);

createSection("Discovered Parameters", data.params || []);

    } catch (error) {
        resultsDiv.textContent = "Error: " + error.message;
    }
});


// ---------------------------------------
// XSS SCAN FORM
// ---------------------------------------

const xssForm = document.getElementById("xss-form");

if (xssForm) {
    xssForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const targetInput = document.getElementById("xss-target-url");
        const resultsDiv = document.getElementById("xss-results");
        const scanButton = document.getElementById("xss-scan-button");

        if (!targetInput || !resultsDiv || !scanButton) {
            console.error("XSS form is missing required HTML elements.");
            return;
        }

        const targetUrl = targetInput.value.trim();

        resultsDiv.textContent = "XSS scan running...";
        scanButton.disabled = true;

        try {
            const response = await fetch("/api/scans/xss", {
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
                throw new Error(data.detail || "XSS scan failed");
            }

            resultsDiv.replaceChildren();

            const summary = document.createElement("p");
            const scanStatus = String(data.status || "unknown").toUpperCase();
            summary.textContent =
                `Scan status: ${scanStatus}. Findings: ${Number(data.findings_count) || 0}`;
            resultsDiv.appendChild(summary);

            const diagnostics = data.diagnostics || {};
            const coverage = document.createElement("section");
            coverage.className = "xss-diagnostics";

            const coverageHeading = document.createElement("h3");
            coverageHeading.textContent = "Scan coverage";
            coverage.appendChild(coverageHeading);

            const coverageSummary = document.createElement("p");
            coverageSummary.textContent =
                `Forms discovered: ${Number(diagnostics.form_count) || 0}; ` +
                `tested: ${Number(diagnostics.forms_tested) || 0}; ` +
                `skipped: ${Number(diagnostics.forms_skipped) || 0}; ` +
                `failed: ${Number(diagnostics.forms_failed) || 0}; ` +
                `incomplete: ${Number(diagnostics.forms_incomplete) || 0}; ` +
                `HTTP requests: ${Number(diagnostics.requests_attempted) || 0}.`;
            coverage.appendChild(coverageSummary);

            const endpointReports = Array.isArray(diagnostics.endpoints)
                ? diagnostics.endpoints
                : [];
            endpointReports.forEach(function (endpoint) {
                const item = document.createElement("details");
                const heading = document.createElement("summary");
                const label = endpoint.is_form
                    ? `Form ${endpoint.form_index}`
                    : "Endpoint";
                heading.textContent =
                    `${label}: ${endpoint.method || "GET"} ${endpoint.url || "unknown"} — ` +
                    `${String(endpoint.status || "unknown").toUpperCase()}`;
                item.appendChild(heading);

                if (endpoint.reason) {
                    const reason = document.createElement("p");
                    reason.textContent = endpoint.reason;
                    item.appendChild(reason);
                }

                if (endpoint.page_url) {
                    const source = document.createElement("p");
                    source.textContent = "Form source: " + endpoint.page_url;
                    item.appendChild(source);
                }

                const parameters = Array.isArray(endpoint.parameters)
                    ? endpoint.parameters
                    : [];
                parameters.forEach(function (parameter) {
                    const detail = document.createElement("p");
                    detail.textContent =
                        `Parameter ${parameter.name}: ${parameter.status}` +
                        (parameter.reason ? ` — ${parameter.reason}` : "") +
                        `; payload attempts: ${Number(parameter.payload_attempts) || 0}; ` +
                        `responses: ${Number(parameter.responses) || 0}.`;
                    item.appendChild(detail);
                });

                coverage.appendChild(item);
            });
            resultsDiv.appendChild(coverage);

            const issues = Array.isArray(diagnostics.issues)
                ? diagnostics.issues
                : [];
            if (issues.length > 0) {
                const issueSection = document.createElement("section");
                const issueHeading = document.createElement("h3");
                issueHeading.textContent = "Scan errors and diagnostics";
                issueSection.appendChild(issueHeading);

                issues.forEach(function (issue) {
                    const detail = document.createElement("p");
                    const location = issue.url
                        ? ` (${issue.url}${issue.parameter ? `, ${issue.parameter}` : ""})`
                        : "";
                    detail.textContent =
                        `[${String(issue.kind || "issue").toUpperCase()}] ` +
                        `${issue.message || "Unknown scan issue"}${location}`;
                    issueSection.appendChild(detail);
                });

                resultsDiv.appendChild(issueSection);
            }

            const findings = Array.isArray(data.findings)
                ? data.findings
                : [];

            if (findings.length === 0) {
                const empty = document.createElement("p");
                empty.textContent = data.status === "completed"
                    ? "Scan completed; no XSS findings were reported."
                    : "No XSS findings were reported. This scan was incomplete; review coverage and diagnostics.";
                resultsDiv.appendChild(empty);
            }

            findings.forEach(function (finding) {
                const card = document.createElement("article");
                card.className = "finding-card";

                const title = document.createElement("h3");
                title.textContent = finding.finding || "XSS finding";

                const severity = document.createElement("p");
                severity.textContent =
                    "Severity: " + (finding.severity || "Unknown");

                const target = document.createElement("p");
                target.textContent =
                    "Target: " + (finding.target || targetUrl);

                const evidence = document.createElement("p");
                evidence.textContent =
                    "Evidence: " + (finding.evidence || "N/A");

                const confidence = document.createElement("p");
                confidence.textContent =
                    "Confidence: " + (finding.confidence ?? "N/A");

                card.append(
                    title,
                    severity,
                    target,
                    evidence,
                    confidence
                );

                resultsDiv.appendChild(card);
            });

            const filter = document.getElementById("module-filter");

            await Promise.all([
                loadStats(),
                loadFindings(filter ? filter.value : ""),
                loadScanHistory()
            ]);
        } catch (error) {
            resultsDiv.textContent = "Error: " + error.message;
            console.error("XSS scan error:", error);
        } finally {
            scanButton.disabled = false;
        }
    });
}


async function loadScanHistory() {

    const historyBody = document.getElementById("history-body");

    try {
        // Request saved scans from FastAPI
        const response = await fetch("/api/scans/history");

        if (!response.ok) {
            throw new Error("Failed to load scan history");
        }

        // Convert JSON into an array
        const scans = await response.json();

        // Clear old rows
        historyBody.replaceChildren();

        // Handle an empty database
        if (scans.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 5;
            cell.textContent = "No scans recorded yet.";

            row.appendChild(cell);
            historyBody.appendChild(row);
            return;
        }

        // Create one table row per scan
        scans.forEach(function(scan) {

            const row = document.createElement("tr");

            const values = [
                "#" + scan.id,
                scan.target_url,
                scan.scan_type,
                scan.status,
                scan.created_at
            ];

            values.forEach(function(value, index) {

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

// Load saved scans when the page opens
loadScanHistory();
