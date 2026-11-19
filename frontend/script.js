let currentScanId = null;

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


const fullScanButton = document.getElementById("full-scan-btn");

if (fullScanButton) {
    fullScanButton.addEventListener("click", async function () {
        const targetUrl = document.getElementById("target-url").value.trim();
        const resultsDiv = document.getElementById("recon-results");

        if (!targetUrl) {
            resultsDiv.textContent = "Please enter a target URL.";
            return;
        }

        fullScanButton.disabled = true;
        resultsDiv.textContent = "Full scan running. Please wait...";

        try {
            const response = await fetch("/api/scans/full", {
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
                    typeof data.detail === "string"
                        ? data.detail
                        : JSON.stringify(data.detail || "Full scan failed")
                );
            }

            currentScanId = data.scan_id;

            resultsDiv.textContent = "Full scan completed. Refreshing results...";

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
            resultsDiv.textContent = "Error: " + error.message;
            console.error(error);
        } finally {
            fullScanButton.disabled = false;
        }
    });
}


/* PRINT REPORT FOR CURRENT SCAN */

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

console.log("BOLA initialization:", {
    form: !!bolaForm,
    results: !!bolaResults,
    button: !!bolaScanBtn
});

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
  if (value === undefined || value === null || value === "") {
    return;
  }

  const row = bolaElement("p");
  const heading = bolaElement("strong", `${label}: `);

  row.appendChild(heading);
  row.appendChild(
    document.createTextNode(String(value))
  );

  parent.appendChild(row);
}

function bolaClearResults() {
  bolaResults.replaceChildren();
}

function bolaShowMessage(message) {
  bolaClearResults();
  bolaResults.appendChild(bolaElement("p", message));
}



function bolaRenderFindings(data) {
  bolaClearResults();

  const scanId = data.scan_id ?? "Unknown";
  const findings = Array.isArray(data.findings)
    ? data.findings
    : [];

  bolaResults.appendChild(
    bolaElement("h3", `BOLA Scan #${scanId}`)
  );

  bolaResults.appendChild(
    bolaElement(
      "p",
      `Total findings: ${findings.length}`
    )
  );

  if (findings.length === 0) {
    bolaResults.appendChild(
      bolaElement("p", "No BOLA vulnerabilities found.")
    );
    return;
  }

  findings.forEach((finding) => {
    const card = bolaElement("div", null, "finding-card");

    card.appendChild(
      bolaElement(
        "h3",
        finding.finding || "Unnamed finding"
      )
    );

    const severity = bolaElement(
      "span",
      String(finding.severity || "unknown").toUpperCase(),
      "severity-badge"
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

      let evidenceText;

      if (typeof finding.evidence === "object") {
        evidenceText = JSON.stringify(
          finding.evidence,
          null,
          2
        );
      } else {
        evidenceText = String(finding.evidence);
      }

      const evidence = bolaElement(
        "pre",
        evidenceText.slice(0, 600)
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

if (bolaForm && bolaResults && bolaScanBtn) {
  bolaForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!bolaForm.reportValidity()) {
      return;
    }

    const extraPaths = document
      .getElementById("bola-extra-paths")
      .value
      .split(/\r?\n/)
      .map((path) => path.trim())
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

    bolaScanBtn.disabled = true;
    bolaScanBtn.textContent = "SCANNING...";

    bolaShowMessage(
      "BOLA scan running... this can take several minutes"
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

      bolaRenderFindings(data);

      // Keep existing dashboard report button in sync.
      if (typeof currentScanId !== "undefined") {
        currentScanId = data.scan_id;
      }

      // Refresh the rest of the dashboard.
      const refreshes = [];

      if (typeof loadStats === "function") {
        refreshes.push(loadStats());
      }

      if (typeof loadFindings === "function") {
        refreshes.push(loadFindings());
      }

      if (typeof loadScanHistory === "function") {
        refreshes.push(loadScanHistory());
      }

      const refreshResults = await Promise.allSettled(
        refreshes
      );

      if (refreshResults.some(
        (result) => result.status === "rejected"
      )) {
        console.warn(
          "BOLA scan completed, but some dashboard panels did not refresh."
        );
      }

    } catch (error) {
      bolaShowMessage(`Error: ${error.message}`);
      console.error("BOLA scan error:", error);

    } finally {
      bolaScanBtn.disabled = false;
      bolaScanBtn.textContent = "RUN BOLA SCAN";
    }
  });
}

