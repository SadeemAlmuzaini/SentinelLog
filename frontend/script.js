/* =====================================================
   SentinelLog
   Intelligent Firewall Log Analyzer
   Version 4.1 — Flask backend client (redesigned UI)
===================================================== */

const fileInput = document.getElementById("logFile");
const selectedFile = document.getElementById("selectedFile");
const uploadStatus = document.getElementById("uploadStatus");
const analyzeButton = document.getElementById("analyzeButton");

const blockedCount = document.getElementById("blockedCount");
const allowedCount = document.getElementById("allowedCount");
const countryCount = document.getElementById("countryCount");
const threatCount = document.getElementById("threatCount");
const threatLevel = document.getElementById("threatLevel");
const aiReport = document.getElementById("aiReport");
const protocolCount = document.getElementById("protocolCount");
const trafficCount = document.getElementById("trafficCount");
const topPort = document.getElementById("topPort");
const downloadPDF = document.getElementById("downloadPDF");
const downloadJSON = document.getElementById("downloadJSON");
const downloadFindingsCSV = document.getElementById("downloadFindingsCSV");
const findingsList = document.getElementById("findingsList");

let trafficChart = null;
let countryChart = null;
let protocolChart = null;
let portsChart = null;
let trafficUsageChart = null;

let selectedCSVFile = null;
let hasAnalysis = false;

Chart.defaults.color = "#9aa4bd";
Chart.defaults.font.family = "Inter";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.boxWidth = 8;
Chart.defaults.plugins.legend.labels.padding = 14;
Chart.defaults.plugins.legend.labels.font = { size: 11.5 };
Chart.defaults.plugins.tooltip.backgroundColor = "#10141f";
Chart.defaults.plugins.tooltip.titleColor = "#e7eaf3";
Chart.defaults.plugins.tooltip.bodyColor = "#9aa4bd";
Chart.defaults.plugins.tooltip.borderColor = "rgba(255,255,255,.08)";
Chart.defaults.plugins.tooltip.borderWidth = 1;
Chart.defaults.plugins.tooltip.cornerRadius = 8;
Chart.defaults.plugins.tooltip.padding = 10;
Chart.defaults.plugins.tooltip.displayColors = true;
Chart.defaults.animation.duration = 500;
Chart.defaults.animation.easing = "easeOutQuart";

/* Coordinated with the dark UI's accent palette (see style.css :root) */
const COLORS = {
    blue: "#4f7cff", cyan: "#14b8a6", purple: "#8b5cf6", green: "#22c55e",
    orange: "#f59e0b", red: "#ef4444", darkBlue: "#1e3a8a", gray: "#68718c"
};
const COUNTRY_PALETTE = [
    COLORS.blue, COLORS.purple, COLORS.cyan, COLORS.green,
    COLORS.orange, COLORS.red, "#94a3b8", "#f472b6", "#60a5fa", "#a78bfa"
];

function setStatus(message, type) {
    if (!uploadStatus) return;
    uploadStatus.textContent = message;
    uploadStatus.className = "upload-status " + (type || "info");
}

function sortEntriesDesc(obj) {
    return Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
}

/* ==========================================
   File Selection
========================================== */

fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
        selectedCSVFile = fileInput.files[0];
        const sizeKB = (selectedCSVFile.size / 1024).toFixed(1);
        selectedFile.textContent = selectedCSVFile.name + " (" + sizeKB + " KB)";
        setStatus("Ready to analyze. Click \"Analyze Logs\".", "info");
    } else {
        selectedCSVFile = null;
        selectedFile.textContent = "No file selected";
        setStatus("", "info");
    }
});

/* ==========================================
   Analyze Button -> POST /api/analyze
========================================== */

analyzeButton.addEventListener("click", async () => {

    if (!selectedCSVFile) {
        setStatus("Please select a CSV log file first.", "error");
        return;
    }

    setStatus("Uploading and analyzing " + selectedCSVFile.name + " ...", "info");
    analyzeButton.disabled = true;

    const formData = new FormData();
    formData.append("file", selectedCSVFile);

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            body: formData
        });

        const body = await response.json();

        if (!response.ok) {
            throw new Error(body.error || ("Request failed with status " + response.status));
        }

        renderAll(body);
        hasAnalysis = true;

        const v = body.validation;
        let msg = "Analysis complete — " + v.valid_rows + " of " + v.total_rows + " rows accepted";
        if (v.rejected_rows > 0) {
            msg += " (" + v.rejected_rows + " rejected — see console for reasons).";
            console.warn("SentinelLog: rejected rows", v.rejected_reasons);
        } else {
            msg += ".";
        }
        if (v.warnings && v.warnings.length > 0) {
            console.warn("SentinelLog: accepted-with-issue rows", v.warnings);
        }
        setStatus(msg, v.rejected_rows > 0 ? "info" : "success");

    } catch (error) {
        console.error(error);
        setStatus("Analysis failed: " + error.message, "error");
    } finally {
        analyzeButton.disabled = false;
    }

});

/* ==========================================
   Render Everything From Backend Response
========================================== */

function renderAll(result) {
    updateDashboard(result);
    createTrafficChart(result.stats);
    createCountryChart(result.stats);
    createProtocolChart(result.stats);
    createPortsChart(result.stats);
    createTrafficUsageChart(result.stats);
    renderFindings(result.findings);
    aiReport.innerHTML = marked.parse(result.report);
}

function updateDashboard(result) {
    const stats = result.stats;
    const risk = result.risk;

    blockedCount.textContent = stats.blocked_connections;
    allowedCount.textContent = stats.allowed_connections;
    countryCount.textContent = stats.countries;
    threatCount.textContent = risk.score;
    threatLevel.textContent = risk.threat_level;
    protocolCount.textContent = stats.protocols;
    trafficCount.textContent = (stats.total_traffic_bytes / 1024 / 1024).toFixed(2) + " MB";

    const sortedPorts = sortEntriesDesc(stats.top_destination_ports);
    topPort.textContent = sortedPorts.length > 0 ? sortedPorts[0][0] : "-";

    updateThreatColor(risk.threat_level);
}

function updateThreatColor(level) {
    threatLevel.classList.remove("low", "medium", "high", "critical");
    threatCount.classList.remove("low", "medium", "high", "critical");
    const value = (level || "").toUpperCase();
    const cls = value === "LOW" ? "low" : value === "MEDIUM" ? "medium" : value === "HIGH" ? "high" : value === "CRITICAL" ? "critical" : null;
    if (cls) {
        threatLevel.classList.add(cls);
        threatCount.classList.add(cls);
    }
}

/* ==========================================
   Findings — compact investigation cards
   Evidence, Affected, MITRE and Recommended Action stay
   always visible; only secondary context ("Why it matters"
   / "Limitations") sits behind a native <details> toggle.
========================================== */

function renderFindings(findings) {
    findingsList.innerHTML = "";

    if (!findings || findings.length === 0) {
        findingsList.innerHTML = '<div class="findings-empty">No findings were triggered by the configured detection rules on this dataset.</div>';
        return;
    }

    findings.forEach(f => {
        const severity = (f.severity || "").toLowerCase();

        const refHtml = f.mitre && f.mitre.reference_url
            ? ` <a href="${escapeHtml(f.mitre.reference_url)}" target="_blank" rel="noopener noreferrer">Reference ↗</a>`
            : "";
        const mitreHtml = f.mitre
            ? `<div class="finding-mitre">
                   <i class="fa-solid fa-diagram-project"></i>
                   <span><strong>${escapeHtml(f.mitre.tactic)} — ${escapeHtml(f.mitre.technique_id)} (${escapeHtml(f.mitre.technique_name)})</strong><br>${escapeHtml(f.mitre.rationale)}${refHtml}</span>
               </div>`
            : "";

        const confidenceHtml = f.confidence
            ? `<span class="finding-confidence" title="How certain this interpretation is, given only a connection log">Confidence: ${escapeHtml(f.confidence)}</span>`
            : "";

        const nextStepsHtml = f.next_steps
            ? `<p><strong>Next step to verify:</strong> ${escapeHtml(f.next_steps)}</p>`
            : "";

        const card = document.createElement("div");
        card.className = `finding-card severity-${severity}`;
        card.innerHTML = `
            <div class="finding-header">
                <span class="finding-severity">${escapeHtml(f.severity)}</span>
                ${confidenceHtml}
                <span class="finding-rule">${escapeHtml(f.rule)}</span>
                <span class="finding-id">${escapeHtml(f.id)}</span>
            </div>
            <p class="finding-desc">${escapeHtml(f.description)}</p>
            <div class="finding-meta">
                <div class="finding-meta-row"><span class="label">Evidence</span><span class="value">${escapeHtml(f.evidence)}</span></div>
                <div class="finding-meta-row"><span class="label">Affected</span><span class="value">${escapeHtml(f.affected)} (${escapeHtml(f.record_count)} record(s))</span></div>
            </div>
            ${mitreHtml}
            <p class="finding-action"><strong>Recommended action:</strong> ${escapeHtml(f.recommended_action)}</p>
            <details class="finding-details">
                <summary>Why it matters &amp; limitations</summary>
                <div class="details-body">
                    <p><strong>Why it matters:</strong> ${escapeHtml(f.rationale)}</p>
                    ${nextStepsHtml}
                    <p><strong>Limitations:</strong> ${escapeHtml(f.limitations)}</p>
                </div>
            </details>
        `;
        findingsList.appendChild(card);
    });
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
}

/* ==========================================
   Charts
========================================== */

function createTrafficChart(stats) {
    const ctx = document.getElementById("trafficChart").getContext("2d");
    if (trafficChart) trafficChart.destroy();

    const allowedGradient = ctx.createLinearGradient(0, 0, 0, 240);
    allowedGradient.addColorStop(0, COLORS.cyan);
    allowedGradient.addColorStop(1, COLORS.blue);
    const blockedGradient = ctx.createLinearGradient(0, 0, 0, 240);
    blockedGradient.addColorStop(0, "#fb7185");
    blockedGradient.addColorStop(1, COLORS.red);

    trafficChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Allowed", "Blocked"],
            datasets: [{
                data: [stats.allowed_connections, stats.blocked_connections],
                backgroundColor: [allowedGradient, blockedGradient],
                borderRadius: 10, borderSkipped: false, maxBarThickness: 64
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: c => c.raw + " connections" } }
            },
            scales: {
                x: { grid: { display: false }, ticks: { color: "#9aa4bd" } },
                y: { beginAtZero: true, grid: { color: "rgba(255,255,255,.06)" }, ticks: { color: "#68718c" } }
            }
        }
    });
}

function createCountryChart(stats) {
    const ctx = document.getElementById("countryChart").getContext("2d");
    if (countryChart) countryChart.destroy();

    const sorted = sortEntriesDesc(stats.country_distribution);
    const labels = sorted.map(e => e[0]);
    const values = sorted.map(e => e[1]);
    const colors = labels.map((_, i) => COUNTRY_PALETTE[i % COUNTRY_PALETTE.length]);

    countryChart = new Chart(ctx, {
        type: "doughnut",
        data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 4 }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            cutout: "68%",
            plugins: { legend: { display: false } }
        }
    });

    const legend = document.getElementById("countryLegend");
    legend.innerHTML = "";
    const total = values.reduce((a, b) => a + b, 0) || 1;
    sorted.forEach(([country, value], i) => {
        const pct = ((value / total) * 100).toFixed(1);
        const item = document.createElement("div");
        item.className = "country-item";
        item.innerHTML = `
            <div class="country-left">
                <span class="country-dot" style="background:${colors[i]}"></span>
                <span class="country-name">${escapeHtml(country)}</span>
            </div>
            <span class="country-value">${value} (${pct}%)</span>`;
        legend.appendChild(item);
    });
}

function createProtocolChart(stats) {
    const ctx = document.getElementById("protocolChart").getContext("2d");
    if (protocolChart) protocolChart.destroy();

    const sorted = sortEntriesDesc(stats.protocol_distribution);
    const labels = sorted.map(e => e[0]);
    const values = sorted.map(e => e[1]);
    const palette = [COLORS.blue, COLORS.purple, COLORS.cyan, COLORS.green, COLORS.orange];

    protocolChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{ data: values, backgroundColor: labels.map((_, i) => palette[i % palette.length]), borderWidth: 0, hoverOffset: 4 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            cutout: "62%",
            plugins: { legend: { position: "bottom", labels: { color: "#9aa4bd" } } }
        }
    });
}

function createPortsChart(stats) {
    const ctx = document.getElementById("portsChart").getContext("2d");
    if (portsChart) portsChart.destroy();

    const sorted = sortEntriesDesc(stats.top_destination_ports).slice(0, 10);
    const labels = sorted.map(e => String(e[0]));
    const values = sorted.map(e => e[1]);

    const gradient = ctx.createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, COLORS.cyan);
    gradient.addColorStop(1, COLORS.blue);

    portsChart = new Chart(ctx, {
        type: "bar",
        data: { labels, datasets: [{ label: "Connections", data: values, backgroundColor: gradient, borderRadius: 8, borderSkipped: false, maxBarThickness: 40 }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => c.raw + " connections" } } },
            scales: {
                y: { beginAtZero: true, grid: { color: "rgba(255,255,255,.06)" }, ticks: { color: "#68718c" } },
                x: { grid: { display: false }, ticks: { color: "#9aa4bd" } }
            }
        }
    });
}

function createTrafficUsageChart(stats) {
    const ctx = document.getElementById("trafficUsageChart").getContext("2d");
    if (trafficUsageChart) trafficUsageChart.destroy();

    const gradient = ctx.createLinearGradient(0, 0, 0, 220);
    gradient.addColorStop(0, "rgba(79,124,255,.35)");
    gradient.addColorStop(1, "rgba(79,124,255,0)");

    const buckets = stats.has_timestamps ? stats.hourly_traffic_bytes : [0, 0, 0, 0, 0, 0];
    const toMB = b => +(b / 1024 / 1024).toFixed(2);

    trafficUsageChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: ["00-04", "04-08", "08-12", "12-16", "16-20", "20-24"],
            datasets: [{
                label: "Traffic (MB)", data: buckets.map(toMB),
                borderColor: COLORS.blue, backgroundColor: gradient, fill: true,
                borderWidth: 2.5, tension: .4, pointRadius: 3, pointHoverRadius: 6,
                pointBackgroundColor: "#0a0e1a", pointBorderColor: COLORS.blue, pointBorderWidth: 2
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: c => c.raw + " MB",
                        afterLabel: () => stats.has_timestamps ? "" : "No valid timestamps in this dataset — all buckets are 0."
                    }
                }
            },
            scales: {
                x: { grid: { display: false }, ticks: { color: "#9aa4bd" } },
                y: { beginAtZero: true, grid: { color: "rgba(255,255,255,.05)" }, ticks: { color: "#68718c" } }
            }
        }
    });
}

/* ==========================================
   Exports
========================================== */

downloadPDF.addEventListener("click", () => {
    if (!hasAnalysis) { setStatus("Run an analysis first, then download the report.", "error"); return; }
    window.open("/api/export/pdf", "_blank");
});

downloadJSON.addEventListener("click", () => {
    if (!hasAnalysis) { setStatus("Run an analysis first, then export JSON.", "error"); return; }
    window.open("/api/export/json", "_blank");
});

downloadFindingsCSV.addEventListener("click", () => {
    if (!hasAnalysis) { setStatus("Run an analysis first, then export findings.", "error"); return; }
    window.open("/api/export/findings.csv", "_blank");
});

console.log("✅ SentinelLog frontend loaded (redesigned UI, backend mode)");
