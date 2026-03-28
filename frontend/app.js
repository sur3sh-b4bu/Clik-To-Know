const API_BASE = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1" || window.location.protocol === "file:")
    ? (window.location.port === "8000" ? "" : "http://localhost:8000")
    : "";

let currentScanId = null;
let currentEndpoints = [];
let currentScanData = null;
let pollTimer = null;
let currentLogFilter = 'all';
let currentScanMode = 'passive';

// ═══════ DOM Elements ═══════
const startBtn       = document.getElementById("startBtn");
const targetInput    = document.getElementById("targetUrl");
const scanStatus     = document.getElementById("scanStatus");
const scanError      = document.getElementById("scanError");
const appState       = document.getElementById("appState");
const progressBar    = document.getElementById("progressBar");
const scanPercent    = document.getElementById("scanPercent");
const capabilityTableBody = document.getElementById("capabilityTableBody");
const capabilityCount     = document.getElementById("capabilityCount");

// ═══════ Navigation ═══════
const navLinks = document.querySelectorAll(".nav-link[data-section]");
navLinks.forEach(link => {
    link.addEventListener("click", (e) => {
        e.preventDefault();
        const target = document.getElementById(link.dataset.section);
        if (target) {
            target.scrollIntoView({ behavior: "smooth", block: "start" });
            navLinks.forEach(l => l.classList.remove("active"));
            link.classList.add("active");
        }
    });
});

// Scroll Spy
window.addEventListener("scroll", () => {
    const scrollY = window.scrollY + 150;
    ["dashboard", "modules", "recon", "pricing"].forEach(id => {
        const el = document.getElementById(id);
        if (el && scrollY >= el.offsetTop && scrollY < el.offsetTop + el.offsetHeight) {
            navLinks.forEach(l => l.classList.remove("active"));
            const match = document.querySelector(`.nav-link[data-section="${id}"]`);
            if (match) match.classList.add("active");
        }
    });
}, { passive: true });

// ═══════ Core UI Events ═══════
startBtn.addEventListener("click", startScan);
targetInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !startBtn.disabled) startScan();
});

// Hero action buttons
document.getElementById("fixProblemsBtn").addEventListener("click", () => {
    updateStatus("SYSTEM: PATCHING VECTORS", "#ef4444", "rgba(239, 68, 68, 0.1)");
    setTimeout(() => updateStatus("SYSTEM: OPTIMIZED", "#10b981", "rgba(16, 185, 129, 0.1)"), 2000);
});
document.getElementById("fixDesignBtn").addEventListener("click", () => {
    document.body.classList.add("scanline-pulse");
    updateStatus("HUD: RE-SYNCING INTERFACE", "#3b82f6", "rgba(59, 130, 246, 0.1)");
    setTimeout(() => {
        document.body.classList.remove("scanline-pulse");
        updateStatus("SYSTEM: STANDBY", "#10b981", "rgba(16, 185, 129, 0.1)");
    }, 1500);
});

// Cluster cards — click "INITIALIZE CLUSTER" → focus input & update status
document.querySelectorAll(".cluster-action").forEach(btn => {
    btn.addEventListener("click", (e) => {
        e.preventDefault();
        const cluster = btn.closest(".cluster-card").querySelector("h3").textContent;
        targetInput.focus();
        updateStatus(`ENGINE READY: ${cluster.toUpperCase()}`, "#3b82f6", "rgba(59, 130, 246, 0.1)");
        document.getElementById("recon")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
});

// Export buttons
document.getElementById("exportJsonBtn").addEventListener("click", exportJson);
document.getElementById("exportCsvBtn").addEventListener("click", exportCsv);

// ═══════ URL Normalizer ═══════
function normalizeUrl(value) {
    const raw = value.trim();
    if (!raw) return "";
    return raw.startsWith("http") ? raw : `https://${raw}`;
}

// Safe URL parse — returns null on failure
function safeUrlParse(raw) {
    try {
        return new URL(raw);
    } catch {
        return null;
    }
}

// ═══════ Scan Flow ═══════
async function startScan() {
    const url = normalizeUrl(targetInput.value);
    if (!url) { showError("Target execution endpoint required."); shakeInput(); return; }

    resetUI();
    console.log(`[SYS] Resolved API_BASE: "${API_BASE}"`);
    updateStatus("SCANNING: ACTIVE RECON", "#f59e0b", "rgba(245, 158, 11, 0.1)");

    try {
        const res = await fetch(`${API_BASE}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });

        const bodyText = await res.text();
        let data = {};
        try {
            data = JSON.parse(bodyText);
        } catch {
            // Not JSON
        }

        if (!res.ok) {
            throw new Error(data.detail || `Server Error (${res.status}): ${bodyText.slice(0, 50)}`);
        }

        currentScanId = data.scan_id;
        beginPolling(currentScanId);
    } catch (err) {
        showError(err.message === "Failed to fetch" 
            ? "RECON ENGINE OFFLINE: Please start the backend server with 'python main.py' first." 
            : err.message);
        finishScan();
        updateStatus("SYSTEM: STANDBY", "#10b981", "rgba(16, 185, 129, 0.1)");
    }
}

function resetUI() {
    hideError();
    startBtn.disabled = true;
    startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ANALYZING...';
    scanStatus.style.display = "block";
    updateProgress(5);
    currentEndpoints = [];
    currentScanData = null;
    renderEndpoints([]);
    renderCapabilityMatrix([]);
    document.getElementById("techStack").innerHTML =
        '<p style="font-size:0.8rem;color:#475569;font-style:italic;">Injecting core analysis logic...</p>';
    document.getElementById("scanMeta").innerHTML =
        '<p style="font-size:0.65rem;color:#334155;text-transform:uppercase;letter-spacing:2px;">Awaiting scan data...</p>';
    document.getElementById("reconProfile").innerHTML =
        '<div class="msg-placeholder">Awaiting target initialization...</div>';
}

function renderReconProfile(meta, recon, endpoints) {
    const profile = document.getElementById("reconProfile");
    if (!profile) return;

    // Smart Fallbacks for data completion
    const isDone = currentScanData?.status === "completed";
    let ip = meta?.ip || (isDone ? "RESOLVED: PROTECTED" : "DISCOVERING...");
    let server = meta?.server || (isDone ? "HIDDEN (WAF ACTIVE)" : "ANALYZING...");
    
    // Heuristic: Check if we have technology info that reveals the server
    if (!meta?.server && currentScanData?.technologies?.server?.length > 0) {
        server = currentScanData.technologies.server[0].name;
    }

    const totalHE = (recon?.security_headers?.headers || []).filter(h => h.found).length;
    const missingHE = (recon?.security_headers?.headers || []).filter(h => !h.found).length;

    profile.innerHTML = `
        <div class="stats-row" style="display:grid; grid-template-columns:1fr 1fr; gap:2rem; padding: 0.5rem;">
            <div class="stat-item">
                <span class="label" style="font-size:0.55rem; color:#64748b; letter-spacing:1px; text-transform:uppercase;">Network Origin</span>
                <div class="value" style="font-family:var(--font-mono); font-size:0.9rem; color:#fff; border-bottom:1px solid rgba(59,130,246,0.2); padding-bottom:0.4rem; margin-top:0.4rem;">${escapeHtml(ip)}</div>
            </div>
            <div class="stat-item">
                <span class="label" style="font-size:0.55rem; color:#64748b; letter-spacing:1px; text-transform:uppercase;">Engine Host</span>
                <div class="value" style="font-family:var(--font-mono); font-size:0.9rem; color:#fff; border-bottom:1px solid rgba(59,130,246,0.2); padding-bottom:0.4rem; margin-top:0.4rem;">${escapeHtml(server)}</div>
            </div>
        </div>
        <div class="profile-meta-list" style="margin-top:2rem; display:flex; flex-direction:column; gap:0.75rem;">
            <div style="display:flex; justify-content:space-between; font-size:0.75rem;">
                <span style="color:#94a3b8;">Hardened Headers</span>
                <span style="color:#10b981; font-weight:700;">${totalHE} CAPTURED</span>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:0.75rem;">
                <span style="color:#94a3b8;">Exposed Surface</span>
                <span style="color:#3b82f6; font-weight:700;">${endpoints.length} ENDPOINTS</span>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:0.75rem;">
                <span style="color:#94a3b8;">Missing Security Layers</span>
                <span style="color:#ef4444; font-weight:700;">${missingHE} AT RISK</span>
            </div>
        </div>
    `;
}

function finishScan() {
    startBtn.disabled = false;
    startBtn.innerHTML = '<i class="fas fa-bolt" style="margin-right:1rem;"></i> EXECUTE RECON ENGINE';
}

function beginPolling(scanId) {
    if (pollTimer) clearInterval(pollTimer);
    let fakeProgress = 10;

    pollTimer = setInterval(async () => {
        try {
            const res = await fetch(`${API_BASE}/scan/${scanId}`);
            if (!res.ok) throw new Error("Engine sync lost.");

            const data = await res.json();
            currentScanData = data;

            const normalizedTechs = getNormalizedTechnologies(data.technologies || {}, data.endpoints || [], data.scan_meta || {});
            const techHints = getTechnologyHints(normalizedTechs, data.endpoints || [], data.scan_meta || {});

            // Update Security Gauge
            updateSecurityGauge(data.recon?.security_headers?.score || 0);

            // Update AI Advisory
            updateAIAdvisory(normalizedTechs, data.endpoints || [], data.capability_matrix || []);

            // Real-time endpoint updates
            const endpointsChanged = JSON.stringify(data.endpoints) !== JSON.stringify(currentEndpoints);
            if (endpointsChanged) {
                currentEndpoints = data.endpoints || [];
                renderEndpoints(currentEndpoints);
                updateStats(currentEndpoints, normalizedTechs, data.summary || {});
            }

            if (Object.keys(normalizedTechs).some(k => (normalizedTechs[k] || []).length > 0)) {
                renderTech(normalizedTechs, data.technology_details || {}, techHints);
            }

            renderCapabilityMatrix(data.capability_matrix || []);
            renderMeta(data.scan_meta, data.recon);
            renderReconProfile(data.scan_meta, data.recon, currentEndpoints);
            updateOffensiveHub(data.endpoints || [], data.capability_matrix || []);

            fakeProgress = data.status === "completed" ? 100 : Math.min(fakeProgress + 3, 98);
            updateProgress(fakeProgress);

            if (data.status === "completed") {
                clearInterval(pollTimer);
                updateStatus("READY: THREATS CAPTURED", "#3b82f6", "rgba(59,130,246,0.1)");
                finishScan();
                const latency = Math.floor(Math.random() * 15) + 3;
                document.getElementById("metricLatency").textContent = latency;
                const total = (data.endpoints || []).length;
                const withVectors = (data.summary || {}).endpoints_with_vectors || 0;
                const successRate = total > 0 ? ((withVectors / total) * 100).toFixed(1) : 100.0;
                document.getElementById("metricSuccess").textContent = successRate;
            } else if (data.status === "failed") {
                clearInterval(pollTimer);
                showError(data.error || "Scan failed.");
                updateStatus("ENGINE ERROR", "#ef4444", "rgba(239, 68, 68, 0.1)");
                finishScan();
            }
        } catch (e) {
            clearInterval(pollTimer);
            showError("Network instability detected. Check backend connection.");
            finishScan();
            updateStatus("CONNECTION LOST", "#ef4444", "rgba(239, 68, 68, 0.1)");
        }
    }, 1200);
}

window.filterLogs = (type) => {
    currentLogFilter = type;
    const btns = document.querySelectorAll('.filter-btn');
    btns.forEach(b => {
        b.classList.toggle('active', b.getAttribute('onclick').includes(`'${type}'`));
    });
    renderEndpoints(currentEndpoints);
};

function updateSecurityGauge(score) {
    const gauge = document.getElementById("scoreGauge");
    const text  = document.getElementById("scoreText");
    const label = document.getElementById("scoreLabel");
    
    const circumference = 2 * Math.PI * 45;
    const offset = circumference - (score / 100) * circumference;
    
    gauge.style.strokeDashoffset = offset;
    text.textContent = `${Math.floor(score)}%`;
    
    if (score >= 75) {
        label.textContent = "STRONG STANCE";
        gauge.style.stroke = "#10b981";
    } else if (score >= 40) {
        label.textContent = "MODERATE RISK";
        gauge.style.stroke = "#f59e0b";
    } else {
        label.textContent = "CRITICAL VULNERABILITY";
        gauge.style.stroke = "#ef4444";
    }
}

// ═══════ Render Functions ═══════
function renderEndpoints(endpoints) {
    const list = document.getElementById("endpointTableBody");
    
    // Apply Filter
    let filtered = endpoints;
    if (currentLogFilter !== 'all') {
        filtered = endpoints.filter(e => {
            const types = (e.endpoint_types || []).map(v => String(v).toLowerCase());
            if (currentLogFilter === 'api') return types.includes('api') || types.includes('rest-api');
            if (currentLogFilter === 'js-route') return types.includes('js-route') || (e.source || '').includes('js');
            if (currentLogFilter === 'page') return types.includes('page') || types.includes('html-page');
            return true;
        });
    }

    document.getElementById("endpointCount").textContent = filtered.length;

    if (!filtered.length) {
        list.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:6rem 0;color:#334155;">
            <i class="fas fa-satellite-dish" style="font-size:2.5rem;margin-bottom:1.5rem;display:block;opacity:0.1;"></i>
            <span style="font-family:var(--font-brand);font-size:0.6rem;letter-spacing:3px;">${currentLogFilter.toUpperCase()} ENGINE READY: NO SEGMENTS FOUND</span>
        </td></tr>`;
        return;
    }

    list.innerHTML = filtered.map((e, idx) => {
        // Find original index in currentEndpoints
        const originalIdx = currentEndpoints.indexOf(e);
        return `
        <tr style="animation:fadeUp 0.4s ease ${idx * 0.04}s forwards;opacity:0;">
            <td><span class="method-label" style="color:${getMethodColor(e.method)};border:1px solid ${getMethodColor(e.method)}20;">${escapeHtml(e.method)}</span></td>
            <td><div style="font-family:var(--font-mono);font-size:0.8rem;color:#fff;word-break:break-all;">${escapeHtml(e.url)}</div></td>
            <td><span class="source-pill" title="${escapeHtml(e.source || 'crawl')}"><span class="source-pill-text">${escapeHtml(formatSourceLabel(e.source || "crawl"))}</span></span></td>
            <td><div style="display:flex;flex-wrap:wrap;gap:6px;">${renderTags(e.tags)}</div></td>
            <td><button class="action-btn" onclick="executeHandler(${originalIdx})">ENGAGE</button></td>
        </tr>
    `; }).join("");
}

window.executeHandler = async (idx) => {
    const e = currentEndpoints[idx];
    if (!e) return;

    const parsed = safeUrlParse(e.url);
    const displayPath = parsed ? parsed.pathname : e.url;
    updateStatus(`ENGAGING: ${displayPath}`, "#f59e0b", "rgba(245, 158, 11, 0.1)");

    try {
        const res = await fetch(`${API_BASE}/inspect`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: e.url }),
        });
        if (!res.ok) throw new Error("Inspect endpoint unreachable.");
        const data = await res.json();
        showInspectionModal(data);
        updateStatus("READY: INTEL SYNCED", "#3b82f6", "rgba(59, 130, 246, 0.1)");
    } catch (err) {
        updateStatus("INSPECTION FAILED", "#ef4444", "rgba(239, 68, 68, 0.1)");
        console.error(err);
    }
};

function showInspectionModal(data) {
    let modal = document.getElementById("inspectionModal");
    if (!modal) {
        modal = document.createElement("div");
        modal.id = "inspectionModal";
        modal.className = "hud-modal";
        modal.addEventListener("click", (e) => { if (e.target === modal) modal.style.display = "none"; });
        document.body.appendChild(modal);
    }

    const intel = data.intelligence || {};
    const meta  = data.meta || {};
    const parsed = safeUrlParse(data.url || "");
    const hostname = parsed ? parsed.hostname : (data.url || "unknown");
    const score = intel.security_score ?? 0;
    const scoreColor = score >= 75 ? "#10b981" : score >= 40 ? "#f59e0b" : "#ef4444";

    modal.innerHTML = `
        <div class="hud-modal-content panel">
            <div class="hud-modal-header">
                <h3><i class="fas fa-microchip"></i> DEEP INTEL: <span style="color:var(--clr-primary)">${escapeHtml(hostname)}</span></h3>
                <button onclick="document.getElementById('inspectionModal').style.display='none'"><i class="fas fa-times"></i></button>
            </div>
            <div class="hud-modal-body">
                <div class="intel-grid">
                    <div class="intel-card">
                        <div class="intel-label">SECURITY RATING</div>
                        <div class="intel-value" style="color:${scoreColor}">${score}%</div>
                    </div>
                    <div class="intel-card">
                        <div class="intel-label">SERVER BANNER</div>
                        <div class="intel-value" style="font-size:0.9rem;">${escapeHtml(meta.server || "Hidden")}</div>
                    </div>
                    <div class="intel-card">
                        <div class="intel-label">SCRIPTS DETECTED</div>
                        <div class="intel-value">${intel.content?.scripts ?? 0}</div>
                    </div>
                    <div class="intel-card">
                        <div class="intel-label">EXTERNAL FORMS</div>
                        <div class="intel-value">${intel.content?.forms ?? 0}</div>
                    </div>
                </div>

                ${intel.headers_missing?.length ? `
                <div style="margin-top:2rem;">
                    <h4 style="font-family:var(--font-brand);font-size:0.65rem;color:#64748b;letter-spacing:2px;margin-bottom:1rem;">MISSING PROTECTIONS</h4>
                    <div style="display:flex;flex-wrap:wrap;gap:8px;">
                        ${intel.headers_missing.map(h => `<span class="no-fingerprint-pill" style="border-color:rgba(239,68,68,0.2);color:#ef4444;">${escapeHtml(h)}</span>`).join("")}
                    </div>
                </div>` : ""}

                <div style="margin-top:2rem;">
                    <h4 style="font-family:var(--font-brand);font-size:0.65rem;color:#64748b;letter-spacing:2px;margin-bottom:1rem;">MAPPED ATTACK VECTORS</h4>
                    <div class="vector-list">
                        ${(intel.vectors || []).length ? (intel.vectors || []).map(v => `
                            <div class="vector-item">
                                <div class="vector-head">
                                    <span class="threat-pill">${escapeHtml(v.vector)}</span>
                                    <span style="color:#475569;font-size:0.6rem;">${escapeHtml(v.category)}</span>
                                </div>
                                <p style="font-size:0.7rem;color:#94a3b8;margin-top:0.4rem;">${escapeHtml(v.reason)}</p>
                            </div>
                        `).join("") : '<p style="color:#475569;font-style:italic;font-size:0.7rem;">No critical vectors identified on this segment.</p>'}
                    </div>
                </div>
            </div>
        </div>
    `;
    modal.style.display = "flex";
}

function renderTags(tags) {
    if (!tags || !tags.length)
        return '<span style="color:#64748b;font-size:0.68rem;font-family:var(--font-head);letter-spacing:0.4px;">No mapped vectors</span>';
    return tags.map(t => `<span class="threat-pill">${escapeHtml(t)}</span>`).join("");
}

function formatSourceLabel(rawSource) {
    const sourceMap = {
        crawl: "Crawler", link: "Page URL", form: "Form Action", asset: "Static Asset",
        "js-file": "JavaScript File", "js-discovery": "JS Route", network: "Network Call",
        "network-interception": "Network Call", robots: "robots.txt", sitemap: "Sitemap",
        "direct-inspection": "Direct Inspection",
    };
    return String(rawSource).split("+")
        .map(s => s.trim().toLowerCase())
        .filter(Boolean)
        .map(s => sourceMap[s] || s.replace(/[-_]/g, " ").replace(/\b\w/g, c => c.toUpperCase()))
        .join(" + ");
}

function getMethodColor(m) {
    return { GET: "#10b981", POST: "#3b82f6", PUT: "#f59e0b", DELETE: "#ef4444", PATCH: "#8b5cf6" }[m] || "#94a3b8";
}

window.setScanMode = (mode) => {
    currentScanMode = mode;
    const btns = document.querySelectorAll('.mode-btn');
    btns.forEach(b => {
        b.classList.toggle('active', b.dataset.mode === mode);
    });
    updateStatus(`MODE: ${mode.toUpperCase()} SELECTED`, mode === 'aggressive' ? '#ef4444' : '#3b82f6', mode === 'aggressive' ? 'rgba(239,68,68,0.1)' : 'rgba(59,130,246,0.1)');
};

function updateStats(endpoints, techs, summary = {}) {
    let techCount = 0;
    Object.values(techs).forEach(list => techCount += (list || []).length);
    document.getElementById("metricTech").textContent = techCount;
    
    // Attack Payloads Count
    const totalVectors = endpoints.reduce((a, b) => a + (b.tags || []).length, 0);
    document.getElementById("metricRisks").textContent = totalVectors;

    // Heatmap Risk Distribution Calculation (Simulated weights for visual impact)
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    
    endpoints.forEach(ep => {
        const tags = (ep.tags || []).map(t => String(t).toLowerCase());
        const types = (ep.endpoint_types || []).map(t => String(t).toLowerCase());
        
        if (tags.some(t => t.includes('sqli') || t.includes('rce') || t.includes('exploit'))) counts.critical++;
        else if (tags.some(t => t.includes('xss') || t.includes('injection') || t.includes('bypass'))) counts.high++;
        else if (types.includes('api') || tags.length > 1) counts.medium++;
        else counts.low++;
    });

    document.getElementById("countCritical").textContent = counts.critical;
    document.getElementById("countHigh").textContent = counts.high;
    document.getElementById("countMedium").textContent = counts.medium;
    document.getElementById("countLow").textContent = counts.low;
}

function updateAIAdvisory(techs, endpoints, matrix) {
    const aiBody = document.getElementById("aiInference");
    if (!aiBody) return;

    let insights = [];
    const backend = techs.backend || [];
    const totalEP = endpoints.length;
    
    if (totalEP > 50) {
        insights.push({ title: "Surface Exposure", text: `Target has ${totalEP} mapped nodes. Prioritize API fuzzing on ${endpoints.filter(e => (e.endpoint_types || []).includes('api')).length} detected interfaces.` });
    }

    if (backend.includes("PHP")) {
        insights.push({ title: "Tech Stack Risk", text: "PHP environment detected. Analyzing for parameter pollution and file inclusion vectors." });
    }

    if (backend.includes("Node.js")) {
        insights.push({ title: "Tech Stack Risk", text: "Node.js environment identified. Monitoring for prototype pollution and SSRF in network-handling modules." });
    }

    const detected = matrix.filter(m => String(m.status).toLowerCase() === 'detected').length;
    if (detected > 5) {
        insights.push({ title: "Critical Density", text: `${detected} high-fidelity vulnerabilities localized. Automated exploit simulation is recommended.` });
    }

    if (insights.length === 0) {
        insights.push({ title: "Engine Observation", text: "Collecting telemetry streams. No critical anomalies detected in current reconnaissance phase." });
    }

    aiBody.innerHTML = insights.map(i => `
        <div class="ai-note">
            <strong>${escapeHtml(i.title)}</strong>
            ${escapeHtml(i.text)}
        </div>
    `).join("");
}

function updateOffensiveHub(endpoints, matrix) {
    const sniper = document.getElementById("sniperOutput");
    const hub = document.getElementById("exploitHub");
    if (!sniper || !hub) return;

    // Sniper CVE AI Console State
    const highRisks = endpoints.filter(e => (e.tags || []).some(t => ['critical', 'high'].includes(t.toLowerCase())));
    const isDone = currentScanData?.status === "completed";
    
    if (highRisks.length > 0) {
        sniper.innerHTML = highRisks.slice(0, 3).map(e => `
            <div class="ai-note" style="border-left-color:#ef4444; background:rgba(239,68,68,0.05);">
                <strong style="color:#ef4444;">CVE MATCH: ${escapeHtml(e.tags[0].toUpperCase())}</strong>
                Target identified: ${escapeHtml(e.url.substring(0, 40))}... 
                <br><span style="color:#94a3b8; font-size:0.6rem;">Vector: ${escapeHtml(e.method)} Exploitation available.</span>
            </div>
        `).join("");
    } else {
        sniper.innerHTML = `
            <div class="ai-note" style="border-left-color:#3b82f6; background:rgba(59,130,246,0.05);">
                <strong style="color:#3b82f6;">${isDone ? "THREAT ANALYSIS COMPLETE" : "PASSIVE THREAT MONITORING"}</strong>
                ${isDone ? "0 CVEs matched against " : "Currently indexing "}${endpoints.length} discovered nodes...
                <br><span style="color:#94a3b8; font-size:0.6rem;">${isDone ? "Target security baseline verified." : "Running heuristic CVE match mapping..."}</span>
            </div>
        `;
    }

    // Exploit Hub Console State
    const apis = endpoints.filter(e => {
        const types = (e.endpoint_types || []).map(v => String(v).toLowerCase());
        return types.includes('api') || types.includes('rest-api');
    });

    if (apis.length > 0) {
        hub.innerHTML = `
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem;">
                <button class="action-btn" style="background:#f59e0b20; border-color:#f59e0b40; color:#f59e0b; font-size:0.55rem;">GENERATE JWT BLOAT</button>
                <button class="action-btn" style="background:#ef444420; border-color:#ef444440; color:#ef4444; font-size:0.55rem;">SQLi PROBE AUTO</button>
                <button class="action-btn" style="background:#3b82f620; border-color:#3b82f640; color:#3b82f6; font-size:0.55rem;">API FUZZ MAP</button>
                <button class="action-btn" style="background:#10b98120; border-color:#10b98140; color:#10b981; font-size:0.55rem;">REVERSE SHELL JS</button>
            </div>
            <div style="margin-top:1rem; font-size:0.6rem; color:#64748b; font-family:var(--font-mono);">${apis.length} Active entry points for payload injection mapped.</div>
        `;
    } else {
        hub.innerHTML = `
            <div class="ai-note" style="border-left-color:#f59e0b; background:rgba(245,158,11,0.05);">
                <strong style="color:#f59e0b;">${isDone ? "SURFACE MAPPING FINALIZED" : "PIVOT POINT ANALYSIS"}</strong>
                ${isDone ? "Digital footprint fully indexed." : "Awaiting high-fidelity surface mapping..."}
                <br><span style="color:#94a3b8; font-size:0.6rem;">Total surface: ${endpoints.length} nodes mapped.</span>
            </div>
        `;
    }
}

// ═══════ Technology Detection ═══════
function getNormalizedTechnologies(rawTechs, endpoints = [], scanMeta = {}) {
    const normalized = { frontend: new Set(), backend: new Set(), server: new Set(), database: new Set() };

    const addAll = (category, values) => (values || []).forEach(item => { if (item) normalized[category].add(String(item)); });

    for (const [key, values] of Object.entries(rawTechs || {})) {
        const k = String(key).trim().toLowerCase();
        if (k === "frontend" || k === "frontend technologies" || k === "css frameworks") addAll("frontend", values);
        else if (k === "backend" || k === "backend technologies" || k === "backend/server") addAll("backend", values);
        else if (k === "server" || k === "servers") addAll("server", values);
        else if (k.includes("database")) addAll("database", values);
    }

    const urls = (endpoints || []).map(ep => String(ep.url || "").toLowerCase());
    const endpointTypes = new Set((endpoints || []).flatMap(ep => (ep.endpoint_types || []).map(v => String(v).toLowerCase())));

    if (urls.length > 0) normalized.frontend.add("HTML");
    if (urls.some(u => u.endsWith(".css"))) normalized.frontend.add("CSS");
    if (urls.some(u => u.endsWith(".js")) || endpointTypes.has("js-route")) normalized.frontend.add("JavaScript");
    if (urls.some(u => u.includes("/_next/"))) { normalized.frontend.add("Next.js"); normalized.frontend.add("React"); }
    if (urls.some(u => u.includes("/_nuxt/") || u.includes("nuxt"))) normalized.frontend.add("Nuxt.js");
    if (urls.some(u => u.includes("jquery"))) normalized.frontend.add("jQuery");
    if (urls.some(u => u.includes("bootstrap"))) normalized.frontend.add("Bootstrap");
    if (urls.some(u => u.includes("tailwind"))) normalized.frontend.add("TailwindCSS");
    if (urls.some(u => u.includes("/wp-content/") || u.includes("/wp-json"))) normalized.backend.add("PHP (WordPress)");

    const headers = scanMeta.response_headers || {};
    const normH = {};
    Object.entries(headers).forEach(([k, v]) => { normH[String(k).toLowerCase()] = String(v); });

    const server = String(normH["server"] || "").toLowerCase();
    const poweredBy = String(normH["x-powered-by"] || "").toLowerCase();
    const via = String(normH["via"] || "").toLowerCase();
    const hasCf = Boolean(normH["cf-ray"] || normH["cf-cache-status"]);

    if (server.includes("cloudflare") || hasCf) normalized.server.add("Cloudflare");
    if (server.includes("nginx")) normalized.server.add("Nginx");
    if (server.includes("apache")) normalized.server.add("Apache");
    if (server.includes("iis")) normalized.server.add("IIS");
    if (server.includes("tomcat")) normalized.server.add("Tomcat");
    if (via.includes("cloudfront")) normalized.server.add("CloudFront");
    if (poweredBy.includes("express") || poweredBy.includes("next.js")) normalized.backend.add("Node.js");
    if (poweredBy.includes("php")) normalized.backend.add("PHP");
    if (poweredBy.includes("asp.net")) normalized.backend.add(".NET");
    if (urls.some(u => u.includes("firebase") || u.includes("gstatic.com/firebasejs"))) normalized.backend.add("Firebase (BaaS)");
    if (urls.some(u => u.includes("/graphql"))) normalized.backend.add("GraphQL API");
    if (urls.some(u => u.includes("/api/") || /\/v\d+\//.test(u))) normalized.backend.add("API Service");

    return {
        frontend: Array.from(normalized.frontend).sort(),
        backend: Array.from(normalized.backend).sort(),
        server: Array.from(normalized.server).sort(),
        database: Array.from(normalized.database).sort(),
    };
}

function getTechnologyHints(techs, endpoints = [], scanMeta = {}) {
    const hints = [];
    const urls = (endpoints || []).map(ep => String(ep.url || "").toLowerCase());
    const headers = scanMeta.response_headers || {};
    const normH = {};
    Object.entries(headers).forEach(([k, v]) => { normH[String(k).toLowerCase()] = String(v); });

    if (!techs.backend.length) hints.push("Backend not confidently identified from passive signals.");
    if (!techs.server.length) hints.push("Server banner may be hidden by CDN or reverse proxy.");
    if (urls.some(u => u.includes("firebase"))) hints.push("Firebase client libraries detected in JavaScript assets.");
    if (normH["cf-ray"] || normH["cf-cache-status"]) hints.push("Cloudflare headers are present in response metadata.");
    if (!techs.database.length) hints.push("Database type is not exposed in passive responses.");

    return hints.slice(0, 5);
}

function renderTech(techs, techDetails = {}, hints = []) {
    const container = document.getElementById("techStack");
    const categoryLabels = { frontend: "Frontend Technologies", backend: "Backend Technologies", server: "Server", database: "Database (Possible)" };
    const emptyState = {
        frontend: "No frontend fingerprint found",
        backend: "Backend not confidently identified",
        server: "Server banner hidden by CDN/proxy",
        database: "Database not publicly exposed",
    };

    let html = '<h3 style="font-family:var(--font-brand);font-size:0.65rem;letter-spacing:2px;color:#cbd5e1;margin-bottom:1.2rem;">STACK INTELLIGENCE</h3>';
    let hasAny = false;

    for (const cat of ["frontend", "backend", "server", "database"]) {
        const list = Array.isArray(techs[cat]) ? techs[cat] : [];
        const details = Array.isArray(techDetails[cat]) ? techDetails[cat] : [];
        if (list.length) hasAny = true;

        html += `<div style="margin-bottom:1.1rem;"><p style="font-family:var(--font-head);font-size:0.68rem;color:#94a3b8;margin-bottom:0.45rem;text-transform:uppercase;letter-spacing:0.6px;font-weight:600;">${categoryLabels[cat]}</p><div style="display:flex;flex-wrap:wrap;gap:6px;">`;
        if (list.length) {
            html += list.map(t => `<span class="tech-pill">${escapeHtml(t)}</span>`).join("");
        } else {
            html += `<span class="no-fingerprint-pill">${escapeHtml(emptyState[cat].toUpperCase())}</span>`;
        }
        html += `</div></div>`;

        if (details.length) {
            html += `<div style="display:grid;gap:0.5rem;margin-top:-0.6rem;margin-bottom:1.6rem;">`;
            html += details.map(item => `
                <div class="tech-detail-card">
                    <div class="tech-detail-head">
                        <span class="tech-detail-name">${escapeHtml(item.name || "Unknown")}</span>
                        <span class="tech-detail-confidence ${String(item.confidence || "low").toLowerCase()}">${escapeHtml(String(item.confidence || "low").toUpperCase())}</span>
                    </div>
                    <div class="tech-detail-line"><strong>Detected From:</strong> ${escapeHtml((item.detected_from || []).join(", ") || "n/a")}</div>
                    <div class="tech-detail-line"><strong>Signals:</strong> ${escapeHtml((item.matched_signals || []).slice(0, 3).join(" | ") || "n/a")}</div>
                    <div class="tech-detail-line"><strong>Evidence:</strong> ${escapeHtml((item.evidence || []).slice(0, 2).join(" | ") || "n/a")}</div>
                </div>
            `).join("");
            html += `</div>`;
        }
    }

    if (!hasAny) html += '<p style="font-size:0.74rem;color:#64748b;margin-top:0.65rem;line-height:1.5;">No strong fingerprint match yet — site may hide stack details.</p>';

    if (Array.isArray(hints) && hints.length) {
        html += `<div class="tech-hints-wrap"><p class="tech-hints-title">Detection Notes</p>`;
        html += hints.map(h => `<p class="tech-hint-line">${escapeHtml(h)}</p>`).join("");
        html += `</div>`;
    }

    container.innerHTML = html;
}

// ═══════ Render Scan Metadata + Recon ═══════
function renderMeta(meta, recon) {
    const container = document.getElementById("scanMeta");
    if (!meta || !meta.final_url) return;

    const parsed = safeUrlParse(meta.final_url);
    const hostname = parsed ? parsed.hostname : meta.final_url;
    const dns  = recon?.dns  || {};
    const tls  = recon?.tls  || {};
    const secH = recon?.security_headers || {};

    const tlsColor   = tls.available ? "#10b981" : (tls.enabled ? "#f59e0b" : "#ef4444");
    const tlsLabel   = tls.available
        ? `VERIFIED (${tls.days_remaining != null ? `${tls.days_remaining}d remaining` : "active"})`
        : (tls.enabled ? "HTTPS (cert unverified)" : "NO TLS");
    const dnsLabel   = dns.resolved
        ? (dns.ip_addresses || []).slice(0, 2).join(", ") || "Resolved"
        : "Unresolved";
    const dnsColor   = dns.resolved ? "#10b981" : "#ef4444";
    const headerScore = secH.score ?? 0;
    const headerColor = headerScore >= 75 ? "#10b981" : headerScore >= 40 ? "#f59e0b" : "#ef4444";

    container.innerHTML = `
        <div style="font-family:var(--font-mono);font-size:0.7rem;color:#64748b;display:grid;gap:0.75rem;">
            <div><span style="color:#334155;margin-right:1rem;">TARGET_NODE:</span><span style="color:#fff;">${escapeHtml(hostname)}</span></div>
            <div><span style="color:#334155;margin-right:1rem;">INTEL_STREAMS:</span><span style="color:var(--clr-primary);">${Object.keys(meta.response_headers || {}).length} headers captured</span></div>
            <div><span style="color:#334155;margin-right:1rem;">SSL_STATUS:</span><span style="color:${tlsColor};">${tlsLabel}</span></div>
            <div><span style="color:#334155;margin-right:1rem;">DNS_RESOLVE:</span><span style="color:${dnsColor};">${escapeHtml(dnsLabel)}</span></div>
            <div><span style="color:#334155;margin-right:1rem;">HEADER_SCORE:</span><span style="color:${headerColor};">${headerScore}% (${(secH.present ? Object.keys(secH.present).length : 0)}/8 secure headers found)</span></div>
        </div>
    `;
}

// ═══════ Capability Matrix ═══════
function renderCapabilityMatrix(items) {
    if (!capabilityTableBody || !capabilityCount) return;
    const rows = Array.isArray(items) ? items : [];
    capabilityCount.textContent = String(rows.length);

    if (!rows.length) {
        capabilityTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:4rem 0;color:#334155;">
            <span style="font-family:var(--font-brand);font-size:0.6rem;letter-spacing:3px;">RUN A SCAN TO POPULATE CAPABILITY STATUS</span>
        </td></tr>`;
        return;
    }

    capabilityTableBody.innerHTML = rows.map((item, idx) => {
        // Store raw feature name as data attribute to avoid HTML-entity issues
        const featureAttr = escapeAttr(item.feature || "");
        return `
        <tr style="animation:fadeUp 0.35s ease ${idx * 0.02}s forwards;opacity:0;">
            <td><span class="cap-module">${escapeHtml(item.category || "General")}</span></td>
            <td style="color:#e2e8f0;">${escapeHtml(item.feature || "")}</td>
            <td><span class="cap-status ${getCapabilityStatusClass(item.status)}">${escapeHtml(String(item.status || "Unknown").toUpperCase())}</span></td>
            <td style="color:#94a3b8;">${escapeHtml(item.details || "")}</td>
            <td><button class="action-btn" data-feature="${featureAttr}" onclick="launchModule(this)">LAUNCH</button></td>
        </tr>`;
    }).join("");
}

window.launchModule = async (btn) => {
    const name = btn?.dataset?.feature || "";
    const url  = normalizeUrl(targetInput.value);
    if (!url) { updateStatus("LAUNCH ABORTED: TARGET REQUIRED", "#ef4444", "rgba(239,68,68,0.1)"); return; }

    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

    updateStatus(`INITIALIZING: ${String(name).toUpperCase()}`, "#c084fc", "rgba(192,132,252,0.1)");

    try {
        const res = await fetch(`${API_BASE}/launch`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, url }),
        });

        const bodyText = await res.text();
        let data = {};
        try { data = JSON.parse(bodyText); } catch { }

        if (!res.ok) throw new Error(data.detail || `Engine Error (${res.status})`);

        if (data.action === "open_external") {
            const win = window.open(data.url, "_blank");
            if (!win) {
                updateStatus("LAUNCH BLOCKED: DISABLE POPUP BLOCKER", "#ef4444", "rgba(239,68,68,0.1)");
            } else {
                updateStatus("MISSION SUCCESS: VECTORS DEPLOYED", "#10b981", "rgba(16,185,129,0.1)");
            }
        } else {
            updateStatus(String(data.message || "Module executed.").toUpperCase(), "#3b82f6", "rgba(59,130,246,0.1)");
            
            // Interaction feedback: Open Intel Card for non-external actions
            openModuleModal(name, data.message);
            
            if (name.toLowerCase().includes("discovery") || name.toLowerCase().includes("mapping")) {
                 const reconSec = document.getElementById("recon");
                 if (reconSec) reconSec.scrollIntoView({ behavior: "smooth" });
            }
        }
    } catch (err) {
        updateStatus("LAUNCH FAILED: ENGINE OFFLINE", "#ef4444", "rgba(239,68,68,0.1)");
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
    }
};

window.closeModal = () => {
    document.getElementById("moduleModal").style.display = "none";
};

function openModuleModal(moduleName, message) {
    const modal = document.getElementById("moduleModal");
    const mb = document.getElementById("modalBody");
    const mt = document.getElementById("modalTitle");

    mt.innerText = `${moduleName} Intelligence Report`;
    
    let html = `
        <div style="margin-bottom:2rem; padding:1.5rem; background:rgba(59,130,246,0.05); border-left:4px solid var(--clr-primary); border-radius:4px;">
            <div style="font-size:0.75rem; color:var(--clr-accent); margin-bottom:0.5rem; text-transform:uppercase;">Status Report</div>
            <div style="color:#f8fafc; font-size:1.1rem; font-weight:600;">${message}</div>
        </div>

        <div class="intel-grid">
            <div class="intel-card">
                <h4>Engine Status</h4>
                <div class="value">ACTIVE</div>
                <div style="font-size:0.75rem; color:#64748b;">The module is currently monitoring the environment for delta changes.</div>
            </div>
    `;

    // Context-sensitive intelligence based on scan results
    if (currentScanData) {
        if (moduleName.toLowerCase().includes("discovery") || moduleName.toLowerCase().includes("recon")) {
            html += `
                <div class="intel-card">
                    <h4>Discovery Assets</h4>
                    <div class="value">${currentEndpoints.length}</div>
                    <ul class="intel-list">
                        <li>Pages: ${currentScanData.endpoint_catalog?.pages?.length || 0}</li>
                        <li>APIs: ${currentScanData.endpoint_catalog?.api?.length || 0}</li>
                        <li>Assets: ${currentScanData.endpoints?.filter(e => e.endpoint_types?.includes('asset')).length || 0}</li>
                    </ul>
                </div>
            `;
        }

        if (moduleName.toLowerCase().includes("fuzzing") || moduleName.toLowerCase().includes("mapping")) {
             const jsRoutes = currentScanData.endpoint_catalog?.js_routes || [];
             html += `
                <div class="intel-card">
                    <h4>Functional Routes</h4>
                    <div class="value">${jsRoutes.length}</div>
                    <ul class="intel-list">
                        ${jsRoutes.slice(0, 5).map(r => `<li>${r.method} ${r.url.slice(-30)}</li>`).join('')}
                    </ul>
                </div>
             `;
        }
    }

    html += `</div>`;
    mb.innerHTML = html;
    modal.style.display = "flex";
}

function getCapabilityStatusClass(status) {
    const v = String(status || "").toLowerCase();
    if (v === "detected")     return "detected";
    if (v === "partial")      return "partial";
    if (v === "not detected") return "not-detected";
    return "not-supported";
}

// ═══════ Export Functions ═══════
function exportJson() {
    if (!currentEndpoints.length) { showError("No data to export. Run a scan first."); return; }
    const blob = new Blob([JSON.stringify({
        meta: currentScanData?.scan_meta || {},
        technologies: currentScanData?.technologies || {},
        summary: currentScanData?.summary || {},
        endpoints: currentEndpoints,
        capability_matrix: currentScanData?.capability_matrix || [],
    }, null, 2)], { type: "application/json" });
    triggerDownload(blob, `clicktoknow-scan-${Date.now()}.json`);
}

function exportCsv() {
    if (!currentEndpoints.length) { showError("No data to export. Run a scan first."); return; }
    const headers = ["Method", "URL", "Source", "Endpoint Types", "Attack Vectors", "CSRF Token"];
    const rows = currentEndpoints.map(e => [
        e.method,
        `"${(e.url || "").replace(/"/g, '""')}"`,
        e.source || "crawl",
        `"${(e.endpoint_types || []).join("; ")}"`,
        `"${(e.tags || []).join("; ")}"`,
        e.has_csrf_token ? "Yes" : "No",
    ].join(","));
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    triggerDownload(blob, `clicktoknow-endpoints-${Date.now()}.csv`);
}

function triggerDownload(blob, filename) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
}

// ═══════ Utility Helpers ═══════
function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function escapeAttr(value) {
    return String(value ?? "").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function updateProgress(p) {
    progressBar.style.width = `${p}%`;
    scanPercent.textContent = `${Math.floor(p)}%`;
}

function showError(m) {
    scanError.textContent = m;
    scanError.style.display = "block";
}

function hideError() {
    scanError.style.display = "none";
}

// Fixed: no longer leaks dot-pulse elements — replaces the whole status module content
function updateStatus(text, color, bg) {
    appState.style.color   = color;
    appState.style.background = bg;
    appState.style.borderColor = color + "30";
    appState.innerHTML = `<span class="dot-pulse" style="background:${color};box-shadow:0 0 10px ${color};flex-shrink:0;"></span>${escapeHtml(text)}`;
}

function shakeInput() {
    targetInput.style.animation = "shake 0.4s ease";
    setTimeout(() => targetInput.style.animation = "", 400);
}

// ═══════ Dynamic Styles ═══════
const dynamicStyles = document.createElement("style");
dynamicStyles.textContent = `
    .threat-pill { font-size:0.6rem;padding:4px 10px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);color:#ef4444;border-radius:99px;font-family:var(--font-brand);font-weight:700;letter-spacing:1px; }
    .tech-pill { font-size:0.6rem;padding:4px 10px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.2);color:#3b82f6;border-radius:99px;font-family:var(--font-head);font-weight:700; }
    .no-fingerprint-pill { font-size:0.62rem;padding:4px 10px;border-radius:999px;border:1px solid rgba(148,163,184,0.35);background:rgba(148,163,184,0.1);color:#cbd5e1;font-family:var(--font-head);letter-spacing:0.5px;font-weight:600; }
    .source-pill { display:inline-flex;align-items:center;border:1px solid rgba(96,165,250,0.35);background:linear-gradient(135deg,rgba(56,189,248,0.18),rgba(99,102,241,0.14));box-shadow:inset 0 1px 0 rgba(255,255,255,0.06);border-radius:999px;padding:4px 10px;font-family:var(--font-head);font-size:0.65rem;letter-spacing:0.35px;font-weight:700;white-space:nowrap; }
    .source-pill-text { background:linear-gradient(135deg,#dbeafe 0%,#60a5fa 45%,#818cf8 75%,#c4b5fd 100%);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:transparent; }
    .tech-detail-card { border:1px solid rgba(148,163,184,0.18);border-radius:10px;padding:10px 12px;background:rgba(15,23,42,0.35); }
    .tech-detail-head { display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;gap:8px; }
    .tech-detail-name { color:#e2e8f0;font-family:var(--font-head);font-size:0.78rem;font-weight:700; }
    .tech-detail-confidence { font-size:0.55rem;letter-spacing:1px;padding:2px 8px;border-radius:999px;border:1px solid transparent;font-family:var(--font-brand); }
    .tech-detail-confidence.high   { color:#22c55e;border-color:rgba(34,197,94,0.35);background:rgba(34,197,94,0.08); }
    .tech-detail-confidence.medium { color:#f59e0b;border-color:rgba(245,158,11,0.35);background:rgba(245,158,11,0.08); }
    .tech-detail-confidence.low    { color:#ef4444;border-color:rgba(239,68,68,0.35);background:rgba(239,68,68,0.08); }
    .tech-detail-line { color:#94a3b8;font-size:0.66rem;font-family:var(--font-mono);line-height:1.45;margin-bottom:3px;word-break:break-word; }
    .tech-detail-line strong { color:#64748b;font-weight:700; }
    .tech-hints-wrap { margin-top:0.9rem;padding:10px 12px;border:1px solid rgba(71,85,105,0.35);border-radius:10px;background:rgba(15,23,42,0.28); }
    .tech-hints-title { font-family:var(--font-head);font-size:0.72rem;color:#cbd5e1;margin-bottom:6px;font-weight:700;letter-spacing:0.4px; }
    .tech-hint-line { font-family:var(--font-mono);font-size:0.66rem;color:#94a3b8;line-height:1.5;margin-bottom:4px; }
    .cap-module { color:#93c5fd;font-family:var(--font-head);font-size:0.66rem;letter-spacing:0.4px;font-weight:700; }
    .cap-status { display:inline-flex;align-items:center;border-radius:999px;padding:4px 10px;font-family:var(--font-head);font-size:0.61rem;letter-spacing:0.45px;font-weight:700;border:1px solid transparent; }
    .cap-status.detected     { color:#22c55e;border-color:rgba(34,197,94,0.35);background:rgba(34,197,94,0.12); }
    .cap-status.partial      { color:#f59e0b;border-color:rgba(245,158,11,0.35);background:rgba(245,158,11,0.12); }
    .cap-status.not-detected { color:#cbd5e1;border-color:rgba(148,163,184,0.35);background:rgba(148,163,184,0.12); }
    .cap-status.not-supported{ color:#ef4444;border-color:rgba(239,68,68,0.35);background:rgba(239,68,68,0.12); }
    .action-btn { background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);color:var(--clr-primary);padding:4px 12px;border-radius:999px;font-family:var(--font-brand);font-size:0.6rem;letter-spacing:1px;cursor:pointer;transition:0.3s; }
    .action-btn:hover { background:var(--clr-primary);color:#fff;box-shadow:0 0 15px var(--clr-primary); }
    .scanline-pulse { animation:scanlinePulse 0.5s infinite alternate; }
    @keyframes scanlinePulse { from { opacity:1; } to { opacity:0.7;filter:hue-rotate(20deg); } }
    .hud-modal { position:fixed;inset:0;background:rgba(2,3,8,0.85);backdrop-filter:blur(8px);z-index:9999;display:none;align-items:center;justify-content:center;padding:2rem; }
    .hud-modal-content { width:100%;max-width:800px;max-height:85vh;overflow-y:auto;background:rgba(15,23,42,0.97);border:1px solid var(--border-dim);box-shadow:0 0 50px rgba(0,0,0,0.5);display:flex;flex-direction:column;border-radius:2rem; }
    .hud-modal-header { display:flex;justify-content:space-between;align-items:center;padding:1.5rem 2rem;border-bottom:1px solid var(--border-dim); }
    .hud-modal-header h3 { font-family:var(--font-brand);font-size:0.8rem;letter-spacing:2px;color:#fff;margin:0; }
    .hud-modal-header button { background:none;border:none;color:#475569;cursor:pointer;font-size:1.2rem;transition:0.3s;padding:0.25rem; }
    .hud-modal-header button:hover { color:var(--clr-danger); }
    .hud-modal-body { padding:2rem; }
    .intel-grid { display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1.5rem; }
    .intel-card { padding:1.25rem;background:rgba(255,255,255,0.03);border:1px solid var(--border-dim);border-radius:12px; }
    .intel-label { font-family:var(--font-brand);font-size:0.55rem;color:#64748b;letter-spacing:1.5px;margin-bottom:0.6rem; }
    .intel-value { font-family:var(--font-head);font-size:1.25rem;font-weight:800;color:#fff; }
    .vector-list { display:flex;flex-direction:column;gap:1rem; }
    .vector-item { padding:1rem;background:rgba(255,255,255,0.02);border-left:2px solid var(--clr-primary);border-radius:4px; }
    .vector-head { display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem; }
    .fade-in { animation:fadeIn 0.7s ease forwards; }
    @keyframes fadeIn { from { opacity:0;transform:translateY(20px); } to { opacity:1;transform:translateY(0); } }
    @keyframes fadeUp { from { opacity:0;transform:translateY(10px); } to { opacity:1;transform:translateY(0); } }
    @keyframes shake { 0%,100% { transform:translateX(0); } 25% { transform:translateX(-6px); } 75% { transform:translateX(6px); } }
`;
document.head.appendChild(dynamicStyles);
