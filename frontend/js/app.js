/**
 * HAST Dashboard – Main Application
 * Vanilla JS, no framework, no build step.
 */

const App = (() => {
  // ── State ──────────────────────────────────────────────────────────────────
  let ws = null;
  let currentScanId = null;
  let scanRunning = false;
  let allFindings = [];
  let filteredFindings = [];
  let expandedRows = new Set();
  let reconnectTimer = null;
  let pingInterval = null;

  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  // ── Tools Catalog ──────────────────────────────────────────────────────────

  const TOOLS_CATALOG = [
    // Recon
    { name: "wafw00f",  phase: "recon", desc: "Detect Web Application Firewalls via response fingerprinting.",
      params: [{ id: "target", label: "Target URL", placeholder: "https://target.com" }] },
    { name: "cdncheck", phase: "recon", desc: "Detect CDN/cloud provider (Cloudflare, Akamai, Fastly, AWS, etc.).",
      params: [{ id: "target", label: "Target URL / IP", placeholder: "https://target.com" }] },
    { name: "nmap",     phase: "recon", desc: "Port scanner — discover open services and versions.",
      params: [{ id: "target", label: "Target URL / IP", placeholder: "https://target.com" }] },
    { name: "asnmap",   phase: "recon", desc: "Map target IP to ASN, org name and CIDR ranges.",
      params: [{ id: "target", label: "Target URL / IP", placeholder: "https://target.com" }] },
    { name: "tlsx",     phase: "recon", desc: "TLS/cert scanner — expiry, self-signed, weak version, mismatches.",
      params: [{ id: "target", label: "Target URL", placeholder: "https://target.com" }] },
    { name: "whatweb",  phase: "recon", desc: "Technology fingerprinting — CMS, frameworks, server software.",
      params: [{ id: "target", label: "Target URL", placeholder: "https://target.com" }] },
    // Discovery
    { name: "subfinder", phase: "discovery", desc: "Passive subdomain enumeration from DNS, APIs, and crawling.",
      params: [{ id: "target", label: "Domain", placeholder: "example.com" }] },
    { name: "dnsx",      phase: "discovery", desc: "Resolve and validate DNS records for a list of hosts.",
      params: [
        { id: "target",  label: "Target URL (domain auto-extracted)", placeholder: "https://target.com" },
        { id: "hosts",   label: "Or: hosts (comma-separated)", placeholder: "sub1.example.com, sub2.example.com" },
      ] },
    { name: "naabu",     phase: "discovery", desc: "Fast port scanner optimised for large-scale host enumeration.",
      params: [
        { id: "target",    label: "Host / IP", placeholder: "example.com" },
        { id: "top_ports", label: "Top N ports", placeholder: "100" },
      ] },
    { name: "httpx",     phase: "discovery", desc: "HTTP probing — confirm live endpoints, grab titles and headers.",
      params: [{ id: "targets", label: "Targets (comma-separated URLs/hosts)", placeholder: "https://target.com, sub.example.com" }] },
    { name: "katana",    phase: "discovery", desc: "Fast, configurable web crawler with JavaScript rendering support.",
      params: [
        { id: "target", label: "Target URL", placeholder: "https://target.com" },
        { id: "depth",  label: "Crawl depth", placeholder: "2" },
      ] },
    { name: "gospider",  phase: "discovery", desc: "Fast web spider for link and endpoint extraction.",
      params: [{ id: "target", label: "Target URL", placeholder: "https://target.com" }] },
    { name: "hakrawler", phase: "discovery", desc: "Simple, fast crawler focused on JS files and endpoints.",
      params: [{ id: "target", label: "Target URL", placeholder: "https://target.com" }] },
    { name: "gau",        phase: "discovery", desc: "Historical URL fetcher from Wayback Machine, OTX, and URLScan.",
      params: [{ id: "target", label: "Target URL", placeholder: "https://target.com" }] },
    { name: "alterx",    phase: "discovery", desc: "Generate subdomain permutations from a list of known subdomains.",
      params: [{ id: "subdomains", label: "Subdomains (comma-separated)", placeholder: "api.example.com, dev.example.com" }] },
    { name: "shuffledns", phase: "discovery", desc: "Mass DNS brute-force using a wordlist and public resolvers.",
      params: [
        { id: "target",    label: "Domain", placeholder: "example.com" },
        { id: "wordlist",  label: "Wordlist path", placeholder: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" },
        { id: "resolvers", label: "Resolvers path", placeholder: "/usr/share/seclists/Miscellaneous/dns-resolvers.txt" },
      ] },
    { name: "urlfinder", phase: "discovery", desc: "Extract URLs from JS files and HTML responses.",
      params: [{ id: "target", label: "Target URL", placeholder: "https://target.com" }] },
    // Scanning
    { name: "nuclei",    phase: "scanning",  desc: "Template-based vulnerability scanner with 9000+ templates.",
      params: [{ id: "target", label: "Target URL", placeholder: "https://target.com" }] },
    { name: "ffuf",      phase: "scanning",  desc: "Fast web fuzzer — probe for exposed paths, configs and files.",
      params: [
        { id: "target",       label: "Target URL", placeholder: "https://target.com" },
        { id: "full_wordlist", label: "Full wordlist (slow)", type: "checkbox" },
      ] },
    { name: "gitleaks",  phase: "scanning",  desc: "Secret detection in JS files — API keys, tokens, credentials.",
      params: [{ id: "js_url", label: "JS file URL", placeholder: "https://target.com/app.bundle.js" }] },
  ];

  let toolAvailability = {};   // tool name -> bool
  const toolRunIds = {};       // tool name -> current run_id (or null)
  const SEV_COLORS = {
    critical: "#ff4d4d",
    high: "#f97316",
    medium: "#eab308",
    low: "#3b82f6",
    info: "#6b7280",
  };

  const recon = { waf: null, ports: [], technologies: [], subdomains: [] };

  // ── WebSocket ──────────────────────────────────────────────────────────────

  function connect() {
    if (
      ws &&
      (ws.readyState === WebSocket.OPEN ||
        ws.readyState === WebSocket.CONNECTING)
    )
      return;

    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.onopen = () => {
      setConnStatus(true);
      clearTimeout(reconnectTimer);
      pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN)
          ws.send(JSON.stringify({ type: "ping" }));
      }, 20000);
    };

    ws.onclose = () => {
      setConnStatus(false);
      clearInterval(pingInterval);
      reconnectTimer = setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        handleMessage(msg);
      } catch (_) {}
    };
  }

  function send(obj) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  }

  // ── Message Handler ────────────────────────────────────────────────────────

  function handleMessage(msg) {
    const { type, data } = msg;

    switch (type) {
      case "scan_queued":
      case "scan_started":
        currentScanId = data.scan_id;
        scanRunning = true;
        setScanRunning(true);
        setStatus("Running", data.target);
        clearTerminal();
        log("info", `[HAST] Scan started → ${data.target} (${data.profile})`);
        log("info", `[HAST] Scan ID: ${data.scan_id}`);
        break;

      case "phase_update":
        updatePhase(data.phase, data.status, data.data);
        if (data.phase === "discovery" && data.data) {
          if (data.data.urls_count !== undefined)
            document.getElementById("stat-urls").textContent =
              data.data.urls_count;
          if (data.data.js_urls_count !== undefined)
            document.getElementById("stat-js").textContent =
              data.data.js_urls_count;
        }
        break;

      case "tool_status":
        updateToolStatus(data.tool, data.status, data.message);
        break;

      case "log":
        log(data.stream, data.data, data.tool);
        break;

      case "finding":
        onFinding(data.finding);
        break;

      case "waf_detected":
        onWafDetected(data);
        break;

      case "scan_complete":
        onScanComplete(data);
        break;

      case "scan_stopped":
        scanRunning = false;
        setScanRunning(false);
        setStatus("Stopped");
        log("warning", `[HAST] Scan stopped.`);
        break;

      case "scan_error":
        scanRunning = false;
        setScanRunning(false);
        setStatus("Error");
        log("error", `[HAST] Error: ${data.error}`);
        break;

      case "tool_run_started":
        onToolRunStarted(data.tool, data.run_id);
        break;

      case "tool_run_done":
        onToolRunDone(data.tool, data.run_id);
        break;

      case "subdomains_found":
        recon.subdomains = data.subdomains || [];
        renderSubdomains();
        break;

      case "pong":
        break;
    }
  }

  // ── Scan Control ───────────────────────────────────────────────────────────

  function startScan() {
    const target = document.getElementById("target-input").value.trim();
    const profile = document.getElementById("profile-select").value;
    const parallel = document.getElementById("parallel-toggle").checked;

    if (!target) {
      alert("Please enter a target URL.");
      return;
    }

    // Reset UI
    allFindings = [];
    filteredFindings = [];
    expandedRows.clear();
    recon.waf = null;
    recon.ports = [];
    recon.technologies = [];
    recon.subdomains = [];
    resetPhases();
    resetCounts();
    renderFindings();
    renderRecon();
    clearDiff();

    document.getElementById("waf-badge").className = "waf-badge";
    document.getElementById("waf-badge").textContent = "";
    document.getElementById("waf-status-text").textContent = "Checking...";
    document.getElementById("new-findings-badge").style.display = "none";

    send({ type: "start_scan", target, profile, parallel });
  }

  function stopScan() {
    if (currentScanId) {
      send({ type: "stop_scan", scan_id: currentScanId });
    }
  }

  // ── Findings ───────────────────────────────────────────────────────────────

  function onFinding(f) {
    allFindings.push(f);
    updateCounts();
    applyFilters();

    // Add to JS secrets tab if from JS scanning
    if (
      f.tool === "regex-secret-scan" ||
      f.tool === "gitleaks" ||
      f.tool === "trufflehog"
    ) {
      appendJsSecretRow(f);
    }

    // Scroll findings into view if critical/high
    if (f.severity === "critical" || f.severity === "high") {
      log(
        "finding",
        `[${f.tool.toUpperCase()}] ${f.severity.toUpperCase()}: ${f.name} @ ${f.url}`,
      );
    }
  }

  function updateCounts() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let newCount = 0;
    allFindings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      if (f.is_new) newCount++;
    });
    for (const [sev, n] of Object.entries(counts)) {
      const el = document.getElementById(`count-${sev}`);
      if (el) el.textContent = n;
    }
    if (newCount > 0) {
      document.getElementById("new-findings-badge").style.display = "flex";
      document.getElementById("new-count").textContent = newCount;
    }
  }

  function resetCounts() {
    ["critical", "high", "medium", "low", "info"].forEach(
      (s) => (document.getElementById(`count-${s}`).textContent = "0"),
    );
    document.getElementById("new-findings-badge").style.display = "none";
    document.getElementById("stat-urls").textContent = "—";
    document.getElementById("stat-js").textContent = "—";
  }

  function applyFilters() {
    const kw = document.getElementById("filter-keyword").value.toLowerCase();
    const sev = document.getElementById("filter-severity").value;
    const tool = document.getElementById("filter-tool").value;

    filteredFindings = allFindings.filter((f) => {
      if (sev && f.severity !== sev) return false;
      if (tool && f.tool !== tool) return false;
      if (kw && !`${f.name} ${f.url} ${f.evidence}`.toLowerCase().includes(kw))
        return false;
      return true;
    });

    renderFindings();
  }

  function filterBySeverity(sev) {
    document.getElementById("filter-severity").value = sev;
    showTab("findings");
    applyFilters();
  }

  function renderFindings() {
    const tbody = document.getElementById("findings-tbody");

    // Update tool filter options
    const toolSelect = document.getElementById("filter-tool");
    const toolSet = new Set(allFindings.map((f) => f.tool));
    const prevTool = toolSelect.value;
    toolSelect.innerHTML =
      '<option value="">All Tools</option>' +
      [...toolSet]
        .sort()
        .map(
          (t) =>
            `<option value="${t}"${t === prevTool ? " selected" : ""}>${t}</option>`,
        )
        .join("");

    if (filteredFindings.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">${
        allFindings.length > 0
          ? "No findings match current filters."
          : "No findings yet. Run a scan to get started."
      }</td></tr>`;
      return;
    }

    // Sort by risk_score desc
    const sorted = [...filteredFindings].sort(
      (a, b) => (b.risk_score || 0) - (a.risk_score || 0),
    );

    tbody.innerHTML = sorted
      .map((f, i) => {
        const key = f.id || `${f.url}|${f.name}`;
        const isExpanded = expandedRows.has(key);
        return buildFindingRow(f, key, isExpanded, i);
      })
      .join("");
  }

  function buildFindingRow(f, key, expanded, idx) {
    const sevClass = `sev-tag-${f.severity}`;
    const riskColor =
      f.severity === "critical"
        ? "#ff4d4d"
        : f.severity === "high"
          ? "#f97316"
          : f.severity === "medium"
            ? "#eab308"
            : f.severity === "low"
              ? "#3b82f6"
              : "#6b7280";

    const riskPct = Math.min(100, f.risk_score || 0);
    const newBadge = f.is_new ? '<span class="is-new-badge">NEW</span>' : "";
    const urlShort = f.url.length > 60 ? "…" + f.url.slice(-57) : f.url;
    const evidenceSnip = (f.evidence || "").slice(0, 60).replace(/</g, "&lt;");
    const escapedKey = escHtml(key);

    let html = `<tr data-row-key="${escapedKey}" class="${expanded ? "expanded" : ""}">
      <td><span class="sev-tag ${sevClass}">${f.severity.toUpperCase()}</span></td>
      <td><span class="mono" style="font-size:11px;">${escHtml(f.tool)}</span></td>
      <td>${escHtml(f.name)}${newBadge}</td>
      <td class="mono" style="font-size:11px;" title="${escHtml(f.url)}">${escHtml(urlShort)}</td>
      <td>
        <div class="risk-bar-wrap">
          <div class="risk-bar"><div class="risk-bar-fill" style="width:${riskPct}%;background:${riskColor};"></div></div>
          <span style="font-size:11px;color:${riskColor};">${f.risk_score || 0}</span>
        </div>
      </td>
      <td class="mono" style="font-size:10px;color:#8b949e;" title="${escHtml(f.evidence || "")}">${escHtml(evidenceSnip)}</td>
      <td>${f.is_new ? '<span class="is-new-badge">NEW</span>' : '<span style="color:var(--text-muted);font-size:10px;">—</span>'}</td>
    </tr>`;

    if (expanded) {
      html += `<tr class="row-detail">
        <td colspan="7">
          <div class="detail-grid">
            <div class="detail-section">
              <label>URL</label>
              <p class="mono" style="font-size:11px;word-break:break-all;">${escHtml(f.url)}</p>
            </div>
            <div class="detail-section">
              <label>CVSS</label>
              <p>${f.cvss_score ? f.cvss_score.toFixed(1) : "N/A"}</p>
            </div>
            <div class="detail-section" style="grid-column:1/-1;">
              <label>Evidence</label>
              <div class="evidence-text">${escHtml(f.evidence || "N/A")}</div>
            </div>
            <div class="detail-section" style="grid-column:1/-1;">
              <label>Remediation</label>
              <div class="remediation-text">${escHtml(f.remediation || "N/A")}</div>
            </div>
          </div>
        </td>
      </tr>`;
    }

    return html;
  }

  function toggleRow(key) {
    if (expandedRows.has(key)) expandedRows.delete(key);
    else expandedRows.add(key);
    renderFindings();
  }

  // ── JS Secrets ─────────────────────────────────────────────────────────────

  function appendJsSecretRow(f) {
    const tbody = document.getElementById("js-secrets-tbody");
    // Remove placeholder
    if (tbody.querySelector("td[colspan]")) tbody.innerHTML = "";

    const sevClass = `sev-tag-${f.severity}`;
    const urlShort = f.url.length > 50 ? "…" + f.url.slice(-47) : f.url;
    tbody.insertAdjacentHTML(
      "beforeend",
      `
      <tr>
        <td><span class="sev-tag ${sevClass}">${f.severity.toUpperCase()}</span></td>
        <td>${escHtml(f.name)}</td>
        <td class="mono" style="font-size:10px;" title="${escHtml(f.url)}">${escHtml(urlShort)}</td>
        <td class="mono" style="font-size:10px;color:#e3b341;">${escHtml((f.evidence || "").slice(0, 80))}</td>
        <td style="font-size:11px;color:var(--green);">${escHtml(f.remediation || "")}</td>
      </tr>
    `,
    );
  }

  // ── Recon ──────────────────────────────────────────────────────────────────

  function onWafDetected(data) {
    recon.waf = data;
    const badge = document.getElementById("waf-badge");
    const statusText = document.getElementById("waf-status-text");

    if (data.detected) {
      badge.className = "detected";
      badge.textContent = `WAF: ${data.name || "Detected"}`;
      statusText.textContent = `Detected: ${data.name || "Unknown"}`;
      statusText.style.color = "var(--orange)";
      log(
        "warning",
        `[wafw00f] WAF detected: ${data.name || "unknown"} — rate limits increased`,
      );
    } else {
      badge.className = "clean";
      badge.textContent = "No WAF";
      statusText.textContent = "No WAF detected";
      statusText.style.color = "var(--green)";
    }
    renderRecon();
  }

  function renderRecon() {
    // WAF
    const wafEl = document.getElementById("recon-waf");
    if (recon.waf) {
      if (recon.waf.detected) {
        wafEl.innerHTML = `<span style="color:var(--orange);">⚠ ${escHtml(recon.waf.name || "Unknown WAF")}</span>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Aggressiveness reduced</div>`;
      } else {
        wafEl.innerHTML = `<span style="color:var(--green);">✓ No WAF detected</span>`;
      }
    } else {
      wafEl.textContent = "—";
    }

    // Ports — parse from finding name/evidence (raw field is not persisted to DB)
    const portFindings = allFindings.filter(
      (f) => f.tool === "nmap" && f.name.startsWith("Open Port:")
    );
    const tbody = document.getElementById("port-tbody");
    if (portFindings.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="4" class="text-muted" style="font-size:11px;">No port data</td></tr>';
    } else {
      tbody.innerHTML = portFindings
        .map((f) => {
          // name: "Open Port: 80/tcp (http)"
          const nm = f.name.match(/Open Port: (\w+)\/(tcp|udp) \(([^)]+)\)/);
          const port    = nm ? nm[1] : "?";
          const proto   = nm ? nm[2] : "tcp";
          const service = nm ? nm[3] : "";
          // evidence: "Port 80/tcp open — Apache httpd 2.4.50"
          const version = (f.evidence || "").replace(/^Port \S+ open — /, "").replace(/^Port \S+ open$/, "");
          const sevColor =
            f.severity === "high"
              ? "var(--sev-high)"
              : f.severity === "medium"
                ? "var(--sev-medium)"
                : "var(--text-secondary)";
          return `<tr>
          <td style="color:${sevColor};font-family:var(--font-mono);">${escHtml(port)}</td>
          <td style="color:var(--text-muted);">${escHtml(proto)}</td>
          <td>${escHtml(service)}</td>
          <td style="color:var(--text-muted);font-size:10px;">${escHtml(version)}</td>
        </tr>`;
        })
        .join("");
    }

    // Tech stack
    const techFindings = allFindings.filter(
      (f) => f.tool === "whatweb" && f.name.includes("Fingerprint"),
    );
    const techEl = document.getElementById("tech-stack");
    if (techFindings.length > 0) {
      const f = techFindings[0];
      const techs = (f.evidence || "").split(", ");
      techEl.innerHTML = techs
        .map((t) => `<span class="tech-tag">${escHtml(t)}</span>`)
        .join("");
    } else {
      techEl.textContent = "—";
    }

    renderSubdomains();
  }

  function renderSubdomains() {
    const listEl = document.getElementById("subdomain-list");
    const countEl = document.getElementById("subdomain-count");
    if (!listEl) return;
    const subs = recon.subdomains || [];
    if (subs.length === 0) {
      listEl.textContent = "—";
      if (countEl) countEl.textContent = "";
      return;
    }
    if (countEl) countEl.textContent = `(${subs.length})`;
    listEl.innerHTML = subs
      .map((s) => `<span class="subdomain-tag">${escHtml(s)}</span>`)
      .join("");
  }

  // ── Scan Complete ──────────────────────────────────────────────────────────

  function onScanComplete(data) {
    scanRunning = false;
    setScanRunning(false);
    setStatus("Complete");
    log(
      "info",
      `[HAST] Scan complete. Total findings: ${data.stats?.total || allFindings.length}`,
    );
    updatePhase("aggregation", "completed");

    // Load full findings list from API for accuracy
    if (currentScanId) {
      loadScanFindings(currentScanId);
      loadScanDiff(currentScanId);
    }
  }

  async function loadScanFindings(scanId) {
    try {
      const safeScanId = normalizeScanId(scanId);
      if (!safeScanId) return;
      const resp = await fetch(
        `/api/scans/${encodeURIComponent(safeScanId)}/findings`,
      );
      const data = await resp.json();
      if (data.findings) {
        allFindings = data.findings;
        updateCounts();
        applyFilters();
        renderRecon();
      }
    } catch (_) {}
  }

  async function loadScanDiff(scanId) {
    try {
      const safeScanId = normalizeScanId(scanId);
      if (!safeScanId) return;
      const resp = await fetch(
        `/api/scans/${encodeURIComponent(safeScanId)}/diff`,
      );
      const data = await resp.json();
      renderDiff(data);
    } catch (_) {}
  }

  // ── Diff ───────────────────────────────────────────────────────────────────

  function renderDiff(data) {
    const el = document.getElementById("diff-content");
    if (!data || (!data.new?.length && !data.resolved?.length)) {
      el.innerHTML =
        '<div class="empty-state">No diff available (first scan for this target, or no previous scan).</div>';
      return;
    }

    const renderSection = (title, items, cssClass, color) => {
      if (!items.length) return "";
      return `<div class="diff-section ${cssClass}">
        <h4 style="color:${color};">${title} (${items.length})</h4>
        ${items
          .slice(0, 50)
          .map(
            (f) => `
          <div style="padding:4px 0; border-bottom:1px solid var(--border-subtle);">
            <span class="sev-tag sev-tag-${f.severity}" style="margin-right:6px;">${f.severity.toUpperCase()}</span>
            <span style="font-size:11px;">${escHtml(f.name)}</span>
            <span style="font-size:10px;color:var(--text-muted);margin-left:8px;">${escHtml(f.url.slice(-60))}</span>
          </div>
        `,
          )
          .join("")}
      </div>`;
    };

    el.innerHTML = `
      ${data.previous_scan_date ? `<div style="font-size:11px;color:var(--text-muted);margin-bottom:12px;">Compared to scan on ${data.previous_scan_date.slice(0, 19)}</div>` : ""}
      ${renderSection(`▲ New Findings`, data.new || [], "diff-new", "var(--red)")}
      ${renderSection(`▼ Resolved`, data.resolved || [], "diff-resolved", "var(--green)")}
      ${renderSection(`= Unchanged`, data.unchanged || [], "diff-unchanged", "var(--text-muted)")}
    `;
  }

  function clearDiff() {
    document.getElementById("diff-content").innerHTML =
      '<div class="empty-state">Run multiple scans on the same target to see diff.</div>';
  }

  // ── Export ─────────────────────────────────────────────────────────────────

  function exportData(format) {
    const safeScanId = normalizeScanId(currentScanId);
    const safeFormat = normalizeExportFormat(format);
    if (!safeScanId) {
      alert("No scan selected.");
      return;
    }
    if (!safeFormat) {
      alert("Unsupported export format.");
      return;
    }
    window.open(
      `/api/scans/${encodeURIComponent(safeScanId)}/export/${safeFormat}`,
      "_blank",
      "noopener",
    );
  }

  // ── Config ─────────────────────────────────────────────────────────────────

  async function loadConfig() {
    try {
      const resp = await fetch("/api/config");
      const cfg = await resp.json();
      document.getElementById("cfg-nuclei-templates").value =
        cfg.nuclei_templates_path || "";
      document.getElementById("cfg-seclists").value = cfg.seclists_path || "";
      document.getElementById("cfg-rate-limit").value =
        cfg.rate_limit_ms || 150;
      document.getElementById("cfg-waf-rate-limit").value =
        cfg.waf_rate_limit_ms || 500;
      document.getElementById("cfg-default-profile").value =
        cfg.default_profile || "standard";
      document.getElementById("cfg-respect-robots").checked =
        cfg.respect_robots !== false;
      document.getElementById("profile-select").value =
        cfg.default_profile || "standard";
    } catch (_) {}
  }

  async function saveConfig() {
    const cfg = {
      nuclei_templates_path: document.getElementById("cfg-nuclei-templates")
        .value,
      seclists_path: document.getElementById("cfg-seclists").value,
      rate_limit_ms: parseInt(document.getElementById("cfg-rate-limit").value),
      waf_rate_limit_ms: parseInt(
        document.getElementById("cfg-waf-rate-limit").value,
      ),
      default_profile: document.getElementById("cfg-default-profile").value,
      respect_robots: document.getElementById("cfg-respect-robots").checked,
    };
    try {
      const resp = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cfg),
      });
      if (resp.ok) {
        log("info", "[config] Settings saved.");
      }
    } catch (_) {}
  }

  async function loadToolStatus() {
    try {
      const resp = await fetch("/api/tools/status");
      const data = await resp.json();
      const el = document.getElementById("tool-status-list");
      el.innerHTML = Object.entries(data.tools)
        .map(([name, info]) => {
          const icon = info.available ? "✓" : "✗";
          const color = info.available ? "var(--green)" : "var(--red)";
          const path = info.available ? info.path : "not found";
          return `<div style="color:${color};">${icon} <span style="color:var(--text-primary);">${name}</span> <span style="color:var(--text-muted);font-size:10px;">${path}</span></div>`;
        })
        .join("");
    } catch (_) {}
  }

  // ── History ────────────────────────────────────────────────────────────────

  async function loadHistory() {
    try {
      const resp = await fetch("/api/scans");
      const data = await resp.json();
      renderHistoryMenu(data.scans || []);
    } catch (_) {}
  }

  function renderHistoryMenu(scans) {
    const menu = document.getElementById("history-menu");
    if (scans.length === 0) {
      menu.innerHTML =
        '<div class="history-item text-muted">No scan history</div>';
      return;
    }
    menu.innerHTML = scans
      .map((s) => {
        const stats = (() => {
          try {
            return JSON.parse(s.stats || "{}");
          } catch (_) {
            return {};
          }
        })();
        const date = (s.started_at || "").slice(0, 16).replace("T", " ");
        return `<div class="history-item">
        <div class="history-item-body" data-history-scan-id="${escHtml(s.id)}">
          <div class="history-target">${escHtml(s.target)}</div>
          <div class="history-meta">${date} · ${s.profile} · ${s.status}
            ${stats.critical ? ` · <span style="color:var(--sev-critical);">${stats.critical}C</span>` : ""}
            ${stats.high ? ` <span style="color:var(--sev-high);">${stats.high}H</span>` : ""}
          </div>
        </div>
        <button class="history-delete-btn" title="Delete scan"
          data-delete-scan-id="${escHtml(s.id)}">✕</button>
      </div>`;
      })
      .join("");
  }

  function toggleHistory() {
    const menu = document.getElementById("history-menu");
    if (menu.classList.contains("open")) {
      menu.classList.remove("open");
    } else {
      loadHistory();
      menu.classList.add("open");
    }
  }

  async function deleteScan(scanId) {
    try {
      const safeScanId = normalizeScanId(scanId);
      if (!safeScanId) return;
      const resp = await fetch(`/api/scans/${encodeURIComponent(safeScanId)}`, {
        method: "DELETE",
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        alert(err.detail || "Could not delete scan");
        return;
      }
      loadHistory();
    } catch (_) {}
  }

  async function loadHistoryScan(scanId) {
    document.getElementById("history-menu").classList.remove("open");
    const safeScanId = normalizeScanId(scanId);
    if (!safeScanId) return;
    currentScanId = safeScanId;

    const resp = await fetch(`/api/scans/${encodeURIComponent(safeScanId)}`);
    const scan = await resp.json();

    document.getElementById("target-input").value = scan.target;
    document.getElementById("profile-select").value = scan.profile;
    setStatus(scan.status, scan.target);

    // Reset all phase badges and recon state for the new scan
    resetPhases();
    recon.waf = null;
    recon.ports = [];
    recon.technologies = [];

    // Restore WAF status from scan record
    const wafDetected = Boolean(scan.waf_detected);
    const wafName = scan.waf_name || "";
    onWafDetected({ detected: wafDetected, name: wafName, message: "" });

    // Mark all phases as completed (this is a finished historical scan)
    if (scan.status === "completed") {
      ["recon", "discovery", "scanning", "aggregation"].forEach((p) =>
        updatePhase(p, "completed"),
      );
    }

    allFindings = [];
    recon.subdomains = [];
    resetCounts();
    await loadScanFindings(safeScanId);
    await loadScanDiff(safeScanId);
    // Load subdomains for this historical scan
    try {
      const subResp = await fetch(`/api/scans/${encodeURIComponent(safeScanId)}/subdomains`);
      if (subResp.ok) {
        const subData = await subResp.json();
        recon.subdomains = subData.subdomains || [];
        renderSubdomains();
      }
    } catch (_) {}
    showTab("findings");
  }

  // ── Terminal ───────────────────────────────────────────────────────────────

  const MAX_LOG_LINES = 5000;
  let logLineCount = 0;

  function log(stream, text, tool) {
    if (!text) return;
    const out = document.getElementById("terminal-output");

    // Remove placeholder
    const placeholder = out.querySelector(".terminal-placeholder");
    if (placeholder) placeholder.remove();

    // Trim old lines
    if (logLineCount > MAX_LOG_LINES) {
      const lines = out.querySelectorAll(".log-line");
      for (let i = 0; i < 500 && lines[i]; i++) lines[i].remove();
      logLineCount -= 500;
    }

    const span = document.createElement("span");
    span.className = `log-line log-${stream}`;
    // Simple ANSI stripping for display
    const clean = text.replace(/\x1b\[[0-9;]*m/g, "");
    span.textContent = clean;
    out.appendChild(span);
    out.appendChild(document.createTextNode("\n"));
    logLineCount++;

    if (document.getElementById("autoscroll").checked) {
      const wrap = document.getElementById("terminal-wrap");
      wrap.scrollTop = wrap.scrollHeight;
    }
  }

  function clearTerminal() {
    const out = document.getElementById("terminal-output");
    out.innerHTML = "";
    logLineCount = 0;
  }

  // ── Phase / Tool Status ────────────────────────────────────────────────────

  const PHASE_BADGE_MAP = {
    running: "badge-running",
    completed: "badge-done",
    failed: "badge-failed",
    idle: "badge-idle",
  };
  const PHASE_TEXT = {
    running: "running",
    completed: "done",
    failed: "failed",
    idle: "idle",
  };

  function updatePhase(phase, status, data) {
    const badge = document.getElementById(`badge-${phase}`);
    if (!badge) return;
    badge.className = `phase-status-badge ${PHASE_BADGE_MAP[status] || "badge-idle"}`;
    badge.textContent = PHASE_TEXT[status] || status;
  }

  function updateToolStatus(tool, status, message) {
    const row = document.getElementById(`tool-${tool}`);
    if (!row) return;
    const dot = row.querySelector(".tool-dot");
    if (dot) {
      dot.className = `tool-dot dot-${status}`;
    }
    if (message) {
      let msgEl = row.querySelector(".tool-status-msg");
      if (!msgEl) {
        msgEl = document.createElement("span");
        msgEl.className = "tool-status-msg";
        row.appendChild(msgEl);
      }
      msgEl.textContent = message;
    }
    if (status === "skipped") {
      row.style.opacity = "0.5";
    }
  }

  function resetPhases() {
    ["recon", "discovery", "scanning", "aggregation"].forEach((p) =>
      updatePhase(p, "idle"),
    );
    document.querySelectorAll(".tool-dot").forEach((d) => {
      d.className = "tool-dot dot-queued";
    });
    document.querySelectorAll(".tool-status-msg").forEach((m) => m.remove());
    document
      .querySelectorAll(".tool-row")
      .forEach((r) => (r.style.opacity = "1"));
  }

  // ── Tabs ───────────────────────────────────────────────────────────────────

  function showTab(tab) {
    document
      .querySelectorAll(".tab-btn")
      .forEach((b) => b.classList.remove("active"));
    document
      .querySelectorAll(".tab-pane")
      .forEach((p) => p.classList.remove("active"));
    document.getElementById(`tab-${tab}`).classList.add("active");
    document.getElementById(`pane-${tab}`).classList.add("active");
    if (tab === "config") loadToolStatus();
    if (tab === "tools")  loadToolsTab();
  }

  // ── UI Helpers ─────────────────────────────────────────────────────────────

  function setScanRunning(running) {
    document.getElementById("scan-btn").disabled = running;
    document.getElementById("stop-btn").disabled = !running;
  }

  function setStatus(status, target) {
    document.getElementById("scan-status-text").textContent = status;
    if (target) {
      document.getElementById("scan-target-text").textContent = target;
    }
  }

  function setConnStatus(connected) {
    const el = document.getElementById("conn-status");
    el.classList.toggle("connected", connected);
    el.title = connected
      ? "WebSocket connected"
      : "WebSocket disconnected (reconnecting...)";
  }

  function escHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function normalizeScanId(scanId) {
    const value = String(scanId || "").trim();
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
      value,
    )
      ? value
      : null;
  }

  function normalizeExportFormat(format) {
    const value = String(format || "")
      .trim()
      .toLowerCase();
    return ["json", "csv", "pdf"].includes(value) ? value : null;
  }

  // ── Profile Tooltip ────────────────────────────────────────────────────────

  const PROFILE_DESCRIPTIONS = {
    quick:    "Recon + nuclei + ffuf only. No crawling. Fast.",
    standard: "Full scan — subdomains, crawl, nuclei, secrets.",
    deep:     "Everything + brute-force DNS, all crawlers. Slow but thorough.",
  };

  function onProfileChange(profile) {
    const el = document.getElementById("profile-tooltip");
    if (!el) return;
    el.textContent = PROFILE_DESCRIPTIONS[profile] || "";
  }

  // ── Resize Handle ──────────────────────────────────────────────────────────

  function initResize() {
    const handle = document.getElementById("resize-handle");
    const bottom = document.getElementById("bottom-area");
    let dragging = false;
    let startY, startH;

    handle.addEventListener("mousedown", (e) => {
      dragging = true;
      startY = e.clientY;
      startH = bottom.offsetHeight;
      document.body.style.userSelect = "none";
    });
    document.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      const delta = startY - e.clientY;
      const newH = Math.max(
        100,
        Math.min(window.innerHeight * 0.7, startH + delta),
      );
      bottom.style.height = newH + "px";
    });
    document.addEventListener("mouseup", () => {
      dragging = false;
      document.body.style.userSelect = "";
    });
  }

  // ── Tools Tab ──────────────────────────────────────────────────────────────

  async function loadToolsTab() {
    try {
      const resp = await fetch("/api/tools/status");
      const data = await resp.json();
      toolAvailability = {};
      for (const [name, info] of Object.entries(data.tools)) {
        toolAvailability[name] = info.available;
      }
    } catch (_) {}
    renderToolCards("all");
  }

  function renderToolCards(phaseFilter) {
    const grid = document.getElementById("tool-cards-grid");
    const currentTarget = document.getElementById("target-input").value.trim();
    const tools = phaseFilter === "all"
      ? TOOLS_CATALOG
      : TOOLS_CATALOG.filter((t) => t.phase === phaseFilter);

    grid.innerHTML = tools.map((t) => {
      const available = toolAvailability[t.name] !== false;
      const runId = toolRunIds[t.name] || null;
      const isRunning = !!runId;

      const paramsHtml = t.params.map((p) => {
        if (p.type === "checkbox") {
          return `<label class="tool-param-group" style="flex-direction:row;align-items:center;gap:6px;cursor:pointer;">
            <input type="checkbox" data-param="${escHtml(p.id)}" style="cursor:pointer;">
            <span class="tool-param-label" style="text-transform:none;font-size:11px;">${escHtml(p.label)}</span>
          </label>`;
        }
        const val = (p.id === "target" || p.id === "targets" || p.id === "hosts" || p.id === "js_url")
          ? currentTarget : (p.placeholder || "");
        return `<div class="tool-param-group">
          <span class="tool-param-label">${escHtml(p.label)}</span>
          <input class="tool-param-input" type="text" data-param="${escHtml(p.id)}"
            placeholder="${escHtml(p.placeholder || "")}"
            value="${escHtml(p.id === "top_ports" || p.id === "depth" ? (p.placeholder || "") : (p.id !== "hosts" ? currentTarget : ""))}">
        </div>`;
      }).join("");

      const btnHtml = isRunning
        ? `<button class="btn btn-danger btn-sm" onclick="App.stopToolRun('${escHtml(t.name)}')">■ Stop</button>`
        : `<button class="btn btn-primary btn-sm" ${available ? "" : "disabled title='Tool not installed'"}
             onclick="App.runTool('${escHtml(t.name)}', this.closest('.tool-card'))">▶ Run</button>`;

      return `<div class="tool-card${isRunning ? " tool-running" : ""}" data-tool="${escHtml(t.name)}" data-phase="${escHtml(t.phase)}">
        <div class="tool-card-header">
          <span class="tool-avail-dot${available ? " available" : ""}"></span>
          <span class="tool-card-name">${escHtml(t.name)}</span>
          <span class="tool-phase-badge ${escHtml(t.phase)}">${escHtml(t.phase)}</span>
        </div>
        <div class="tool-card-desc">${escHtml(t.desc)}</div>
        <div class="tool-card-params">${paramsHtml}</div>
        <div class="tool-card-footer">
          ${btnHtml}
          <span class="tool-run-status${isRunning ? " running" : ""}" id="tool-run-status-${escHtml(t.name)}">
            ${isRunning ? "Running…" : (available ? "Ready" : "Not installed")}
          </span>
        </div>
      </div>`;
    }).join("");
  }

  function filterToolCards(phase, btn) {
    document.querySelectorAll(".phase-filter-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    renderToolCards(phase);
  }

  function runTool(toolName, card) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      log("error", "[tools] WebSocket not connected.");
      return;
    }
    const params = {};
    card.querySelectorAll("[data-param]").forEach((el) => {
      const key = el.getAttribute("data-param");
      params[key] = el.type === "checkbox" ? el.checked : el.value.trim();
    });
    // Use main target-input as fallback for target
    if (!params.target && !params.targets && !params.js_url) {
      params.target = document.getElementById("target-input").value.trim();
    }
    send({ type: "run_tool", tool: toolName, params });
    log("info", `[tools] Running ${toolName}…`);
    showTab("findings");
  }

  function stopToolRun(toolName) {
    const runId = toolRunIds[toolName];
    if (runId) {
      send({ type: "stop_tool_run", run_id: runId });
    }
  }

  function onToolRunStarted(toolName, runId) {
    toolRunIds[toolName] = runId;
    const statusEl = document.getElementById(`tool-run-status-${toolName}`);
    if (statusEl) {
      statusEl.textContent = "Running…";
      statusEl.className = "tool-run-status running";
    }
    const card = document.querySelector(`.tool-card[data-tool="${toolName}"]`);
    if (card) card.classList.add("tool-running");
  }

  function onToolRunDone(toolName, runId) {
    if (toolRunIds[toolName] === runId) delete toolRunIds[toolName];
    const statusEl = document.getElementById(`tool-run-status-${toolName}`);
    if (statusEl) {
      statusEl.textContent = "Done";
      statusEl.className = "tool-run-status done";
      setTimeout(() => {
        if (statusEl) { statusEl.textContent = "Ready"; statusEl.className = "tool-run-status"; }
      }, 4000);
    }
    const card = document.querySelector(`.tool-card[data-tool="${toolName}"]`);
    if (card) {
      card.classList.remove("tool-running");
      // Swap Stop back to Run button
      const footer = card.querySelector(".tool-card-footer");
      if (footer) {
        const btn = footer.querySelector("button");
        if (btn && btn.textContent.includes("Stop")) {
          const avail = toolAvailability[toolName] !== false;
          btn.className = "btn btn-primary btn-sm";
          btn.disabled = !avail;
          btn.textContent = "▶ Run";
          btn.setAttribute("onclick", `App.runTool('${toolName}', this.closest('.tool-card'))`);
        }
      }
    }
  }

  // ── Bulk Scan ──────────────────────────────────────────────────────────────

  async function openBulkScan() {
    document.getElementById("bulk-modal").style.display = "flex";
    document.getElementById("bulk-status").textContent = "";
    document.getElementById("bulk-run-btn").disabled = false;
    // Show real path count from backend
    try {
      const resp = await fetch("/api/probe-paths/count");
      if (resp.ok) {
        const { count } = await resp.json();
        document.getElementById("bulk-path-count").textContent = count;
      }
    } catch (_) {
      document.getElementById("bulk-path-count").textContent = "200+";
    }
  }

  function closeBulkScan() {
    document.getElementById("bulk-modal").style.display = "none";
  }

  async function runBulkScan() {
    const raw = document.getElementById("bulk-targets").value;
    const profile = document.getElementById("bulk-profile").value;

    const targets = raw
      .split("\n")
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    if (targets.length === 0) {
      document.getElementById("bulk-status").textContent =
        "Enter at least one target.";
      document.getElementById("bulk-status").style.color = "var(--red)";
      return;
    }
    if (targets.length > 50) {
      document.getElementById("bulk-status").textContent =
        "Maximum 50 targets allowed.";
      document.getElementById("bulk-status").style.color = "var(--red)";
      return;
    }

    document.getElementById("bulk-run-btn").disabled = true;
    document.getElementById("bulk-status").style.color = "var(--accent)";
    document.getElementById("bulk-status").textContent =
      `Queueing ${targets.length} targets…`;

    try {
      const resp = await fetch("/api/bulk-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets, profile }),
      });
      const data = await resp.json();

      if (resp.ok) {
        document.getElementById("bulk-status").style.color = "var(--green)";
        document.getElementById("bulk-status").textContent =
          `✓ ${data.queued} scans queued (${profile} profile). Check History to track progress.`;

        // Close after 2 seconds
        setTimeout(closeBulkScan, 2000);
        // Refresh history
        setTimeout(loadHistory, 3000);
      } else {
        throw new Error(data.detail || "Unknown error");
      }
    } catch (err) {
      document.getElementById("bulk-status").style.color = "var(--red)";
      document.getElementById("bulk-status").textContent =
        `Error: ${err.message}`;
      document.getElementById("bulk-run-btn").disabled = false;
    }
  }

  // Close modal on backdrop click
  document.getElementById("bulk-modal").addEventListener("click", (e) => {
    if (e.target === document.getElementById("bulk-modal")) closeBulkScan();
  });

  // ── Click outside to close history ────────────────────────────────────────

  document.addEventListener("click", (e) => {
    const btn = document.getElementById("history-btn");
    const menu = document.getElementById("history-menu");
    if (!btn.contains(e.target) && !menu.contains(e.target)) {
      menu.classList.remove("open");
    }
  });

  // ── Enter key on input ─────────────────────────────────────────────────────

  document.getElementById("target-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") startScan();
  });

  // ── Init ───────────────────────────────────────────────────────────────────

  function init() {
    connect();
    loadConfig();
    initResize();
    onProfileChange(document.getElementById("profile-select").value);

    const findingsTbody = document.getElementById("findings-tbody");
    findingsTbody.addEventListener("click", (e) => {
      const row = e.target.closest("tr[data-row-key]");
      if (!row || !findingsTbody.contains(row)) return;
      const key = row.getAttribute("data-row-key");
      if (key) toggleRow(key);
    });

    const historyMenu = document.getElementById("history-menu");
    historyMenu.addEventListener("click", (e) => {
      const deleteBtn = e.target.closest("[data-delete-scan-id]");
      if (deleteBtn) {
        e.stopPropagation();
        deleteScan(deleteBtn.getAttribute("data-delete-scan-id"));
        return;
      }
      const body = e.target.closest("[data-history-scan-id]");
      if (body) {
        loadHistoryScan(body.getAttribute("data-history-scan-id"));
      }
    });
  }

  init();

  // ── Public API ─────────────────────────────────────────────────────────────

  return {
    startScan,
    stopScan,
    showTab,
    exportData,
    saveConfig,
    applyFilters,
    filterBySeverity,
    toggleRow,
    toggleHistory,
    deleteScan,
    loadHistoryScan,
    clearTerminal,
    openBulkScan,
    closeBulkScan,
    runBulkScan,
    filterToolCards,
    runTool,
    stopToolRun,
    onProfileChange,
  };
})();
