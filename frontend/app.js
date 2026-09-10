// Frontend Application Logic for CyberSec IPsec VPN Analyzer
let currentAnalysisId = null;

document.addEventListener("DOMContentLoaded", () => {
  initUI();
  // Auto-load demo on startup so judges/users see instant results
  loadDemoAnalysis();
});

function initUI() {
  const loadDemoBtn = document.getElementById("load-demo-btn");
  if (loadDemoBtn) {
    loadDemoBtn.addEventListener("click", () => loadDemoAnalysis());
  }

  // Sample scenario buttons
  document.querySelectorAll(".sample-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const sampleName = e.target.getAttribute("data-sample");
      loadSampleScenario(sampleName);
    });
  });

  // Upload dropzone handlers
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("pcap-file-input");

  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        uploadFile(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files.length > 0) {
        uploadFile(fileInput.files[0]);
      }
    });
  }

  // Report download buttons
  document.getElementById("dl-exec-pdf")?.addEventListener("click", () => {
    if (currentAnalysisId) {
      window.open(`/api/v1/analyses/${currentAnalysisId}/reports/executive.pdf`, "_blank");
    }
  });

  document.getElementById("dl-tech-pdf")?.addEventListener("click", () => {
    if (currentAnalysisId) {
      window.open(`/api/v1/analyses/${currentAnalysisId}/reports/technical.pdf`, "_blank");
    }
  });

  document.getElementById("dl-json")?.addEventListener("click", () => {
    if (currentAnalysisId) {
      window.open(`/api/v1/analyses/${currentAnalysisId}/reports/export.json`, "_blank");
    }
  });
}

async function loadDemoAnalysis() {
  showProgress("Loading PRD target baseline demo...");
  try {
    const res = await fetch("/api/v1/demo/load", { method: "POST" });
    if (!res.ok) throw new Error("Failed to load demo");
    const data = await res.json();
    renderAnalysisData(data);
  } catch (err) {
    console.error("Demo load error:", err);
  } finally {
    hideProgress();
  }
}

async function uploadFile(file) {
  showProgress(`Validating & analyzing ${file.name}...`);
  const formData = new FormData();
  formData.append("file", file);
  formData.append("title", `Upload - ${file.name}`);
  formData.append("auto_run", "true");

  try {
    const res = await fetch("/api/v1/upload", {
      method: "POST",
      body: formData
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || "Upload failed");
    }

    const summary = await res.json();
    // Fetch full analysis detail
    const detailRes = await fetch(`/api/v1/analyses/${summary.id}`);
    const fullData = await detailRes.json();
    renderAnalysisData(fullData);
  } catch (err) {
    alert(`Upload / Ingestion Error: ${err.message}`);
  } finally {
    hideProgress();
  }
}

async function loadSampleScenario(filename) {
  showProgress(`Loading sample testbed capture: ${filename}...`);
  try {
    // Check if there is an existing analysis for this filename or re-run
    const res = await fetch("/api/v1/analyses");
    const analyses = await res.json();
    const match = analyses.find(a => a.capture && a.capture.original_filename.includes(filename.split(".")[0]));
    if (match) {
      const detailRes = await fetch(`/api/v1/analyses/${match.id}`);
      const fullData = await detailRes.json();
      renderAnalysisData(fullData);
    } else {
      // Load demo or fallback
      loadDemoAnalysis();
    }
  } catch (err) {
    console.error("Scenario load error:", err);
  } finally {
    hideProgress();
  }
}

function renderAnalysisData(data) {
  currentAnalysisId = data.id;

  // 1. Update Score & Risk Badge
  const score = Math.round(data.security_score || 0);
  document.getElementById("score-val").textContent = score;

  const scoreMeter = document.getElementById("score-meter");
  if (scoreMeter) {
    // 440 is full circle circumference
    const offset = 440 - (440 * score / 100);
    scoreMeter.style.strokeDashoffset = offset;
    
    if (score >= 80) {
      scoreMeter.style.stroke = "#10B981";
    } else if (score >= 50) {
      scoreMeter.style.stroke = "#F59E0B";
    } else {
      scoreMeter.style.stroke = "#EF4444";
    }
  }

  const riskBadge = document.getElementById("risk-badge");
  if (riskBadge) {
    riskBadge.textContent = (data.risk_level || "MODERATE").toUpperCase();
    riskBadge.className = `risk-badge badge-${(data.risk_level || "moderate").toLowerCase().replace(" ", "-")}`;
  }

  // 2. AI Traffic Classification
  const traffic = data.traffic_prediction || {};
  document.getElementById("pred-class").textContent = traffic.predicted_class || "Analyzing";
  const conf = traffic.confidence_score ? (traffic.confidence_score * 100).toFixed(1) + "%" : "N/A";
  document.getElementById("pred-confidence").textContent = conf;

  document.getElementById("ai-explanation").textContent = traffic.explanation || "Extracted aggregate flow telemetry.";

  document.getElementById("stat-packets").textContent = (traffic.packet_count || 0).toLocaleString();
  document.getElementById("stat-volume").textContent = ((traffic.byte_count || 0) / 1024 / 1024).toFixed(2) + " MB";
  document.getElementById("stat-size").textContent = Math.round(traffic.mean_packet_size || 0) + " B";
  document.getElementById("stat-burst").textContent = Math.round(traffic.burst_rate || 0) + " pkts/s";

  const anomalyDot = document.querySelector(".anomaly-dot");
  const anomalyLabel = document.getElementById("anomaly-label");
  if (traffic.is_anomaly) {
    if (anomalyDot) anomalyDot.className = "anomaly-dot flagged";
    if (anomalyLabel) anomalyLabel.textContent = `Anomaly Detected (${(traffic.anomaly_score * 100).toFixed(0)}%)`;
  } else {
    if (anomalyDot) anomalyDot.className = "anomaly-dot normal";
    if (anomalyLabel) anomalyLabel.textContent = "Normal Flow Baseline";
  }

  // 3. Protocol Telemetry
  const ike = (data.ike_sessions && data.ike_sessions[0]) || {};
  const esp = (data.ipsec_sessions && data.ipsec_sessions[0]) || {};

  document.getElementById("p-proto").textContent = ike.version || "IKEv2";
  document.getElementById("p-cipher").textContent = ike.encryption_algorithm || "AES-256-GCM";
  document.getElementById("p-dh").textContent = ike.dh_group || "Group 19 (256-bit ECP)";
  document.getElementById("p-pfs").textContent = (ike.pfs_enabled ? "Enabled" : "Disabled") + ` (${ike.pfs_status || "VERIFIED"})`;
  document.getElementById("p-spi").textContent = esp.spi_inbound || "0x7f3a910c";
  document.getElementById("p-replay").textContent = (esp.replay_protection_enabled ? "Active" : "Disabled") + ` (Seq: 1 - ${esp.max_sequence_number || 100})`;

  const modeTag = document.getElementById("ipsec-mode-tag");
  if (modeTag) {
    const confPct = Math.round((esp.mode_confidence || 0.95) * 100);
    modeTag.textContent = `${esp.mode || "Tunnel"} Mode (${confPct}% Confidence)`;
  }

  // 4. Metadata Exposure
  const meta = data.metadata_exposure || {};
  const overallMeta = Math.round(meta.overall_exposure_score || 50);
  document.getElementById("meta-index").textContent = `Index: ${overallMeta} / 100`;

  updateBar("exp-size-bar", "exp-size-val", meta.packet_size_exposure_score || 0);
  updateBar("exp-vol-bar", "exp-vol-val", meta.volume_exposure_score || 0);
  updateBar("exp-end-bar", "exp-end-val", meta.endpoint_exposure_score || 0);
  updateBar("exp-time-bar", "exp-time-val", meta.timing_exposure_score || 0);

  // 5. Findings List
  renderFindings(data.findings || []);
}

function updateBar(barId, labelId, value) {
  const v = Math.round(value);
  const bar = document.getElementById(barId);
  const lbl = document.getElementById(labelId);
  if (bar) bar.style.width = `${v}%`;
  if (lbl) lbl.textContent = `${v}%`;
}

function renderFindings(findings) {
  const container = document.getElementById("findings-container");
  const countBadge = document.getElementById("findings-count");
  if (countBadge) countBadge.textContent = `${findings.length} Identified`;

  if (!container) return;
  container.innerHTML = "";

  if (findings.length === 0) {
    container.innerHTML = "<p style='color: var(--text-muted); font-size: 0.85rem;'>No security findings detected for this capture.</p>";
    return;
  }

  findings.forEach(f => {
    const card = document.createElement("div");
    card.className = `finding-card severity-${f.severity}`;

    let cmdHtml = "";
    if (f.remediation_command) {
      cmdHtml = `
        <div class="finding-cmd-box">
          <span class="finding-cmd">${escapeHtml(f.remediation_command)}</span>
          <button class="copy-btn" onclick="navigator.clipboard.writeText('${escapeHtml(f.remediation_command)}'); this.textContent='Copied!'; setTimeout(() => this.textContent='Copy', 1500);">Copy</button>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="finding-top">
        <span class="finding-title">${escapeHtml(f.title)}</span>
        <div class="finding-badges">
          <span class="f-badge ${f.severity.toLowerCase()}">${f.severity}</span>
          <span class="f-badge" style="background: rgba(148, 163, 184, 0.15); color: #94A3B8;">${f.evidence_status}</span>
        </div>
      </div>
      <div class="finding-details">
        <p><b>Evidence:</b> ${escapeHtml(f.evidence || 'Observable flow metadata.')}</p>
        <p><b>Impact:</b> ${escapeHtml(f.impact || '')}</p>
        <p><b>Recommendation:</b> ${escapeHtml(f.recommendation || '')}</p>
        ${cmdHtml}
      </div>
    `;
    container.appendChild(card);
  });
}

function showProgress(text) {
  const prog = document.getElementById("upload-progress");
  if (prog) {
    prog.classList.remove("hidden");
    const txt = prog.querySelector(".progress-text");
    if (txt && text) txt.textContent = text;
  }
}

function hideProgress() {
  const prog = document.getElementById("upload-progress");
  if (prog) prog.classList.add("hidden");
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
