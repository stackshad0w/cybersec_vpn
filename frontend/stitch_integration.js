// Stitch UI Live API Connector for Cyber Wala VPN
(function() {
  let currentAnalysisId = null;

  document.addEventListener("DOMContentLoaded", () => {
    initStitchPage();
  });

  async function initStitchPage() {
    const urlParams = new URLSearchParams(window.location.search);
    const paramId = urlParams.get("id");

    // Fetch initial analysis (either requested ID or demo analysis)
    let analysisData = null;
    try {
      if (paramId) {
        const res = await fetch(`/api/v1/analyses/${paramId}`);
        if (res.ok) analysisData = await res.json();
      }
      if (!analysisData) {
        const res = await fetch("/api/v1/demo/load", { method: "POST" });
        if (res.ok) analysisData = await res.json();
      }
    } catch (e) {
      console.warn("Could not load backend data:", e);
    }

    if (analysisData) {
      currentAnalysisId = analysisData.id;
      bindAnalysisData(analysisData);
    }

    // Setup interactive handlers
    setupUploadHandlers();
    setupReportDownloadHandlers();
    setupDemoButtonHandlers();
  }

  function setupDemoButtonHandlers() {
    // Check for buttons with text containing "demo" or "sample"
    document.querySelectorAll("button, a").forEach(el => {
      const text = (el.textContent || "").toLowerCase();
      if (text.includes("load demo") || text.includes("demo analysis") || text.includes("sample capture")) {
        el.addEventListener("click", async (e) => {
          e.preventDefault();
          try {
            const res = await fetch("/api/v1/demo/load", { method: "POST" });
            if (res.ok) {
              const data = await res.json();
              window.location.href = `/results.html?id=${data.id}`;
            }
          } catch (err) {
            console.error("Demo load failed", err);
          }
        });
      }
    });
  }

  function setupUploadHandlers() {
    // Look for file input or dropzones in analyze.html
    const fileInput = document.querySelector('input[type="file"]') || createHiddenFileInput();
    
    // Wire dropzones
    const dropzones = document.querySelectorAll('[class*="border-dashed"], [id*="drop"], [class*="dropzone"]');
    dropzones.forEach(dz => {
      dz.style.cursor = "pointer";
      dz.addEventListener("click", () => fileInput.click());
      dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.style.borderColor = "#06b6d4"; });
      dz.addEventListener("dragleave", () => { dz.style.borderColor = ""; });
      dz.addEventListener("drop", (e) => {
        e.preventDefault();
        dz.style.borderColor = "";
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          handleFileUpload(e.dataTransfer.files[0]);
        }
      });
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files.length > 0) {
        handleFileUpload(fileInput.files[0]);
      }
    });

    // Wire sample scenario buttons
    document.querySelectorAll("button, a").forEach(el => {
      const text = (el.textContent || "").toLowerCase();
      if (text.includes("secure_ikev2") || text.includes("weak_ikev1") || text.includes("transport_gcm") || text.includes("sample")) {
        el.addEventListener("click", async (e) => {
          e.preventDefault();
          const demoRes = await fetch("/api/v1/demo/load", { method: "POST" });
          if (demoRes.ok) {
            const d = await demoRes.json();
            window.location.href = `/results.html?id=${d.id}`;
          }
        });
      }
    });
  }

  function createHiddenFileInput() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".pcap,.pcapng,.cap";
    input.style.display = "none";
    document.body.appendChild(input);
    return input;
  }

  async function handleFileUpload(file) {
    const banner = showStatusBanner(`Uploading and analyzing ${file.name}...`);
    const formData = new FormData();
    formData.append("file", file);
    formData.append("title", `Analysis - ${file.name}`);
    formData.append("auto_run", "true");

    try {
      const res = await fetch("/api/v1/upload", {
        method: "POST",
        body: formData
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Upload failed");
      }
      const data = await res.json();
      window.location.href = `/results.html?id=${data.id}`;
    } catch (err) {
      alert(`PCAP Validation / Ingestion Error: ${err.message}`);
      if (banner) banner.remove();
    }
  }

  function setupReportDownloadHandlers() {
    document.querySelectorAll("button, a").forEach(el => {
      const text = (el.textContent || "").toLowerCase();
      if (text.includes("executive") || text.includes("exec pdf")) {
        el.addEventListener("click", (e) => {
          e.preventDefault();
          const id = currentAnalysisId || 1;
          window.open(`/api/v1/analyses/${id}/reports/executive.pdf`, "_blank");
        });
      } else if (text.includes("technical") || text.includes("tech pdf")) {
        el.addEventListener("click", (e) => {
          e.preventDefault();
          const id = currentAnalysisId || 1;
          window.open(`/api/v1/analyses/${id}/reports/technical.pdf`, "_blank");
        });
      } else if (text.includes("json export") || text.includes("export json") || text.includes("raw json")) {
        el.addEventListener("click", (e) => {
          e.preventDefault();
          const id = currentAnalysisId || 1;
          window.open(`/api/v1/analyses/${id}/reports/export.json`, "_blank");
        });
      }
    });
  }

  function bindAnalysisData(data) {
    // 1. Update scores
    const scoreVal = Math.round(data.security_score || 82);
    document.querySelectorAll('[class*="mono-metric"], .score-val').forEach(el => {
      if (el.textContent.includes("82") || el.textContent.includes("Score") || el.textContent.includes("/100") || el.id === "score-val") {
        el.textContent = scoreVal;
      }
    });

    // 2. Update Risk badge text
    const riskLvl = (data.risk_level || "Good").toUpperCase();
    document.querySelectorAll('[class*="threat-secure"], [class*="threat-warning"], [class*="threat-high"], [class*="threat-critical"]').forEach(el => {
      if (el.textContent.includes("GOOD") || el.textContent.includes("EXCELLENT") || el.textContent.includes("RISK")) {
        el.textContent = riskLvl;
      }
    });

    // 3. Traffic AI bindings
    const traffic = data.traffic_prediction || {};
    if (traffic.predicted_class) {
      document.querySelectorAll("h1, h2, h3, span, div").forEach(el => {
        if (el.textContent.includes("Video-like") || el.textContent.includes("Traffic Class")) {
          el.textContent = `${traffic.predicted_class} — ${(traffic.confidence_score * 100).toFixed(0)}% Confidence`;
        }
      });
    }

    // 4. Update Analysis ID / Filename tags
    document.querySelectorAll('[class*="mono-data"]').forEach(el => {
      if (el.textContent.includes("ANL-") || el.textContent.includes("ID:")) {
        el.textContent = `ANL-${data.id.toString().padStart(4, "0")}-IPSEC`;
      }
    });
  }

  function showStatusBanner(msg) {
    const banner = document.createElement("div");
    banner.style.position = "fixed";
    banner.style.top = "16px";
    banner.style.right = "16px";
    banner.style.zIndex = "9999";
    banner.style.background = "linear-gradient(135deg, #06b6d4, #2563eb)";
    banner.style.color = "#ffffff";
    banner.style.padding = "12px 20px";
    banner.style.borderRadius = "8px";
    banner.style.fontSize = "13px";
    banner.style.fontWeight = "600";
    banner.style.boxShadow = "0 8px 24px rgba(0,0,0,0.5)";
    banner.textContent = msg;
    document.body.appendChild(banner);
    return banner;
  }
})();
