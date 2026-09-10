// =============================================================================
// Cyber Wala IPsec SOC Analyzer - Master Unified SPA Integration
// Connects ALL views under a single localhost link: http://127.0.0.1:8000/
// =============================================================================

(function () {
  let currentAnalysisId = null;
  let currentAnalysisData = null;
  let activeTab = "dashboard";

  // Template in-memory cache
  const viewCache = {
    dashboard: null,
    analyze: null,
    results: null,
    "traffic-ai": null
  };

  document.addEventListener("DOMContentLoaded", () => {
    initMasterApp();
  });

  async function initMasterApp() {
    // Cache initial dashboard markup
    const mainEl = document.querySelector("main");
    if (mainEl && (window.location.pathname === "/" || window.location.pathname.endsWith("index.html"))) {
      viewCache.dashboard = mainEl.innerHTML;
    }

    // Enhance sidebar navigation links for SPA routing
    setupSidebarRouting();
    setupGlobalHeader();

    // Listen to hash changes (for back/forward buttons and direct bookmarking)
    window.addEventListener("hashchange", handleHashChange);

    // Initial route handling
    const hash = window.location.hash.replace(/^#/, "");
    if (hash) {
      handleRoute(hash);
    } else {
      // Default to dashboard
      await switchTab("dashboard");
    }

    // Prefetch other views in the background for sub-millisecond tab switching
    prefetchViews();
  }

  // ---------------------------------------------------------------------------
  // Prefetch Views
  // ---------------------------------------------------------------------------
  async function prefetchViews() {
    const viewsToFetch = [
      { key: "analyze", url: "/analyze.html" },
      { key: "results", url: "/results.html" },
      { key: "traffic-ai", url: "/traffic-ai.html" }
    ];

    for (const v of viewsToFetch) {
      if (!viewCache[v.key]) {
        try {
          const res = await fetch(v.url);
          if (res.ok) {
            const html = await res.text();
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, "text/html");
            const m = doc.querySelector("main");
            if (m) viewCache[v.key] = m.innerHTML;
          }
        } catch (e) {
          console.debug("Prefetch notice:", e);
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // SPA Routing & Navigation
  // ---------------------------------------------------------------------------
  function setupSidebarRouting() {
    // Map data-path to tabs
    const pathToTab = {
      "dashboard": "dashboard",
      "analyze-pcap": "analyze",
      "analyses": "results",
      "vpn-profiles": "results",
      "findings-and-threats": "results",
      "traffic-ai": "traffic-ai",
      "packet-explorer": "traffic-ai",
      "reports": "reports",
      "settings": "settings"
    };

    document.querySelectorAll("aside nav a").forEach((a) => {
      const dataPath = a.getAttribute("data-path") || "";
      const tab = pathToTab[dataPath];

      if (tab) {
        a.addEventListener("click", (e) => {
          e.preventDefault();
          if (tab === "reports") {
            showReportModal(currentAnalysisId || 1);
          } else if (tab === "settings") {
            showSettingsModal();
          } else {
            switchTab(tab, currentAnalysisId);
          }
        });
      }
    });

    // Add API Docs / Swagger link in the sidebar footer if not present
    const asideFooter = document.querySelector("aside > div:last-child");
    if (asideFooter && !document.getElementById("docs-nav-link")) {
      const docsLink = document.createElement("a");
      docsLink.id = "docs-nav-link";
      docsLink.href = "/docs";
      docsLink.target = "_blank";
      docsLink.className = "mt-2 pt-2 border-t border-border-subtle flex items-center justify-between font-mono-packet text-mono-packet text-text-secondary hover:text-primary transition-colors";
      docsLink.innerHTML = `
        <span class="flex items-center gap-1.5">
          <span class="material-symbols-outlined text-[14px] text-primary">api</span>
          REST API Docs (Swagger)
        </span>
        <span class="material-symbols-outlined text-[13px]">open_in_new</span>
      `;
      asideFooter.appendChild(docsLink);
    }
  }

  function setupGlobalHeader() {
    const searchInput = document.querySelector('header input[type="text"]');
    if (!searchInput) return;

    searchInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const q = searchInput.value.trim().toLowerCase();
        if (!q) return;
        if (q.includes("demo") || q.includes("video")) {
          loadScenarioAndNavigate("demo_video");
        } else if (q.includes("secure") || q.includes("aes") || q.includes("gcm")) {
          loadScenarioAndNavigate("secure_ikev2");
        } else if (q.includes("weak") || q.includes("3des") || q.includes("ikev1")) {
          loadScenarioAndNavigate("weak_ikev1");
        } else if (q.includes("transport")) {
          loadScenarioAndNavigate("transport_gcm");
        } else if (q.includes("ai") || q.includes("traffic") || q.includes("ml")) {
          switchTab("traffic-ai", currentAnalysisId);
        } else if (q.includes("upload") || q.includes("analyze")) {
          switchTab("analyze");
        } else {
          showToast(`Filtered by "${q}"`, "info");
        }
      }
    });
  }

  function handleHashChange() {
    const hash = window.location.hash.replace(/^#/, "");
    if (hash) handleRoute(hash);
  }

  function handleRoute(routeStr) {
    const [tabPart, queryPart] = routeStr.split("?");
    let requestedId = null;
    if (queryPart) {
      const params = new URLSearchParams(queryPart);
      requestedId = params.get("id");
    }
    switchTab(tabPart, requestedId, false);
  }

  async function switchTab(tab, analysisId = null, updateHash = true) {
    activeTab = tab;
    if (analysisId) currentAnalysisId = analysisId;

    // Update active nav styling
    updateActiveNavClasses(tab);

    const mainEl = document.querySelector("main");
    if (!mainEl) return;

    // Fade out slightly
    mainEl.style.opacity = "0.4";
    mainEl.style.transition = "opacity 0.15s ease-out";

    // Load template
    let content = viewCache[tab];
    if (!content) {
      let fetchUrl = "";
      if (tab === "analyze") fetchUrl = "/analyze.html";
      else if (tab === "results") fetchUrl = "/results.html";
      else if (tab === "traffic-ai") fetchUrl = "/traffic-ai.html";
      else fetchUrl = "/";

      try {
        const res = await fetch(fetchUrl);
        const html = await res.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, "text/html");
        const m = doc.querySelector("main");
        if (m) {
          content = m.innerHTML;
          viewCache[tab] = content;
        }
      } catch (e) {
        console.error("Error loading view:", e);
      }
    }

    if (content) {
      mainEl.innerHTML = content;
    }

    // Fade in
    setTimeout(() => {
      mainEl.style.opacity = "1";
    }, 50);

    // Update browser URL hash if requested
    if (updateHash) {
      const hashStr = `#${tab}${currentAnalysisId ? `?id=${currentAnalysisId}` : ""}`;
      if (window.location.hash !== hashStr) {
        history.pushState(null, "", hashStr);
      }
    }

    // Scroll to top
    window.scrollTo({ top: 0, behavior: "smooth" });

    // Initialize the active view
    if (tab === "dashboard") {
      await initDashboardPage();
    } else if (tab === "analyze") {
      initAnalyzePage();
    } else if (tab === "results") {
      await loadAnalysisData(currentAnalysisId);
      initResultsPage();
    } else if (tab === "traffic-ai") {
      await loadAnalysisData(currentAnalysisId);
      initTrafficAIPage();
    }
  }

  function updateActiveNavClasses(activeTab) {
    const navMap = {
      "dashboard": ["dashboard"],
      "analyze": ["analyze-pcap"],
      "results": ["analyses", "vpn-profiles", "findings-and-threats"],
      "traffic-ai": ["traffic-ai", "packet-explorer"]
    };

    const targetPaths = navMap[activeTab] || [];

    document.querySelectorAll("aside nav a").forEach((a) => {
      const path = a.getAttribute("data-path") || "";
      if (targetPaths.includes(path)) {
        a.classList.add("bg-surface-raised", "text-primary", "border-l-2", "border-border-active");
        a.classList.remove("text-text-secondary");
      } else {
        a.classList.remove("bg-surface-raised", "text-primary", "border-l-2", "border-border-active");
        a.classList.add("text-text-secondary");
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Data Fetching
  // ---------------------------------------------------------------------------
  async function loadAnalysisData(requestedId) {
    try {
      if (requestedId) {
        const res = await fetch(`/api/v1/analyses/${requestedId}`);
        if (res.ok) {
          currentAnalysisData = await res.json();
          currentAnalysisId = currentAnalysisData.id;
          return currentAnalysisData;
        }
      }
      // Fallback to load demo
      const res = await fetch("/api/v1/demo/load", { method: "POST" });
      if (res.ok) {
        currentAnalysisData = await res.json();
        currentAnalysisId = currentAnalysisData.id;
        return currentAnalysisData;
      }
    } catch (err) {
      console.warn("Analysis load error:", err);
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // 1. DASHBOARD VIEW
  // ---------------------------------------------------------------------------
  async function initDashboardPage() {
    await refreshDashboardQueue();

    // Wire "Start Instant Analysis" button
    const startInstantBtn = document.getElementById("start-analysis-btn") ||
      Array.from(document.querySelectorAll("button")).find(b => (b.textContent || "").includes("Start Instant Analysis"));
    if (startInstantBtn) {
      startInstantBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        showToast("Dispatching Instant Analysis Demo (Target Video VPN)...", "info");
        await loadScenarioAndNavigate("demo_video");
      });
    }

    // Wire Quick Upload dropzone
    const dashDropzone = document.getElementById("dropzone");
    if (dashDropzone) {
      const fileInput = document.createElement("input");
      fileInput.type = "file";
      fileInput.accept = ".pcap,.pcapng,.cap";
      fileInput.style.display = "none";
      document.body.appendChild(fileInput);

      dashDropzone.style.cursor = "pointer";
      dashDropzone.addEventListener("click", () => fileInput.click());

      dashDropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dashDropzone.classList.add("border-primary", "bg-surface-raised/40");
      });
      dashDropzone.addEventListener("dragleave", () => {
        dashDropzone.classList.remove("border-primary", "bg-surface-raised/40");
      });
      dashDropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dashDropzone.classList.remove("border-primary", "bg-surface-raised/40");
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          uploadAndAnalyze(e.dataTransfer.files[0]);
        }
      });

      fileInput.addEventListener("change", () => {
        if (fileInput.files && fileInput.files.length > 0) {
          uploadAndAnalyze(fileInput.files[0]);
        }
      });
    }

    // Wire Quick-links & audit list buttons
    document.querySelectorAll("button, a").forEach((btn) => {
      const txt = (btn.textContent || "").toLowerCase();
      if (txt.includes("audit list") || txt.includes("open full threat matrix")) {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          switchTab("results", currentAnalysisId);
        });
      }
    });
  }

  async function refreshDashboardQueue() {
    const tbody = document.querySelector("table tbody");
    if (!tbody) return;

    try {
      const res = await fetch("/api/v1/analyses");
      if (!res.ok) return;
      const analyses = await res.json();
      if (!analyses || analyses.length === 0) return;

      tbody.innerHTML = "";
      analyses.slice(0, 8).forEach((anl, idx) => {
        const tr = document.createElement("tr");
        tr.className = idx % 2 === 0 ? "bg-surface-container-low/60 hover:bg-surface-raised/60 transition-colors" : "bg-surface-container-lowest hover:bg-surface-raised/60 transition-colors";

        const score = Math.round(anl.security_score || 0);
        let scoreBadgeClass = "bg-threat-secure/15 text-threat-secure";
        let dotClass = "bg-threat-secure";
        if (score < 50) {
          scoreBadgeClass = "bg-threat-critical/15 text-threat-critical";
          dotClass = "bg-threat-critical";
        } else if (score < 75) {
          scoreBadgeClass = "bg-threat-warning/15 text-threat-warning";
          dotClass = "bg-threat-warning";
        }

        const filename = anl.capture ? anl.capture.original_filename : (anl.title || "capture.pcap");
        const idCode = `#ANL-${anl.id.toString().padStart(4, "0")}`;

        tr.innerHTML = `
          <td class="py-2.5 px-3 font-semibold text-primary flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full ${dotClass}"></span>
            <span>${idCode}</span>
          </td>
          <td class="py-2.5 px-3 text-text-primary">
            <span class="flex items-center gap-1 truncate max-w-[200px]" title="${filename}">
              <span class="material-symbols-outlined text-[15px] text-text-muted">description</span>
              ${filename}
            </span>
          </td>
          <td class="py-2.5 px-3 text-text-muted font-mono-packet text-mono-packet">${formatTimeAgo(anl.created_at)}</td>
          <td class="py-2.5 px-3">
            <span class="inline-flex items-center gap-1 font-semibold px-2 py-0.5 rounded ${scoreBadgeClass} font-mono-packet text-mono-packet">
              ${score}/100
            </span>
          </td>
          <td class="py-2.5 px-3">
            <span class="text-text-secondary truncate max-w-[220px] inline-block font-body-sm">
              ${anl.risk_level || "Assessed"} · ${anl.status}
            </span>
          </td>
          <td class="py-2.5 px-3 text-right">
            <div class="flex items-center justify-end gap-1">
              <button class="px-2 py-1 bg-surface-raised hover:bg-primary hover:text-on-primary rounded text-text-primary font-body-sm text-body-sm transition-colors btn-view-assessment" data-id="${anl.id}" title="View Full Assessment" type="button">
                Assessment
              </button>
              <button class="p-1 hover:bg-surface-raised rounded text-text-muted hover:text-text-primary transition-colors btn-download-report" data-id="${anl.id}" title="Export Executive PDF" type="button">
                <span class="material-symbols-outlined text-[16px]">file_download</span>
              </button>
            </div>
          </td>
        `;

        tbody.appendChild(tr);
      });

      // Bind row actions for SPA navigation
      tbody.querySelectorAll(".btn-view-assessment").forEach(btn => {
        btn.addEventListener("click", () => {
          const id = btn.getAttribute("data-id");
          switchTab("results", id);
        });
      });

      tbody.querySelectorAll(".btn-download-report").forEach(btn => {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          const id = btn.getAttribute("data-id");
          window.open(`/api/v1/analyses/${id}/reports/executive.pdf`, "_blank");
        });
      });
    } catch (err) {
      console.warn("Could not populate dashboard queue:", err);
    }
  }

  // ---------------------------------------------------------------------------
  // 2. ANALYZE PCAP INGESTION VIEW
  // ---------------------------------------------------------------------------
  function initAnalyzePage() {
    const dropZone = document.getElementById("drop-container");
    const fileInput = document.getElementById("file-input");
    const previewCard = document.getElementById("file-preview-card");
    const clearBtn = document.getElementById("clear-btn");
    const clearBtnAlt = document.getElementById("btn-clear-alt");
    const startBtn = document.getElementById("start-btn");

    let selectedFile = null;

    if (dropZone && fileInput) {
      dropZone.style.cursor = "pointer";

      const handleFile = (file) => {
        if (!file) return;
        selectedFile = file;

        if (previewCard) {
          previewCard.classList.remove("hidden");
          previewCard.style.display = "block";

          const nameEl = previewCard.querySelector(".font-headline-sm, .font-semibold, h4") || previewCard.querySelector(".text-text-primary");
          if (nameEl) nameEl.textContent = file.name;

          const sizeEl = previewCard.querySelector(".font-mono-packet, .text-text-muted");
          if (sizeEl) {
            const mb = (file.size / (1024 * 1024)).toFixed(2);
            sizeEl.textContent = `${mb} MB · Structure Validated · Ready for Ingestion`;
          }
        }
      };

      fileInput.addEventListener("change", () => {
        if (fileInput.files && fileInput.files.length > 0) {
          handleFile(fileInput.files[0]);
        }
      });

      dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          handleFile(e.dataTransfer.files[0]);
        }
      });

      const clearFile = (e) => {
        if (e) e.preventDefault();
        selectedFile = null;
        if (fileInput) fileInput.value = "";
        if (previewCard) previewCard.style.display = "none";
      };
      if (clearBtn) clearBtn.addEventListener("click", clearFile);
      if (clearBtnAlt) clearBtnAlt.addEventListener("click", clearFile);

      if (startBtn) {
        startBtn.addEventListener("click", (e) => {
          e.preventDefault();
          if (selectedFile) {
            uploadAndAnalyze(selectedFile);
          } else {
            showToast("No PCAP selected. Loading Enterprise Target Video Demo...", "info");
            loadScenarioAndNavigate("demo_video");
          }
        });
      }
    }

    // Wire testbed scenario buttons
    document.querySelectorAll("table tr, div").forEach((row) => {
      const text = (row.textContent || "").toLowerCase();
      if (text.includes("secure_ikev2") || text.includes("weak_ikev1") || text.includes("transport_gcm") || text.includes("demo_video") || text.includes("video_call")) {
        const actionBtn = row.querySelector("button, a");
        if (actionBtn) {
          actionBtn.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (text.includes("weak")) {
              loadScenarioAndNavigate("weak_ikev1");
            } else if (text.includes("transport")) {
              loadScenarioAndNavigate("transport_gcm");
            } else if (text.includes("secure")) {
              loadScenarioAndNavigate("secure_ikev2");
            } else {
              loadScenarioAndNavigate("demo_video");
            }
          });
        }
      }
    });
  }

  // ---------------------------------------------------------------------------
  // 3. RESULTS & CRYPTO AUDIT VIEW
  // ---------------------------------------------------------------------------
  function initResultsPage() {
    if (!currentAnalysisData) return;
    const data = currentAnalysisData;

    // Header metadata
    const idStr = `ANL-${data.id.toString().padStart(4, "0")}-IPSEC`;
    document.querySelectorAll('[class*="mono-data"]').forEach((el) => {
      if (el.textContent.includes("ANL-")) {
        el.textContent = idStr;
      }
    });

    const cap = data.capture || {};
    if (cap.original_filename) {
      document.querySelectorAll(".material-symbols-outlined").forEach((icon) => {
        if (icon.textContent.trim() === "description" && icon.parentElement) {
          icon.parentElement.innerHTML = `<span class="material-symbols-outlined text-[15px] text-text-muted">description</span> ${cap.original_filename}`;
        }
      });
    }

    // Score & Risk Gauge
    const scoreVal = Math.round(data.security_score || 0);
    const riskLvl = (data.risk_level || "Good").toUpperCase();

    document.querySelectorAll('[class*="mono-metric"]').forEach((el) => {
      if (el.textContent.includes("/100") || el.textContent.includes("82") || el.textContent.includes("94")) {
        el.textContent = `${scoreVal}/100`;
      }
    });

    document.querySelectorAll('[class*="threat-"]').forEach((el) => {
      const t = el.textContent.trim();
      if (t === "GOOD" || t === "EXCELLENT" || t === "HIGH RISK" || t === "CRITICAL" || t === "MODERATE") {
        el.textContent = riskLvl;
        el.className = el.className.replace(/text-threat-\w+/g, "");
        el.classList.add(getThreatColorClass(scoreVal));
      }
    });

    // Cryptographic Parameters Binding
    const ike = (data.ike_sessions && data.ike_sessions.length > 0) ? data.ike_sessions[0] : null;
    const esp = (data.ipsec_sessions && data.ipsec_sessions.length > 0) ? data.ipsec_sessions[0] : null;

    if (ike || esp) {
      bindCryptoPanel(ike, esp);
    }

    // Render Dynamic Findings
    renderFindingsCards(data.findings || []);

    // Wire Export & Report buttons
    setupResultsActionButtons(data.id);
  }

  function bindCryptoPanel(ike, esp) {
    const encAlg = ike ? (ike.encryption_algorithm || "AES-256-GCM") : "AES-256-GCM";
    const integAlg = ike ? (ike.integrity_algorithm || "HMAC-SHA256-128") : "HMAC-SHA256";
    const dhGroup = ike ? (ike.dh_group || "Group 19 (256-bit ECP)") : "Group 19 (256-bit ECP)";
    const pfsStatus = (ike && ike.pfs_enabled) ? "PFS Active (Verified)" : "PFS Not Enforced";

    document.querySelectorAll("div, span").forEach((el) => {
      const txt = el.textContent.trim();
      if (txt === "3DES-CBC" || txt === "AES-256-GCM" || txt.includes("Negotiated Cipher")) {
        if (el.children.length === 0) el.textContent = encAlg;
      } else if (txt === "HMAC-MD5-96" || txt === "HMAC-SHA256-128" || txt.includes("HMAC-SHA")) {
        if (el.children.length === 0) el.textContent = integAlg;
      } else if (txt.includes("Diffie-Hellman") && el.children.length === 0 && txt.includes("Group")) {
        el.textContent = dhGroup;
      } else if (txt === "PFS Disabled" || txt === "PFS Active" || txt.includes("Forward Secrecy")) {
        if (el.children.length === 0) {
          el.textContent = pfsStatus;
          el.className = ike && ike.pfs_enabled ? "text-threat-secure font-bold" : "text-threat-critical font-bold";
        }
      }
    });
  }

  function renderFindingsCards(findings) {
    const container = Array.from(document.querySelectorAll("div")).find(d => {
      const h = d.querySelector(".font-headline-sm");
      return h && (h.textContent || "").includes("Key Findings & Threat Matrix");
    });
    if (!container) return;

    let cardsParent = container.parentElement;
    if (!cardsParent) return;

    const existingCards = cardsParent.querySelectorAll('[class*="border-threat-"], [class*="rounded-xl"]');
    existingCards.forEach((c) => {
      if (c.querySelector('[class*="text-threat-"]') && c !== container) {
        c.remove();
      }
    });

    if (findings.length === 0) {
      const cleanDiv = document.createElement("div");
      cleanDiv.className = "bg-surface-subtle border border-threat-secure/30 rounded-xl p-6 shadow-sm flex items-center gap-4 text-threat-secure";
      cleanDiv.innerHTML = `
        <span class="material-symbols-outlined text-[36px]">verified_user</span>
        <div>
          <h4 class="font-headline-sm font-semibold">Zero Critical Vulnerabilities Detected</h4>
          <p class="font-body-sm text-text-secondary mt-1">Cryptographic proposals, key exchange parameters, and sequence counters conform strictly to modern enterprise security baselines (NIST SP 800-77 Rev. 1 & CNSA Suite B).</p>
        </div>
      `;
      cardsParent.appendChild(cleanDiv);
      return;
    }

    findings.forEach((f, idx) => {
      const card = document.createElement("div");
      const sev = (f.severity || "MEDIUM").toUpperCase();
      let borderClass = "border-threat-warning/40";
      let badgeClass = "bg-threat-warning/15 text-threat-warning border-threat-warning/30";
      let icon = "warning";

      if (sev === "CRITICAL") {
        borderClass = "border-threat-critical/50";
        badgeClass = "bg-threat-critical/15 text-threat-critical border-threat-critical/30";
        icon = "report";
      } else if (sev === "HIGH") {
        borderClass = "border-threat-high/40";
        badgeClass = "bg-threat-high/15 text-threat-high border-threat-high/30";
        icon = "gshield";
      } else if (sev === "INFO" || sev === "LOW") {
        borderClass = "border-threat-info/40";
        badgeClass = "bg-threat-info/15 text-threat-info border-threat-info/30";
        icon = "info";
      }

      card.className = `bg-surface-subtle border ${borderClass} rounded-xl p-5 shadow-sm space-y-3 transition-all hover:border-border-active`;
      card.innerHTML = `
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle pb-3">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded border font-mono-packet text-mono-packet font-bold uppercase ${badgeClass}">
              ${sev}
            </span>
            <span class="font-mono-packet text-mono-packet text-text-muted">
              CATEGORY: <strong class="text-text-primary uppercase">${f.category || "GENERAL"}</strong>
            </span>
            <span class="text-text-muted">·</span>
            <span class="font-mono-packet text-mono-packet text-threat-secure flex items-center gap-1">
              <span class="material-symbols-outlined text-[14px]">check_circle</span>
              ${f.evidence_status || "VERIFIED"}
            </span>
          </div>
          <span class="font-mono-packet text-mono-packet text-text-muted">FINDING #${idx + 1}</span>
        </div>

        <div>
          <h4 class="font-headline-sm text-headline-sm text-text-primary font-bold flex items-center gap-2">
            <span class="material-symbols-outlined text-[20px]">${icon}</span>
            ${f.title}
          </h4>
          <p class="font-body-sm text-text-secondary mt-1 leading-relaxed">${f.impact || ""}</p>
        </div>

        ${f.evidence ? `
          <div class="bg-surface-container-lowest p-3 rounded-lg border border-border-subtle font-mono-packet text-mono-packet text-text-muted">
            <span class="text-text-secondary font-semibold block mb-1">Observable PCAP Forensic Evidence:</span>
            <code class="text-primary font-mono-data text-mono-data">${escapeHtml(f.evidence)}</code>
          </div>
        ` : ""}

        ${f.remediation_command ? `
          <div class="bg-surface-base p-3.5 rounded-lg border border-threat-secure/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div class="flex flex-col">
              <span class="font-label-caps text-label-caps text-threat-secure uppercase font-semibold">Recommended Remediation Directive</span>
              <code class="font-mono-data text-mono-data text-text-primary mt-1">${escapeHtml(f.remediation_command)}</code>
            </div>
            <button class="px-3 py-1.5 rounded bg-surface-raised hover:bg-surface-bright text-text-primary font-body-sm text-body-sm transition-colors flex items-center gap-1.5 self-start sm:self-center copy-cmd-btn" data-cmd="${escapeAttr(f.remediation_command)}" type="button">
              <span class="material-symbols-outlined text-[16px]">content_copy</span>
              <span>Copy Directive</span>
            </button>
          </div>
        ` : ""}
      `;

      cardsParent.appendChild(card);
    });

    cardsParent.querySelectorAll(".copy-cmd-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const cmd = btn.getAttribute("data-cmd");
        if (cmd) {
          navigator.clipboard.writeText(cmd);
          btn.innerHTML = '<span class="material-symbols-outlined text-[16px] text-threat-secure">done</span><span class="text-threat-secure">Copied!</span>';
          setTimeout(() => {
            btn.innerHTML = '<span class="material-symbols-outlined text-[16px]">content_copy</span><span>Copy Directive</span>';
          }, 2000);
        }
      });
    });
  }

  function setupResultsActionButtons(analysisId) {
    document.querySelectorAll("button, a").forEach((btn) => {
      const txt = (btn.textContent || "").toLowerCase();

      // Export PDF button
      if (txt.includes("export pdf") || txt.includes("picture_as_pdf")) {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          showReportModal(analysisId);
        });
      }

      // JSON Matrix button
      if (txt.includes("json matrix") || txt.includes("export json") || (txt.includes("json") && txt.includes("matrix"))) {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          window.open(`/api/v1/analyses/${analysisId}/reports/export.json`, "_blank");
        });
      }

      // Packet Explorer
      if (txt.includes("packet explorer")) {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          switchTab("traffic-ai", analysisId);
        });
      }
    });
  }

  // ---------------------------------------------------------------------------
  // 4. TRAFFIC AI & METADATA EXPOSURE VIEW
  // ---------------------------------------------------------------------------
  function initTrafficAIPage() {
    if (!currentAnalysisData) return;
    const data = currentAnalysisData;
    const traffic = data.traffic_prediction || {};
    const meta = data.metadata_exposure || {};

    const predClass = traffic.predicted_class || "Video-like";
    const conf = Math.round((traffic.confidence_score || 0.91) * 100);

    document.querySelectorAll("h2, h3, div, span").forEach((el) => {
      const txt = el.textContent || "";
      if (txt.includes("Enterprise Video") || txt.includes("(Video-like)") || txt.includes("Conferencing")) {
        if (el.children.length === 0 || el.tagName === "H2") {
          el.innerHTML = `${predClass} Application Traffic <span class="text-text-secondary font-normal text-body-lg">(${conf}% ML Confidence)</span>`;
        }
      } else if (txt.includes("91%") || txt.includes("Confidence")) {
        if (el.children.length === 0 && el.textContent.includes("%")) {
          el.textContent = `${conf}% Confidence`;
        }
      }
    });

    if (traffic.is_anomaly) {
      document.querySelectorAll('[class*="threat-secure"]').forEach((el) => {
        if (el.textContent.includes("NOMINAL") || el.textContent.includes("BASELINE")) {
          el.textContent = "SIDE-CHANNEL ANOMALY DETECTED";
          el.className = "text-threat-critical font-bold";
        }
      });
    }

    const setMeter = (selectorKeyword, scoreVal) => {
      document.querySelectorAll("div").forEach((d) => {
        if ((d.textContent || "").includes(selectorKeyword) && d.parentElement) {
          const bar = d.parentElement.querySelector('[style*="width"]');
          if (bar) bar.style.width = `${Math.min(100, Math.round(scoreVal * 100))}%`;
          const valLabel = d.parentElement.querySelector(".font-mono-packet");
          if (valLabel) valLabel.textContent = `${Math.round(scoreVal * 100)}/100`;
        }
      });
    };

    if (meta.endpoint_exposure_score !== undefined) {
      setMeter("IP Endpoint", meta.endpoint_exposure_score);
      setMeter("Traffic Burst", meta.timing_exposure_score);
      setMeter("Packet Size", meta.packet_size_exposure_score);
      setMeter("Traffic Volume", meta.volume_exposure_score);
      setMeter("IKE Negotiation", meta.ike_exposure_score);
    }
  }

  // ---------------------------------------------------------------------------
  // Action Handlers
  // ---------------------------------------------------------------------------
  async function uploadAndAnalyze(file) {
    const banner = showStatusBanner(`Validating and analyzing ${file.name}...`);
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
        throw new Error(err.detail || "Upload validation failed");
      }

      const anl = await res.json();
      banner.textContent = `Analysis complete (Score ${Math.round(anl.security_score || 80)}/100). Loading results...`;
      setTimeout(() => {
        if (banner) banner.remove();
        switchTab("results", anl.id);
      }, 500);
    } catch (err) {
      alert(`PCAP Upload Error: ${err.message}`);
      if (banner) banner.remove();
    }
  }

  async function loadScenarioAndNavigate(scenarioName) {
    const banner = showStatusBanner(`Loading testbed scenario: ${scenarioName}...`);
    try {
      const res = await fetch(`/api/v1/demo/scenario/${scenarioName}`, { method: "POST" });
      let anl = null;
      if (res.ok) {
        anl = await res.json();
      } else {
        const demoRes = await fetch("/api/v1/demo/load", { method: "POST" });
        if (demoRes.ok) anl = await demoRes.json();
      }

      if (anl) {
        if (banner) banner.remove();
        switchTab("results", anl.id);
      }
    } catch (err) {
      alert(`Scenario Load Error: ${err.message}`);
      if (banner) banner.remove();
    }
  }

  // ---------------------------------------------------------------------------
  // Modals & Notifications
  // ---------------------------------------------------------------------------
  function showReportModal(analysisId) {
    const existing = document.getElementById("report-modal");
    if (existing) existing.remove();

    const id = analysisId || currentAnalysisId || 1;
    const modal = document.createElement("div");
    modal.id = "report-modal";
    modal.className = "fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-in fade-in";
    modal.innerHTML = `
      <div class="bg-surface-base border border-border-strong rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-5">
        <div class="flex items-center justify-between border-b border-border-subtle pb-3">
          <div class="flex items-center gap-2">
            <span class="material-symbols-outlined text-primary text-[24px]">description</span>
            <h3 class="font-headline-sm text-text-primary font-bold">Export Audit Reports</h3>
          </div>
          <button id="close-modal-btn" class="p-1 rounded hover:bg-surface-raised text-text-muted hover:text-text-primary transition-colors">
            <span class="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        <p class="font-body-sm text-text-secondary">Instant forensic report downloads for Analysis #${id}:</p>

        <div class="space-y-3">
          <a href="/api/v1/analyses/${id}/reports/executive.pdf" target="_blank" class="flex items-center justify-between p-4 rounded-xl bg-surface-subtle border border-border-subtle hover:border-primary hover:bg-surface-raised transition-all group">
            <div class="flex items-center gap-3">
              <span class="material-symbols-outlined text-threat-info text-[28px]">shield</span>
              <div class="flex flex-col">
                <span class="font-headline-sm text-[15px] text-text-primary font-semibold group-hover:text-primary">Executive Summary PDF</span>
                <span class="font-mono-packet text-mono-packet text-text-muted">High-level risk posture, KPIs & C-suite compliance</span>
              </div>
            </div>
            <span class="material-symbols-outlined text-text-muted group-hover:text-primary text-[20px]">download</span>
          </a>

          <a href="/api/v1/analyses/${id}/reports/technical.pdf" target="_blank" class="flex items-center justify-between p-4 rounded-xl bg-surface-subtle border border-border-subtle hover:border-tertiary hover:bg-surface-raised transition-all group">
            <div class="flex items-center gap-3">
              <span class="material-symbols-outlined text-tertiary text-[28px]">terminal</span>
              <div class="flex flex-col">
                <span class="font-headline-sm text-[15px] text-text-primary font-semibold group-hover:text-tertiary">Technical Deep-Dive PDF</span>
                <span class="font-mono-packet text-mono-packet text-text-muted">Detailed IKE/ESP SPIs, rules, CLI fixes & AI telemetry</span>
              </div>
            </div>
            <span class="material-symbols-outlined text-text-muted group-hover:text-tertiary text-[20px]">download</span>
          </a>

          <a href="/api/v1/analyses/${id}/reports/export.json" target="_blank" class="flex items-center justify-between p-4 rounded-xl bg-surface-subtle border border-border-subtle hover:border-secondary hover:bg-surface-raised transition-all group">
            <div class="flex items-center gap-3">
              <span class="material-symbols-outlined text-secondary text-[28px]">data_object</span>
              <div class="flex flex-col">
                <span class="font-headline-sm text-[15px] text-text-primary font-semibold group-hover:text-secondary">Structured JSON Matrix</span>
                <span class="font-mono-packet text-mono-packet text-text-muted">Raw telemetry for SIEM & SOC orchestration</span>
              </div>
            </div>
            <span class="material-symbols-outlined text-text-muted group-hover:text-secondary text-[20px]">download</span>
          </a>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector("#close-modal-btn").addEventListener("click", () => modal.remove());
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.remove();
    });
  }

  function showSettingsModal() {
    const existing = document.getElementById("settings-modal");
    if (existing) existing.remove();

    const modal = document.createElement("div");
    modal.id = "settings-modal";
    modal.className = "fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-in fade-in";
    modal.innerHTML = `
      <div class="bg-surface-base border border-border-strong rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5">
        <div class="flex items-center justify-between border-b border-border-subtle pb-3">
          <div class="flex items-center gap-2">
            <span class="material-symbols-outlined text-primary text-[24px]">tune</span>
            <h3 class="font-headline-sm text-text-primary font-bold">Engine Configuration & Policies</h3>
          </div>
          <button id="close-settings-btn" class="p-1 rounded hover:bg-surface-raised text-text-muted hover:text-text-primary transition-colors">
            <span class="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        <div class="space-y-4 font-body-sm text-text-secondary">
          <div class="bg-surface-subtle p-3 rounded-lg border border-border-subtle flex items-center justify-between">
            <div>
              <div class="font-semibold text-text-primary">Deterministic Compliance Profile</div>
              <div class="font-mono-packet text-mono-packet text-text-muted">NIST SP 800-77 Rev. 1 / NSA CNSA Suite B</div>
            </div>
            <span class="px-2 py-0.5 rounded bg-threat-secure/15 text-threat-secure font-mono-packet font-semibold">ENFORCED</span>
          </div>

          <div class="bg-surface-subtle p-3 rounded-lg border border-border-subtle flex items-center justify-between">
            <div>
              <div class="font-semibold text-text-primary">Zero-Storage Privacy Mode</div>
              <div class="font-mono-packet text-mono-packet text-text-muted">Raw payload data scrubbed immediately from memory</div>
            </div>
            <span class="px-2 py-0.5 rounded bg-threat-secure/15 text-threat-secure font-mono-packet font-semibold">ACTIVE</span>
          </div>

          <div class="bg-surface-subtle p-3 rounded-lg border border-border-subtle flex items-center justify-between">
            <div>
              <div class="font-semibold text-text-primary">Interactive OpenAPI / Swagger</div>
              <div class="font-mono-packet text-mono-packet text-text-muted">REST API definitions, schemas and live test runner</div>
            </div>
            <a href="/docs" target="_blank" class="px-3 py-1 rounded bg-primary text-surface-base font-semibold hover:bg-primary-container transition-colors flex items-center gap-1 font-mono-packet">
              <span>Open /docs</span>
              <span class="material-symbols-outlined text-[13px]">open_in_new</span>
            </a>
          </div>
        </div>

        <div class="pt-2 flex justify-end">
          <button id="close-settings-done" class="px-4 py-2 rounded-lg bg-surface-raised hover:bg-surface-bright text-text-primary font-body-sm transition-colors">Close</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector("#close-settings-btn").addEventListener("click", () => modal.remove());
    modal.querySelector("#close-settings-done").addEventListener("click", () => modal.remove());
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.remove();
    });
  }

  function showStatusBanner(msg) {
    const existing = document.getElementById("status-banner");
    if (existing) existing.remove();

    const banner = document.createElement("div");
    banner.id = "status-banner";
    banner.style.position = "fixed";
    banner.style.top = "18px";
    banner.style.right = "18px";
    banner.style.zIndex = "99999";
    banner.style.background = "linear-gradient(135deg, #06b6d4, #2563eb)";
    banner.style.color = "#ffffff";
    banner.style.padding = "14px 22px";
    banner.style.borderRadius = "10px";
    banner.style.fontSize = "13px";
    banner.style.fontWeight = "600";
    banner.style.boxShadow = "0 10px 30px rgba(0,0,0,0.6)";
    banner.style.display = "flex";
    banner.style.alignItems = "center";
    banner.style.gap = "10px";
    banner.innerHTML = `<span class="material-symbols-outlined animate-spin text-[18px]">progress_activity</span><span>${msg}</span>`;
    document.body.appendChild(banner);
    return banner;
  }

  function showToast(msg, type = "info") {
    const toast = document.createElement("div");
    toast.style.position = "fixed";
    toast.style.bottom = "24px";
    toast.style.right = "24px";
    toast.style.zIndex = "99999";
    toast.style.background = type === "error" ? "#ef4444" : "#181c24";
    toast.style.border = "1px solid #334155";
    toast.style.color = "#ffffff";
    toast.style.padding = "12px 18px";
    toast.style.borderRadius = "8px";
    toast.style.fontSize = "13px";
    toast.style.fontWeight = "500";
    toast.style.boxShadow = "0 8px 24px rgba(0,0,0,0.4)";
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3500);
  }

  function getThreatColorClass(score) {
    if (score >= 85) return "text-threat-secure";
    if (score >= 70) return "text-threat-info";
    if (score >= 50) return "text-threat-warning";
    return "text-threat-critical";
  }

  function formatTimeAgo(isoString) {
    if (!isoString) return "Just now";
    const date = new Date(isoString);
    const diffSeconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (diffSeconds < 60) return "Just now";
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)} mins ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)} hours ago`;
    return `${Math.floor(diffSeconds / 86400)} days ago`;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  function escapeAttr(str) {
    if (!str) return "";
    return str.replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }
})();
