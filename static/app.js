/* ═══════════════════════════════════════════════════════════════════════════
   app.js — ForensiCheck frontend logic
   Handles: drag-and-drop, file browse, fetch POST, results rendering.
   ═══════════════════════════════════════════════════════════════════════════ */

/* ── DOM refs ───────────────────────────────────────────────────────────── */
const dropZone      = document.getElementById("drop-zone");
const fileInput     = document.getElementById("file-input");
const dropPrimary   = document.getElementById("drop-primary");
const dropHint      = document.getElementById("drop-hint");
const dropIcon      = document.getElementById("drop-icon");
const btnAnalyze    = document.getElementById("btn-analyze");
const btnSpinner    = document.getElementById("btn-spinner");
const resultsSection= document.getElementById("results-section");
const errorToast    = document.getElementById("error-toast");

// Result sub-elements
const verdictCard   = document.getElementById("verdict-card");
const verdictBadge  = document.getElementById("verdict-badge");
const verdictFilename = document.getElementById("verdict-filename");
const verdictFilesize = document.getElementById("verdict-filesize");
const verdictDetail = document.getElementById("verdict-detail");
const sigContent    = document.getElementById("sig-content");
const entropyContent= document.getElementById("entropy-content");
const entropyInfoCard= document.getElementById("entropy-info-card");
const zipDetailCard = document.getElementById("zip-detail-card");
const zipDetailContent = document.getElementById("zip-detail-content");

/* ── State ──────────────────────────────────────────────────────────────── */
let selectedFile = null;

/* ── Utilities ──────────────────────────────────────────────────────────── */
function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}

function showToast(msg) {
  errorToast.textContent = msg;
  errorToast.classList.add("show");
  setTimeout(() => errorToast.classList.remove("show"), 4000);
}

function setFile(file) {
  selectedFile = file;
  dropPrimary.textContent = file.name;
  dropHint.textContent = formatBytes(file.size);
  dropIcon.textContent = "📄";
  dropZone.classList.add("has-file");
  dropZone.classList.remove("drag-active");
  btnAnalyze.disabled = false;
}

function setLoading(on) {
  if (on) {
    btnAnalyze.classList.add("loading");
    btnAnalyze.disabled = true;
  } else {
    btnAnalyze.classList.remove("loading");
    btnAnalyze.disabled = false;
  }
}

/* ── Drag-and-drop handlers ─────────────────────────────────────────────── */
["dragenter", "dragover"].forEach(evt => {
  dropZone.addEventListener(evt, e => {
    e.preventDefault();
    dropZone.classList.add("drag-active");
  });
});

["dragleave", "drop"].forEach(evt => {
  dropZone.addEventListener(evt, e => {
    e.preventDefault();
    dropZone.classList.remove("drag-active");
  });
});

dropZone.addEventListener("drop", e => {
  const files = e.dataTransfer.files;
  if (files.length) setFile(files[0]);
});

/* ── Click-to-browse ────────────────────────────────────────────────────── */
dropZone.addEventListener("click", e => {
  // Avoid double-triggering when the browse label is clicked
  if (e.target.classList.contains("btn-browse")) return;
  fileInput.click();
});

dropZone.addEventListener("keydown", e => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
});

fileInput.addEventListener("change", () => {
  if (fileInput.files.length) setFile(fileInput.files[0]);
});

/* ── Analyze ────────────────────────────────────────────────────────────── */
btnAnalyze.addEventListener("click", async () => {
  if (!selectedFile) return;

  setLoading(true);
  resultsSection.classList.remove("visible");

  const formData = new FormData();
  formData.append("file", selectedFile);

  try {
    const response = await fetch("/analyze", { method: "POST", body: formData });
    const data = await response.json();

    if (!response.ok || data.error) {
      showToast(`Error: ${data.error || "Unknown server error."}`);
      setLoading(false);
      return;
    }

    renderResults(data);
  } catch (err) {
    showToast("Network error — could not reach the server.");
  } finally {
    setLoading(false);
  }
});

/* ── Result rendering ───────────────────────────────────────────────────── */
function renderResults(d) {
  /* ── Verdict card ─────────────────────────────────────────────────────── */
  verdictCard.className = `card verdict-card ${d.verdict}`;

  const icons = { MATCH: "✅", MISMATCH: "🚨", SUSPICIOUS: "⚠️", UNKNOWN: "❓" };
  verdictBadge.className = `verdict-badge ${d.verdict}`;
  verdictBadge.innerHTML = `${icons[d.verdict] || "❓"} &nbsp; ${d.verdict}`;

  verdictFilename.textContent = d.filename;
  verdictFilesize.textContent = `${formatBytes(d.file_size)} · .${d.declared_ext} declared`;
  verdictDetail.innerHTML = d.verdict_detail;  // safe: server generates this

  /* ── Signature matches ────────────────────────────────────────────────── */
  if (!d.detected_types || d.detected_types.length === 0) {
    sigContent.innerHTML = `<p class="no-match">No known signature matched this file.</p>`;
  } else {
    const rows = d.detected_types.map(sig => `
      <tr>
        <td>${sig.label}</td>
        <td class="mono">${sig.magic_hex}</td>
        <td><span class="sig-pill">+${sig.offset}</span></td>
      </tr>
    `).join("");

    sigContent.innerHTML = `
      <table class="sig-table">
        <thead>
          <tr>
            <th>Detected Format</th>
            <th>Magic Bytes</th>
            <th>Offset</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      ${d.detected_types[0]?.note
        ? `<p class="zip-note" style="margin-top:12px">ℹ️ ${d.detected_types[0].note}</p>`
        : ""}
    `;
  }

  /* ── Entropy ──────────────────────────────────────────────────────────── */
  const ent = d.entropy;
  // Bar fill percentage: entropy goes 0–8, map to 0–100%
  const pct = Math.min(100, (ent.value / 8) * 100).toFixed(1);
  const badgeBg = `${ent.color}22`;
  const badgeBorder = `${ent.color}55`;

  let expectedMarker = "";
  let expectedText = "";
  if (ent.expected_range && ent.expected_range.length === 2) {
    const minPct = (ent.expected_range[0] / 8) * 100;
    const widthPct = ((ent.expected_range[1] - ent.expected_range[0]) / 8) * 100;
    expectedMarker = `<div class="entropy-expected-range" style="left: ${minPct}%; width: ${widthPct}%;" title="Expected range: ${ent.expected_range[0].toFixed(1)} - ${ent.expected_range[1].toFixed(1)}"></div>`;
    expectedText = `<span class="entropy-expected-text">Expected range for this format is <strong>${ent.expected_range[0].toFixed(1)} – ${ent.expected_range[1].toFixed(1)}</strong></span>`;
  }

  entropyContent.innerHTML = `
    <div class="entropy-value-row">
      <span class="entropy-number">${ent.value.toFixed(3)}</span>
      <span class="entropy-scale">/ 8.000 bits/byte</span>
    </div>
    <div class="entropy-bar-track">
      ${expectedMarker}
      <div class="entropy-bar-fill" style="width:${pct}%; background:${ent.color}"></div>
    </div>
    ${expectedText}
    <span class="entropy-level-badge"
      style="color:${ent.color}; background:${badgeBg}; border:1px solid ${badgeBorder}">
      ${ent.level}
    </span>
    <p class="entropy-message">${ent.message}</p>
  `;

  /* ── ZIP sub-type detail ──────────────────────────────────────────────── */
  if (d.zip_detail) {
    zipDetailCard.style.display = "block";
    zipDetailContent.innerHTML = `
      <p class="zip-found-label">
        Internal ZIP directory analysis identified this file as:
        <strong>${d.zip_detail.label}</strong>
      </p>
      <p class="zip-note">
        ForensiCheck scanned the ZIP central directory for known internal
        paths (e.g., <code>word/document.xml</code> for DOCX,
        <code>META-INF/MANIFEST.MF</code> for JAR) to distinguish between
        formats that share the same <code>PK\\x03\\x04</code> magic bytes.
      </p>
    `;
  } else {
    zipDetailCard.style.display = "none";
  }

  /* ── Reveal ───────────────────────────────────────────────────────────── */
  requestAnimationFrame(() => {
    resultsSection.classList.add("visible");
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  });
}
