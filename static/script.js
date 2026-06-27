const GAUGE_CIRCUMFERENCE = 528;

const form = document.getElementById("scanForm");
const urlInput = document.getElementById("url");
const scanBtn = document.getElementById("scanBtn");
const errorHint = document.getElementById("errorHint");

const gaugeFill = document.getElementById("gaugeFill");
const riskText = document.getElementById("riskText");
const gaugeLabel = document.getElementById("gaugeLabel");

const verdictBody = document.getElementById("verdictBody");
const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");

const history = document.getElementById("history");
const logEmpty = document.getElementById("logEmpty");

function riskTier(score) {
  if (score < 40) return "safe";
  if (score < 70) return "warn";
  return "danger";
}

function setScanning(isScanning) {
  scanBtn.disabled = isScanning;
  scanBtn.classList.toggle("scanning", isScanning);
  if (isScanning) {
    statusDot.className = "dot dot-scanning";
    statusText.textContent = "SCANNING…";
  }
}

function setGauge(score) {
  const tier = riskTier(score);
  const colorVar = tier === "safe" ? "var(--safe)" : tier === "warn" ? "var(--warn)" : "var(--danger)";
  const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * score) / 100;

  gaugeFill.style.stroke = colorVar;
  gaugeFill.style.strokeDashoffset = offset;
  riskText.textContent = score;
  riskText.style.color = colorVar;

  const labels = { safe: "low risk", warn: "elevated risk", danger: "high risk" };
  gaugeLabel.textContent = labels[tier];
}

function renderVerdict(data) {
  const isPhishing = data.prediction === 1;
  const tier = isPhishing ? "danger" : "safe";
  const icon = isPhishing ? "⚠" : "✓";
  const title = isPhishing ? "Likely phishing" : "Looks legitimate";

  let reasonsHtml;
  if (data.reasons && data.reasons.length > 0) {
    reasonsHtml = `
      <p class="reasons-label">Flagged signals</p>
      <ul class="reasons-list">
        ${data.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")}
      </ul>`;
  } else {
    reasonsHtml = `<p class="reasons-none">No suspicious signals detected.</p>`;
  }

  verdictBody.innerHTML = `
    <div class="verdict-head">
      <span class="verdict-icon">${icon}</span>
      <h3 class="verdict-title ${tier}">${title}</h3>
    </div>
    <p class="verdict-confidence">Model confidence: ${data.confidence}%</p>
    ${reasonsHtml}
  `;

  statusDot.className = `dot dot-${tier}`;
  statusText.textContent = isPhishing ? "THREAT DETECTED" : "CLEAR";
}

function addHistoryEntry(url, score) {
  logEmpty.style.display = "none";
  const tier = riskTier(score);
  const li = document.createElement("li");
  li.innerHTML = `
    <span class="log-url">${escapeHtml(url)}</span>
    <span class="log-score ${tier === "danger" ? "danger" : "safe"}">${score}/100</span>
  `;
  history.prepend(li);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  errorHint.textContent = "";

  if (!url) {
    errorHint.textContent = "Enter a URL to scan.";
    return;
  }

  setScanning(true);

  try {
    const formData = new FormData();
    formData.append("url", url);

    const response = await fetch("/predict", {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    if (data.error) {
      errorHint.textContent = data.error;
      statusDot.className = "dot dot-idle";
      statusText.textContent = "SYSTEM IDLE";
      return;
    }

    setGauge(data.risk_score);
    renderVerdict(data);
    addHistoryEntry(url, data.risk_score);
  } catch (err) {
    errorHint.textContent = "Scan failed — check the server and try again.";
    statusDot.className = "dot dot-idle";
    statusText.textContent = "SYSTEM IDLE";
  } finally {
    setScanning(false);
  }
});
