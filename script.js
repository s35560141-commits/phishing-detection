/* =====================================================================
   AI-Powered Phishing URL Detection using Finite Automata
   ---------------------------------------------------------------------
   This file is organised in five parts, matching the "How It Works"
   pipeline described on the page:

     1. FEATURE EXTRACTION   -> extractFeatures(url)
     2. FINITE AUTOMATA      -> runAutomaton(url, features)
     3. AI RISK ANALYSIS     -> calculateRisk(features)
     4. RENDERING            -> renderXxx() functions
     5. UI WIRING            -> event listeners at the bottom

   Everything runs client-side. There is no backend and no real
   trained ML model — the "AI risk score" is a transparent, rule based
   weighted sum, clearly labelled as a simulation.
   ===================================================================== */

/* ---------------------------------------------------------------------
   Reference data used by both feature extraction and the automaton
   --------------------------------------------------------------------- */
const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "account", "password", "secure",
  "update", "bank", "confirm", "confirmation", "signin", "webscr"
];

const SUSPICIOUS_TLDS = ["xyz", "tk", "ml", "ga", "cf", "gq", "top", "info", "click", "work"];

const SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"];

/* ---------------------------------------------------------------------
   1. FEATURE EXTRACTION
   Parses the raw URL string and pulls out the measurable signals the
   rest of the pipeline needs. Falls back to manual string parsing if
   the browser's URL() constructor rejects the input (e.g. missing
   protocol), so the tool still works on loosely-typed input.
   --------------------------------------------------------------------- */
function extractFeatures(rawUrl) {
  let urlStr = rawUrl.trim();
  if (!/^https?:\/\//i.test(urlStr)) {
    urlStr = "http://" + urlStr; // assume http if user forgot the scheme
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (e) {
    parsed = null;
  }

  const hostname = parsed ? parsed.hostname : urlStr.replace(/^https?:\/\//i, "").split("/")[0];
  const isHttps = parsed ? parsed.protocol === "https:" : /^https:\/\//i.test(urlStr);

  // number of dots in hostname (a rough proxy for subdomain depth)
  const dotCount = (hostname.match(/\./g) || []).length;

  // subdomain count = labels before the registrable domain (label.label.tld)
  const hostLabels = hostname.split(".").filter(Boolean);
  const subdomainCount = Math.max(0, hostLabels.length - 2);

  // IPv4 address used directly as the host, e.g. http://192.168.1.1/login
  const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

  // special characters across the full URL (excluding the standard :// separators)
  const specialCharMatches = urlStr.replace(/^https?:\/\//i, "").match(/[^a-zA-Z0-9.\-\/]/g) || [];
  const specialCharCount = specialCharMatches.length;

  // suspicious keyword hits, scanned across the whole (lower-cased) URL
  const lowerUrl = urlStr.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(k => lowerUrl.includes(k));

  const hasAtSymbol = urlStr.includes("@");

  const isShortened = SHORTENERS.some(s => hostname.includes(s));

  const tldMatch = hostname.match(/\.([a-z]+)$/i);
  const domainExtension = tldMatch ? tldMatch[1].toLowerCase() : "";
  const isSuspiciousTld = SUSPICIOUS_TLDS.includes(domainExtension);

  return {
    fullUrl: urlStr,
    hostname,
    length: urlStr.length,
    isHttps,
    dotCount,
    subdomainCount,
    isIpAddress,
    specialCharCount,
    matchedKeywords,
    hasAtSymbol,
    isShortened,
    domainExtension,
    isSuspiciousTld
  };
}

/* ---------------------------------------------------------------------
   2. FINITE AUTOMATA SIMULATION
   Models the classifier as a 5-state DFA:

     q0 (start) --read chars--> q1 (reading)
     q1 --keyword or IP match found--> q2 (suspicious pattern found)
     q2 --second independent flag found--> q3 (multiple suspicious patterns)
     q1 / q2 / q3 --end of input--> q4 (final classification)

   The transition rules are driven directly by the extracted features:
   each independently suspicious signal (keyword, IP host, @ symbol,
   suspicious TLD, shortener) counts as one "pattern" that can push the
   automaton from q1 -> q2, and a second one pushes q2 -> q3.
   --------------------------------------------------------------------- */
function runAutomaton(features) {
  const patternFlags = [];
  if (features.matchedKeywords.length > 0) patternFlags.push("suspicious keyword");
  if (features.isIpAddress) patternFlags.push("IP address host");
  if (features.hasAtSymbol) patternFlags.push("@ symbol");
  if (features.isSuspiciousTld) patternFlags.push("suspicious domain extension");
  if (features.isShortened) patternFlags.push("URL shortener");
  if (features.subdomainCount > 2) patternFlags.push("excessive subdomains");

  // Build the path the automaton actually takes through its states.
  const path = ["q0", "q1"];
  if (patternFlags.length >= 1) path.push("q2");
  if (patternFlags.length >= 2) path.push("q3");
  path.push("q4");

  return {
    path,
    patternFlags,
    verdict: patternFlags.length > 0 ? "Suspicious Pattern Detected" : "No Suspicious Pattern Detected"
  };
}

/* ---------------------------------------------------------------------
   3. AI RISK ANALYSIS
   A transparent, rule-weighted scoring function standing in for a
   trained classifier. Each risky feature adds a fixed weight; the
   total is capped at 100. This is intentionally simple so it can be
   explained line-by-line in a viva.
   --------------------------------------------------------------------- */
function calculateRisk(features) {
  const factors = []; // { label, weight, flagged }
  let score = 0;

  const add = (label, weight, condition) => {
    factors.push({ label, weight, flagged: !!condition });
    if (condition) score += weight;
  };

  add(`${features.matchedKeywords.length} suspicious keyword(s) found`, 22, features.matchedKeywords.length > 0);
  add("No HTTPS encryption", 18, !features.isHttps);
  add("Host is a raw IP address", 22, features.isIpAddress);
  add("Excessive subdomains (> 2)", 10, features.subdomainCount > 2);
  add(`Long URL (${features.length} characters)`, 12, features.length > 60);
  add(`Suspicious domain extension (.${features.domainExtension})`, 10, features.isSuspiciousTld);
  add("Contains '@' symbol", 16, features.hasAtSymbol);
  add("Uses a URL shortening service", 12, features.isShortened);
  add(`High special-character count (${features.specialCharCount})`, 8, features.specialCharCount > 4);

  score = Math.min(100, score);

  let level, classification;
  if (score >= 60) { level = "High"; classification = "Potential Phishing"; }
  else if (score >= 30) { level = "Medium"; classification = "Potential Phishing"; }
  else { level = "Low"; classification = "Legitimate"; }

  return { score, level, classification, factors };
}

/* ---------------------------------------------------------------------
   4. RENDERING HELPERS
   --------------------------------------------------------------------- */
function renderFeatures(features) {
  document.getElementById("analyzedUrlDisplay").textContent = features.fullUrl;

  const cards = [
    { label: "URL Length", value: features.length, flag: features.length > 60 },
    { label: "HTTPS", value: features.isHttps ? "Yes" : "No", flag: !features.isHttps, ok: features.isHttps },
    { label: "Number of Dots", value: features.dotCount, flag: features.dotCount > 4 },
    { label: "Subdomains", value: features.subdomainCount, flag: features.subdomainCount > 2 },
    { label: "IP Address Host", value: features.isIpAddress ? "Yes" : "No", flag: features.isIpAddress, ok: !features.isIpAddress },
    { label: "Special Characters", value: features.specialCharCount, flag: features.specialCharCount > 4 },
    { label: "Suspicious Keywords", value: features.matchedKeywords.length, flag: features.matchedKeywords.length > 0, ok: features.matchedKeywords.length === 0 },
    { label: "Domain Extension", value: "." + (features.domainExtension || "—"), flag: features.isSuspiciousTld },
    { label: "'@' Symbol Present", value: features.hasAtSymbol ? "Yes" : "No", flag: features.hasAtSymbol, ok: !features.hasAtSymbol },
    { label: "URL Shortener", value: features.isShortened ? "Yes" : "No", flag: features.isShortened, ok: !features.isShortened }
  ];

  const grid = document.getElementById("featureGrid");
  grid.innerHTML = cards.map(c => `
    <div class="feature-card ${c.flag ? "flag-on" : (c.ok ? "flag-off" : "")}">
      <div class="feature-label">${c.label}</div>
      <div class="feature-value ${c.flag ? "value-flag" : (c.ok ? "value-ok" : "")}">${c.value}</div>
    </div>
  `).join("");

  document.getElementById("analysisEmpty").classList.add("hidden");
  document.getElementById("analysisResults").classList.remove("hidden");
}

function renderTape(features) {
  const tape = document.getElementById("faTape");
  const chars = features.fullUrl.split("");
  const lowerUrl = features.fullUrl.toLowerCase();

  // Determine which character indices fall inside a suspicious keyword,
  // so the tape can highlight the exact substring the automaton flags.
  const flaggedIndices = new Set();
  features.matchedKeywords.forEach(keyword => {
    let idx = lowerUrl.indexOf(keyword);
    while (idx !== -1) {
      for (let i = idx; i < idx + keyword.length; i++) flaggedIndices.add(i);
      idx = lowerUrl.indexOf(keyword, idx + 1);
    }
  });
  if (features.hasAtSymbol) flaggedIndices.add(features.fullUrl.indexOf("@"));

  tape.innerHTML = chars.map((ch, i) =>
    `<span class="tape-cell" data-index="${i}" data-flag="${flaggedIndices.has(i) ? "1" : "0"}">${ch === " " ? "&nbsp;" : ch}</span>`
  ).join("");

  return tape.querySelectorAll(".tape-cell");
}

function setAutomatonState(stateId, mode) {
  // mode: "active" | "suspicious" | "done" | ""
  document.querySelectorAll(".fa-state").forEach(el => {
    el.classList.remove("state-active", "state-suspicious", "state-done");
  });
  const el = document.getElementById("state-" + stateId);
  if (el && mode) el.classList.add("state-" + mode);
}

function setEdgeActive(fromId, toId, danger) {
  const edge = document.getElementById(`path-${fromId}-${toId}`);
  if (edge) edge.classList.add(danger ? "edge-danger" : "edge-active");
}

function resetAutomatonVisual() {
  document.querySelectorAll(".fa-state").forEach(el => el.classList.remove("state-active", "state-suspicious", "state-done"));
  document.querySelectorAll(".fa-edge").forEach(el => el.classList.remove("edge-active", "edge-danger"));
}

/* Steps the tape + state diagram through the automaton's path with a
   short delay per stage, so the transition is visible rather than an
   instant jump — this is the "animation on analyze" requirement. */
function animateAutomaton(features, automatonResult, tapeCells, onComplete) {
  resetAutomatonVisual();
  const danger = automatonResult.patternFlags.length > 0;

  // Phase 1: read the tape left to right (q0 -> q1)
  setAutomatonState("q0", "active");
  let i = 0;
  const totalChars = tapeCells.length;
  const perCharDelay = Math.max(8, Math.min(35, 900 / totalChars));

  function readStep() {
    if (i > 0) tapeCells[i - 1].classList.remove("cell-active");
    if (i < totalChars) {
      const cell = tapeCells[i];
      cell.classList.add(cell.dataset.flag === "1" ? "cell-flag" : "cell-active");
      if (i === 2) { setAutomatonState("q0", ""); setAutomatonState("q1", "active"); setEdgeActive("q0", "q1", false); }
      i++;
      setTimeout(readStep, perCharDelay);
    } else {
      finishReading();
    }
  }

  function finishReading() {
    // Phase 2: pattern detection states
    if (automatonResult.path.includes("q2")) {
      setTimeout(() => {
        setAutomatonState("q1", "");
        setAutomatonState("q2", "suspicious");
        setEdgeActive("q1", "q2", true);
      }, 150);
    }
    if (automatonResult.path.includes("q3")) {
      setTimeout(() => {
        setAutomatonState("q2", "");
        setAutomatonState("q3", "suspicious");
        setEdgeActive("q2", "q3", true);
      }, 500);
    }
    // Phase 3: final classification state q4
    setTimeout(() => {
      const lastMidState = automatonResult.path[automatonResult.path.length - 2];
      setAutomatonState(lastMidState, "");
      setAutomatonState("q4", danger ? "suspicious" : "done");
      onComplete && onComplete();
    }, automatonResult.path.includes("q3") ? 850 : (automatonResult.path.includes("q2") ? 500 : 250));
  }

  readStep();
}

function renderRisk(risk) {
  const gauge = document.getElementById("gaugeFill");
  const circumference = 251.2;
  const offset = circumference - (circumference * risk.score) / 100;
  gauge.style.strokeDashoffset = offset;
  gauge.style.stroke = risk.score >= 60 ? "var(--danger)" : (risk.score >= 30 ? "var(--signal)" : "var(--safe)");

  document.getElementById("riskScoreValue").textContent = risk.score;

  const cls = document.getElementById("riskClassification");
  cls.textContent = `Classification: ${risk.classification}`;
  cls.className = "risk-classification " + (risk.classification === "Potential Phishing" ? "rc-danger" : "rc-safe");

  const list = document.getElementById("riskFactors");
  list.innerHTML = risk.factors.map(f =>
    `<li class="${f.flagged ? "factor-flag" : ""}">${f.label} ${f.flagged ? `(+${f.weight})` : "(0)"}</li>`
  ).join("");
}

function renderResult(features, automatonResult, risk) {
  const card = document.getElementById("resultCard");
  const isPhishing = risk.classification === "Potential Phishing";

  card.className = "result-card " + (isPhishing ? "rc-danger" : "rc-safe");
  document.getElementById("resultIcon").textContent = isPhishing ? "⚠" : "✓";
  document.getElementById("resultVerdict").textContent = isPhishing ? "POTENTIAL PHISHING URL" : "LEGITIMATE URL";
  document.getElementById("resultRiskLevel").textContent = risk.level;
  document.getElementById("resultFaResult").textContent = automatonResult.verdict;
  document.getElementById("resultRiskScore").textContent = risk.score + "%";
  document.getElementById("resultRecommendation").textContent = isPhishing
    ? "Recommendation: Do not enter sensitive information on this website."
    : "Recommendation: No suspicious patterns detected. Standard browsing caution still applies.";

  card.scrollIntoView({ behavior: "smooth", block: "center" });
}

/* ---------------------------------------------------------------------
   Master pipeline: ties extraction -> automaton -> risk -> render
   --------------------------------------------------------------------- */
function analyzeUrl(rawUrl) {
  if (!rawUrl || !rawUrl.trim()) return;

  const features = extractFeatures(rawUrl);
  const automatonResult = runAutomaton(features);
  const risk = calculateRisk(features);

  renderFeatures(features);
  const tapeCells = renderTape(features);
  animateAutomaton(features, automatonResult, tapeCells, () => {
    renderRisk(risk);
    renderResult(features, automatonResult, risk);
  });

  document.getElementById("urlInput").value = features.fullUrl;
}

/* ---------------------------------------------------------------------
   5. UI WIRING
   --------------------------------------------------------------------- */
document.addEventListener("DOMContentLoaded", () => {

  // -- mobile nav toggle --
  const navToggle = document.getElementById("navToggle");
  const navLinks = document.getElementById("navLinks");
  navToggle.addEventListener("click", () => navLinks.classList.toggle("open"));
  navLinks.querySelectorAll("a").forEach(a => a.addEventListener("click", () => navLinks.classList.remove("open")));

  // -- hero analyze form --
  const heroForm = document.getElementById("heroForm");
  const urlInput = document.getElementById("urlInput");
  heroForm.addEventListener("submit", (e) => {
    e.preventDefault();
    analyzeUrl(urlInput.value);
    document.getElementById("analyzer").scrollIntoView({ behavior: "smooth", block: "start" });
  });

  // -- example chips under the hero --
  document.querySelectorAll(".chip").forEach(chip => {
    chip.addEventListener("click", () => {
      urlInput.value = chip.dataset.url;
      analyzeUrl(chip.dataset.url);
      document.getElementById("analyzer").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  // -- detection examples table --
  const exampleRows = [
    { url: "https://www.google.com", automata: "Safe", risk: "Low", result: "Legitimate" },
    { url: "https://example.com", automata: "Safe", risk: "Low", result: "Legitimate" },
    { url: "http://login-bank-verify.com", automata: "Suspicious", risk: "High", result: "Potential Phishing" },
    { url: "http://secure-account-login.xyz", automata: "Suspicious", risk: "High", result: "Potential Phishing" },
    { url: "http://192.168.10.4/verify/account", automata: "Suspicious", risk: "High", result: "Potential Phishing" },
    { url: "https://bit.ly/update-password", automata: "Suspicious", risk: "Medium", result: "Potential Phishing" }
  ];
  const tbody = document.querySelector("#examplesTable tbody");
  tbody.innerHTML = exampleRows.map(r => `
    <tr data-url="${r.url}">
      <td>${r.url}</td>
      <td><span class="badge ${r.automata === "Safe" ? "badge-safe" : "badge-danger"}">${r.automata}</span></td>
      <td>${r.risk}</td>
      <td><span class="badge ${r.result === "Legitimate" ? "badge-safe" : "badge-danger"}">${r.result}</span></td>
    </tr>
  `).join("");
  tbody.querySelectorAll("tr").forEach(row => {
    row.addEventListener("click", () => {
      urlInput.value = row.dataset.url;
      analyzeUrl(row.dataset.url);
      document.getElementById("analyzer").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  // -- idle hero "scanning" ticker: cycles demo URLs across the top
  //    readout until the user runs a real analysis --
  const idleUrls = [
    "https://www.university-portal.edu/dashboard",
    "http://secure-account-login.xyz/update",
    "https://www.google.com/search",
    "http://192.168.4.12/login/verify"
  ];
  let idleIndex = 0;
  const heroScanString = document.getElementById("heroScanString");
  const heroStateLabel = document.getElementById("heroStateLabel");
  let idleTimer = null;

  function tickIdle() {
    const url = idleUrls[idleIndex % idleUrls.length];
    heroScanString.textContent = url;
    const f = extractFeatures(url);
    const susp = f.matchedKeywords.length > 0 || f.isIpAddress || f.isSuspiciousTld;
    heroStateLabel.textContent = susp ? "SUSPICIOUS" : "READING";
    heroStateLabel.style.color = susp ? "var(--danger)" : "";
    heroStateLabel.style.background = susp ? "var(--danger-dim)" : "";
    heroStateLabel.style.borderColor = susp ? "rgba(255,77,109,0.35)" : "";
    idleIndex++;
    idleTimer = setTimeout(tickIdle, 2600);
  }
  tickIdle();
});
