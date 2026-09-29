"use strict";

const state = { lastQuestion: "", lastAnswer: "", lastOutOfScope: false, triageRequestId: 0, toastTimer: null };
const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "");
try { state.interactionCount = Number(sessionStorage.getItem("incidentops-interaction-count")) || 0; }
catch { state.interactionCount = 0; }
const answerPlaceholders = {
  stateless: byId("stateless-answer").innerHTML,
  grounded: byId("grounded-answer").innerHTML,
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "The request could not be completed.";
    throw new Error(detail);
  }
  return data;
}

function renderMarkdown(target, markdown) {
  if (!window.marked || !window.DOMPurify) {
    target.textContent = markdown || "";
    return;
  }
  target.innerHTML = DOMPurify.sanitize(marked.parse(markdown || ""));
}

function toast(message) {
  const node = byId("toast");
  node.textContent = message;
  node.classList.add("visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => node.classList.remove("visible"), 2800);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  const text = button.querySelector(".submit-label, .ingest-label, .lesson-submit-label");
  if (text && label) text.textContent = label;
  button.style.opacity = busy ? ".65" : "";
  button.style.cursor = busy ? "wait" : "";
}

function updateInteractionCounter() {
  const memoryCount = byId("memory-count").textContent;
  byId("interaction-counter").textContent = `Interaction ${state.interactionCount} | Lessons in memory: ${memoryCount}`;
}

function recordInteraction() {
  state.interactionCount += 1;
  try { sessionStorage.setItem("incidentops-interaction-count", String(state.interactionCount)); }
  catch { /* Keep the in-memory counter working when browser storage is unavailable. */ }
  updateInteractionCounter();
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === `panel-${name}`));
  const comparisonSlot = byId(name === "ingest" ? "ingest-comparison-slot" : "triage-comparison-slot");
  comparisonSlot.append(byId("comparison-grid"));
}

document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => switchTab(tab.dataset.tab)));

function setAnswer(targetId, text) {
  const cleaned = String(text || "No answer returned.").replace(/\[(?:observation|world)\]\s*/gi, "");
  renderMarkdown(byId(targetId), cleaned);
}

function updateRecallCount(recalledCount) {
  const memoryCount = Number(byId("memory-count").textContent) || 0;
  byId("recall-count-text").textContent = `Recalled ${recalledCount} of ${memoryCount} lessons for this answer`;
}

function normalizeAdvice(text) {
  return String(text || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function highlightGroundedDifferences(result) {
  const statelessAnswer = byId("stateless-answer");
  const groundedAnswer = byId("grounded-answer");
  const steps = Array.from(groundedAnswer.querySelectorAll("li"))
    .filter((step) => !step.parentElement.closest("li"));
  steps.forEach((step) => step.classList.remove("memory-difference"));
  if (result.out_of_scope || result.stateless?.error || result.grounded?.error) return;

  const baseline = normalizeAdvice(statelessAnswer.textContent);
  if (!baseline) return;
  steps.forEach((step) => {
    const advice = normalizeAdvice(step.textContent);
    if (advice && !baseline.includes(advice)) step.classList.add("memory-difference");
  });
}

function setTriageResult(result, question) {
  state.lastQuestion = question;
  state.lastAnswer = result.grounded?.answer || "";
  state.lastOutOfScope = Boolean(result.out_of_scope);
  setAnswer("stateless-answer", result.stateless?.answer || "No answer returned.");
  setAnswer("grounded-answer", result.grounded?.answer || "No answer returned.");
  highlightGroundedDifferences(result);
  byId("stateless-latency").textContent = `${result.stateless?.latency_ms ?? 0} ms`;
  byId("grounded-latency").textContent = `${result.grounded?.latency_ms ?? 0} ms`;
  const count = Number(result.recalled_count) || 0;
  byId("grounding-text").textContent = `Grounded on ${count} recalled ${count === 1 ? "lesson" : "lessons"}`;
  updateRecallCount(count);
  byId("learned-badge").classList.toggle("hidden", count === 0);
  const sources = byId("recalled-sources");
  sources.replaceChildren();
  if (count > 0) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = `RECALLED SOURCES (${count})`;
    details.append(summary);
    (result.memories || []).forEach((memory) => {
      const item = document.createElement("div");
      item.className = "source-memory";
      item.textContent = String(memory.text || "").replace(/\[(?:observation|world)\]\s*/gi, "");
      details.append(item);
    });
    sources.append(details);
  }
  sources.classList.toggle("hidden", count === 0);
  byId("approval-callout").classList.toggle("hidden", result.out_of_scope || Boolean(result.stateless?.error && result.grounded?.error));
}

const ERROR_PATTERN_SIGNAL = /\b(?:error|fatal|fail(?:ed|ure|ures)?|exceptions?|panic|critical|alert|denied|timeout)\b/i;

function normalizeErrorPattern(line) {
  const bglMessage = line.match(/\b(?:INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+(.+)$/i);
  return (bglMessage?.[1] || line).toLowerCase()
    .replace(/\b\d{4}[.-]\d{2}[.-]\d{2}(?:[ T]\d{2}[:.]\d{2}[:.]\d{2}(?:[.:]\d+)?)?/g, "<timestamp>")
    .replace(/\bR\d+-M\d+-[A-Z0-9]+-C:[A-Z0-9-]+/gi, "<node>")
    .replace(/\b0x[0-9a-f]+\b/gi, "<hex>")
    .replace(/\b\d+\b/g, "#")
    .replace(/\s+/g, " ")
    .trim();
}

function updateLogStats() {
  const lines = byId("logs-input").value.split(/\r\n|\r|\n/).filter((line) => line.trim());
  const patterns = new Set(lines.filter((line) => ERROR_PATTERN_SIGNAL.test(line)).map(normalizeErrorPattern));
  byId("log-stats").textContent = `${lines.length} lines pasted, ${patterns.size} distinct error patterns detected`;
}

byId("logs-input").addEventListener("input", updateLogStats);
updateLogStats();

byId("triage-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const question = byId("question-input").value.trim();
  if (!question) return;
  const button = event.currentTarget.querySelector("button[type=submit]");
  const requestId = ++state.triageRequestId;
  recordInteraction();
  const error = byId("triage-error");
  error.classList.add("hidden");
  byId("approval-callout").classList.add("hidden");
  setBusy(button, true, "Running...");
  try {
    const result = await api("/api/triage", { method: "POST", body: JSON.stringify({ question }) });
    if (requestId === state.triageRequestId) {
      await refreshMemories();
      if (requestId === state.triageRequestId) setTriageResult(result, question);
    }
  } catch (err) {
    error.textContent = err.message;
    error.classList.remove("hidden");
  } finally {
    setBusy(button, false, "Run triage");
  }
});

const lessonDialog = byId("lesson-dialog");
function openLesson(question, answer) {
  if (state.lastOutOfScope) return;
  const text = `Incident: ${question}\n\nApproved response / lesson: ${answer}`;
  byId("lesson-input").value = text.slice(0, 5000);
  byId("lesson-error").classList.add("hidden");
  lessonDialog.showModal();
}
byId("approve-button").addEventListener("click", () => openLesson(state.lastQuestion, state.lastAnswer));
byId("reject-button").addEventListener("click", () => {
  byId("approval-callout").classList.add("hidden");
  toast("Response rejected. Nothing was retained.");
});
byId("close-dialog").addEventListener("click", () => lessonDialog.close());
byId("cancel-lesson").addEventListener("click", () => lessonDialog.close());

function readTimeline() {
  const bankId = byId("bank-label").textContent;
  try { return JSON.parse(localStorage.getItem(`incidentops-approved-lessons:${bankId}`) || "[]"); }
  catch { return []; }
}
function writeTimeline(entries) {
  const bankId = byId("bank-label").textContent;
  localStorage.setItem(`incidentops-approved-lessons:${bankId}`, JSON.stringify(entries));
}
function renderTimeline() {
  const entries = readTimeline();
  byId("timeline-count").textContent = String(entries.length);
  const list = byId("timeline-list");
  list.replaceChildren();
  if (!entries.length) {
    const empty = document.createElement("div");
    empty.className = "large-empty";
    empty.innerHTML = '<span class="empty-icon">↳</span><strong>No approved lessons yet</strong><p>Run a triage, then approve a useful lesson to begin building team memory.</p>';
    list.append(empty);
    return;
  }
  entries.forEach((entry) => {
    const row = document.createElement("article");
    row.className = "timeline-entry";
    const marker = document.createElement("span");
    marker.className = "timeline-marker";
    const time = document.createElement("time");
    time.className = "timeline-time";
    time.textContent = new Date(entry.createdAt).toLocaleString();
    const content = document.createElement("div");
    content.className = "timeline-content";
    const title = document.createElement("h3");
    title.textContent = "Engineer-approved lesson";
    const text = document.createElement("p");
    text.textContent = entry.lesson;
    const source = document.createElement("div");
    source.className = "timeline-source";
    source.textContent = "RETAINED IN HINDSIGHT · HUMAN APPROVED";
    content.append(title, text, source);
    row.append(marker, time, content);
    list.append(row);
  });
}

byId("lesson-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const lesson = byId("lesson-input").value.trim();
  if (lesson.length < 10) return;
  const button = event.currentTarget.querySelector("button[type=submit]");
  setBusy(button, true, "Saving...");
  try {
    await api("/api/lessons/approve", { method: "POST", body: JSON.stringify({ lesson, question: state.lastQuestion, answer: state.lastAnswer }) });
    const entries = readTimeline();
    entries.unshift({ lesson, createdAt: new Date().toISOString() });
    writeTimeline(entries);
    lessonDialog.close();
    byId("approval-callout").classList.add("hidden");
    renderTimeline();
    await refreshMemories();
    toast("Lesson approved and retained in Hindsight.");
  } catch (err) {
    byId("lesson-error").textContent = err.message;
    byId("lesson-error").classList.remove("hidden");
  } finally {
    setBusy(button, false, "Approve and save");
  }
});

function flattenMemoryResponse(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  for (const key of ["memories", "results", "items", "data"]) {
    if (Array.isArray(value[key])) return value[key];
    if (value[key] && typeof value[key] === "object") {
      const nested = flattenMemoryResponse(value[key]);
      if (nested.length) return nested;
    }
  }
  return [];
}
function updateMemoryCount(count) {
  byId("memory-count").textContent = String(count);
  byId("memory-count-label").textContent = `${count === 1 ? "memory unit" : "memory units"} in bank`;
  byId("memory-bar").style.width = `${Math.min(100, count * 10)}%`;
  updateInteractionCounter();
}
async function refreshMemories() {
  const list = byId("memory-list");
  try {
    const result = await api("/api/memories");
    const rows = flattenMemoryResponse(result.items);
    list.replaceChildren();
    updateMemoryCount(Number(result.total) || rows.length);
    if (!rows.length) {
      const empty = document.createElement("div");
      empty.className = "large-empty";
      empty.innerHTML = '<span class="empty-icon">⌕</span><strong>This bank is empty</strong><p>Approve a lesson or run the real-data seed script to begin.</p>';
      list.append(empty);
      return;
    }
    rows.forEach((item) => {
      const text = typeof item === "string" ? item : (item.text || item.content || JSON.stringify(item));
      const card = document.createElement("article");
      card.className = "memory-card";
      const body = document.createElement("p");
      body.textContent = text;
      const meta = document.createElement("div");
      meta.className = "memory-meta";
      const type = document.createElement("span");
      type.textContent = typeof item === "object" ? (item.type || "MEMORY UNIT") : "MEMORY UNIT";
      const source = document.createElement("span");
      source.className = "memory-source-label";
      source.textContent = typeof item === "object" ? (item.source_label || "other source") : "other source";
      const id = document.createElement("span");
      id.textContent = typeof item === "object" && item.id ? String(item.id).slice(0, 12) : "HINDSIGHT";
      meta.append(type, source, id);
      card.append(body, meta);
      list.append(card);
    });
  } catch (err) {
    list.innerHTML = "";
    const empty = document.createElement("div");
    empty.className = "large-empty";
    empty.textContent = err.message;
    list.append(empty);
  }
}
byId("refresh-memories").addEventListener("click", async () => {
  const button = byId("refresh-memories");
  button.disabled = true;
  try { await refreshMemories(); }
  finally { button.disabled = false; }
});

byId("resolution-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const problem = byId("resolution-problem").value.trim();
  const solution = byId("resolution-solution").value.trim();
  const error = byId("resolution-error");
  error.classList.add("hidden");
  if (problem.length < 10 || solution.length < 10) {
    error.textContent = "Problem and Solution must each contain at least 10 non-whitespace characters.";
    error.classList.remove("hidden");
    return;
  }
  const button = form.querySelector("button[type=submit]");
  setBusy(button, true, "Logging...");
  try {
    const payload = { problem, solution };
    console.log("[Log Resolution] POST /api/resolutions/log payload:", payload);
    await api("/api/resolutions/log", { method: "POST", body: JSON.stringify(payload) });
    form.reset();
    await refreshMemories();
    toast("Resolution logged directly to Hindsight.");
  } catch (err) {
    error.textContent = err.message;
    error.classList.remove("hidden");
  } finally {
    setBusy(button, false, "Log resolution");
  }
});

document.querySelectorAll(".sandbox-form").forEach((form) => form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const kind = form.dataset.kind;
  const query = form.elements.query.value.trim();
  if (!query) return;
  const output = byId(`${kind}-output`);
  output.textContent = "Querying Hindsight...";
  const button = form.querySelector("button");
  button.disabled = true;
  try {
    const result = await api(`/api/${kind}`, { method: "POST", body: JSON.stringify({ query }) });
    output.textContent = JSON.stringify(result, null, 2);
  } catch (err) {
    output.textContent = err.message;
  } finally {
    button.disabled = false;
  }
}));

byId("load-sample").addEventListener("click", async () => {
  const button = byId("load-sample");
  const scenario = byId("bgl-scenario").value;
  const error = byId("ingest-error");
  error.classList.add("hidden");
  if (!scenario) {
    error.textContent = "Choose a LogHub BGL scenario first.";
    error.classList.remove("hidden");
    return;
  }
  button.disabled = true;
  try {
    const result = await api(`/api/loghub-sample?scenario=${encodeURIComponent(scenario)}`);
    byId("logs-input").value = result.logs;
    updateLogStats();
    toast(`Loaded ${result.label} from LogHub BGL.`);
  } catch (err) {
    error.textContent = err.message;
    error.classList.remove("hidden");
  } finally { button.disabled = false; }
});

byId("ingest-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const logs = byId("logs-input").value.trim();
  if (!logs) return;
  const button = event.currentTarget.querySelector("button[type=submit]");
  const error = byId("ingest-error");
  error.classList.add("hidden");
  byId("ingest-approval").classList.add("hidden");
  recordInteraction();
  setBusy(button, true, "Analyzing...");
  const requestId = ++state.triageRequestId;
  try {
    const result = await api("/api/ingest", { method: "POST", body: JSON.stringify({ logs }) });
    if (requestId !== state.triageRequestId) return;
    await refreshMemories();
    if (requestId !== state.triageRequestId) return;
    setTriageResult(result, "Triage these supplied system logs:\n" + logs.slice(0, 1200));
    byId("ingest-approval").classList.toggle("hidden", result.out_of_scope || Boolean(result.stateless?.error && result.grounded?.error));
  } catch (err) {
    if (requestId === state.triageRequestId) {
      error.textContent = err.message;
      error.classList.remove("hidden");
    }
  } finally { setBusy(button, false, "Triage logs"); }
});

byId("ingest-approve").addEventListener("click", () => openLesson(state.lastQuestion, state.lastAnswer));

byId("reset-button").addEventListener("click", async () => {
  if (!window.confirm("Switch to a new empty memory bank? Existing banks are not deleted.")) return;
  const button = byId("reset-button");
  button.disabled = true;
  try {
    const result = await api("/api/reset", { method: "POST" });
    byId("bank-label").textContent = result.bank_id;
    byId("memory-bank-small").textContent = result.bank_id;
    state.triageRequestId += 1;
    state.lastQuestion = "";
    state.lastAnswer = "";
    state.lastOutOfScope = false;
    byId("question-input").value = "";
    byId("stateless-answer").innerHTML = answerPlaceholders.stateless;
    byId("grounded-answer").innerHTML = answerPlaceholders.grounded;
    byId("stateless-latency").textContent = "—";
    byId("grounded-latency").textContent = "—";
    byId("grounding-text").textContent = "Grounded on 0 recalled lessons";
    updateRecallCount(0);
    byId("learned-badge").classList.add("hidden");
    byId("recalled-sources").replaceChildren();
    byId("recalled-sources").classList.add("hidden");
    byId("triage-error").textContent = "";
    byId("triage-error").classList.add("hidden");
    updateMemoryCount(0);
    renderTimeline();
    byId("timeline-count").textContent = "0";
    byId("memory-list").innerHTML = '<div class="large-empty"><span class="empty-icon">⌕</span><strong>This bank is empty</strong><p>Approve a lesson or run the real-data seed script to begin.</p></div>';
    byId("approval-callout").classList.add("hidden");
    toast("Cold Start active. A fresh empty bank is ready.");
  } catch (err) { toast(err.message); }
  finally { button.disabled = false; }
});

async function loadStatus() {
  try {
    const status = await api("/api/status");
    byId("bank-label").textContent = status.bank_id;
    byId("memory-bank-small").textContent = status.bank_id;
    const hindsight = byId("hindsight-dot");
    const groq = byId("groq-dot");
    hindsight.classList.add(status.hindsight_connected ? "ready" : "down");
    groq.classList.add(status.groq_connected ? "ready" : "down");
    hindsight.title = status.hindsight_connected ? "Hindsight connected" : "Hindsight unavailable or not configured";
    groq.title = status.groq_connected ? "Groq connected" : "Groq unavailable or not configured";
    renderTimeline();
  } catch { /* The main panels will surface specific connection errors. */ }
}

renderTimeline();
updateInteractionCounter();
loadStatus();
refreshMemories();
