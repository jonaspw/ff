// frontend/src/api/analyze.js

const API_BASE = "http://127.0.0.1:8000/api";

function getConfigHeader() {
  try {
    return localStorage.getItem("scoring_config") || "";
  } catch {
    return "";
  }
}

export async function analyzeQuery(query) {
  const headers = { "Content-Type": "application/json" };
  const config = getConfigHeader();
  if (config) headers["X-Scoring-Config"] = config;

  const res = await fetch(
    `${API_BASE}/analyze/?q=${encodeURIComponent(query)}`,
    { headers }
  );
  return res.json();
}

export async function analyzeAPT(name) {
  const headers = {};
  const config = getConfigHeader();
  if (config) headers["X-Scoring-Config"] = config;

  const res = await fetch(
    `${API_BASE}/analyze/apt/?name=${encodeURIComponent(name)}`,
    { headers }
  );
  return res.json();
}
