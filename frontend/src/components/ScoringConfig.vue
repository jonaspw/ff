
<template>
  <div class="scoring-config">
    <div class="config-header">
      <div class="header-title-row">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <circle cx="8" cy="8" r="6.5" stroke="var(--accent-cyan)" stroke-width="1.3"/>
          <path d="M8 5v3l2 1.5" stroke="var(--accent-cyan)" stroke-width="1.3" stroke-linecap="round"/>
        </svg>
        <span class="config-title mono">SCORING CONFIGURATION</span>
      </div>
      <p class="config-desc">
        Set the contribution of each source to the final risk score.
        The sum of the weights of active sources must equal 100%.
        Settings are saved locally in the browser.
      </p>
    </div>

    <!-- Źródła -->
    <div class="sources-list">
      <div
        v-for="source in SOURCES"
        :key="source.id"
        class="source-row card"
        :class="{ disabled: !config.enabled[source.id] }"
      >
        <div class="source-left">
          <div class="source-dot" :style="{ background: source.color }"></div>
          <div class="source-info">
            <div class="source-name mono">{{ source.name }}</div>
            <div class="source-desc">{{ source.desc }}</div>
          </div>
        </div>

        <div class="source-right">
          <div class="weight-control">
            <input
              type="range"
              min="0"
              max="100"
              step="1"
              :value="config.weights[source.id]"
              :disabled="!config.enabled[source.id]"
              @input="updateWeight(source.id, $event.target.value)"
              class="range-input"
            />
            <span class="weight-val mono" :style="{ color: config.enabled[source.id] ? weightColor(config.weights[source.id]) : 'var(--text-muted)' }">
              {{ config.weights[source.id] }}%
            </span>
          </div>

          <label class="toggle">
            <input
              type="checkbox"
              :checked="config.enabled[source.id]"
              @change="toggleEnabled(source.id, $event.target.checked)"
            />
            <span class="toggle-track">
              <span class="toggle-thumb"></span>
            </span>
          </label>
        </div>
      </div>
    </div>

    <!-- Pasek sumy -->
    <div class="sum-bar" :class="total === 100 ? 'ok' : 'warn'">
      <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
        <circle cx="6.5" cy="6.5" r="5.5" stroke="currentColor" stroke-width="1.2"/>
        <path v-if="total === 100" d="M4 6.5l1.8 1.8L9 4.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
        <line v-else x1="6.5" y1="3.5" x2="6.5" y2="7.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
        <circle v-if="total !== 100" cx="6.5" cy="9.5" r="0.7" fill="currentColor"/>
      </svg>
      <span v-if="total === 100">Suma wag: 100% — gotowe do zapisu</span>
      <span v-else>Suma wag: <strong>{{ total }}%</strong> — wymagane 100%</span>
      <div class="sum-progress">
        <div class="sum-fill" :style="{ width: Math.min(total, 100) + '%' }" :class="total === 100 ? 'ok' : total > 100 ? 'over' : 'under'"></div>
      </div>
    </div>

    <p v-if="errorMsg" class="error-msg mono">{{ errorMsg }}</p>

    <!-- Przyciski -->
    <div class="actions">
      <button class="btn-reset" @click="handleReset">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M1 6a5 5 0 1 0 1.5-3.5L1 4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M1 1v3h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        Przywróć domyślne
      </button>
      <button class="btn-save" :disabled="total !== 100" @click="handleSave">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 6.5l2.5 2.5L10 3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
        {{ savedMsg || 'Zapisz ustawienia' }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const SOURCES = [
  { id: 'virustotal', name: 'VirusTotal', color: 'var(--accent-blue)',   desc: 'Analiza wielosilnikowa AV — malicious, suspicious, detection ratio' },
  { id: 'abuseipdb',  name: 'AbuseIPDB',  color: 'var(--risk-critical)', desc: 'Abuse score 0–100 oparty na zgłoszeniach społeczności' },
  { id: 'threatfox',  name: 'ThreatFox',  color: 'var(--accent-orange)', desc: 'Baza IOC z confidence level i typem zagrożenia' },
  { id: 'circl',      name: 'CIRCL',      color: 'var(--accent-purple)', desc: 'Eventy APT z tagami MISP threat-level i kill-chain' },
  { id: 'shodan',     name: 'Shodan',     color: '#e8073a',              desc: 'CVE, tagi infrastruktury, bannery HTTP, porty C2' },
]

const DEFAULT_CONFIG = {
  weights: { virustotal: 20, abuseipdb: 20, threatfox: 20, circl: 20, shodan: 20 },
  enabled: { virustotal: true, abuseipdb: true, threatfox: true, circl: true, shodan: true },
}

function loadConfig() {
  try {
    const saved = localStorage.getItem('scoring_config')
    return saved ? JSON.parse(saved) : structuredClone(DEFAULT_CONFIG)
  } catch {
    return structuredClone(DEFAULT_CONFIG)
  }
}

function persistConfig(cfg) {
  localStorage.setItem('scoring_config', JSON.stringify(cfg))
}

const config   = ref(loadConfig())
const errorMsg = ref('')
const savedMsg = ref('')

const total = computed(() =>
  SOURCES.reduce((sum, s) =>
    config.value.enabled[s.id] ? sum + (config.value.weights[s.id] || 0) : sum, 0)
)

function weightColor(w) {
  if (w >= 40) return 'var(--risk-high)'
  if (w >= 20) return 'var(--accent-cyan)'
  return 'var(--text-secondary)'
}

function updateWeight(id, value) {
  config.value.weights[id] = parseInt(value)
  errorMsg.value = ''
  savedMsg.value = ''
}

function toggleEnabled(id, checked) {
  config.value.enabled[id] = checked
  errorMsg.value = ''
  savedMsg.value = ''
}

function handleSave() {
  if (total.value !== 100) {
    errorMsg.value = `Suma wag musi wynosić 100% (aktualnie: ${total.value}%)`
    return
  }
  persistConfig(config.value)
  savedMsg.value = '✓ Zapisano'
  errorMsg.value = ''
  setTimeout(() => (savedMsg.value = ''), 2000)
}

function handleReset() {
  config.value = structuredClone(DEFAULT_CONFIG)
  persistConfig(config.value)
  savedMsg.value = '✓ Przywrócono'
  errorMsg.value = ''
  setTimeout(() => (savedMsg.value = ''), 2000)
}
</script>

<style scoped>
.scoring-config {
  max-width: 680px;
  padding: 32px 0 80px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.config-header { display: flex; flex-direction: column; gap: 10px; }
.header-title-row { display: flex; align-items: center; gap: 8px; }
.config-title { font-size: 12px; letter-spacing: 0.12em; color: var(--accent-cyan); }
.config-desc { font-size: 13px; color: var(--text-secondary); line-height: 1.6; }

/* Source rows */
.sources-list { display: flex; flex-direction: column; gap: 8px; }

.source-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; padding: 14px 18px;
  transition: opacity 0.2s, border-color 0.2s;
}
.source-row.disabled { opacity: 0.45; }

.source-left { display: flex; align-items: center; gap: 12px; flex: 1; min-width: 0; }
.source-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.source-info { min-width: 0; }
.source-name { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.source-desc { font-size: 11px; color: var(--text-muted); margin-top: 2px; line-height: 1.4; }

.source-right { display: flex; align-items: center; gap: 16px; flex-shrink: 0; }

/* Range slider */
.weight-control { display: flex; align-items: center; gap: 10px; }
.range-input {
  width: 120px; height: 4px;
  -webkit-appearance: none; appearance: none;
  background: var(--border); border-radius: 2px; outline: none;
  cursor: pointer;
}
.range-input::-webkit-slider-thumb {
  -webkit-appearance: none; appearance: none;
  width: 14px; height: 14px; border-radius: 50%;
  background: var(--accent-cyan); cursor: pointer;
  border: 2px solid var(--bg-card);
  box-shadow: 0 0 0 1px var(--accent-cyan);
  transition: transform 0.15s;
}
.range-input::-webkit-slider-thumb:hover { transform: scale(1.2); }
.range-input:disabled { opacity: 0.4; cursor: not-allowed; }
.range-input:disabled::-webkit-slider-thumb { cursor: not-allowed; }
.weight-val { font-size: 13px; font-weight: 600; width: 36px; text-align: right; transition: color 0.2s; }

/* Toggle */
.toggle { position: relative; display: inline-block; cursor: pointer; }
.toggle input { opacity: 0; width: 0; height: 0; position: absolute; }
.toggle-track {
  display: block; width: 36px; height: 20px;
  background: var(--border); border-radius: 10px;
  transition: background 0.2s; position: relative;
  border: 1px solid rgba(255,255,255,0.06);
}
.toggle input:checked + .toggle-track { background: var(--accent-cyan); }
.toggle-thumb {
  position: absolute; top: 2px; left: 2px;
  width: 14px; height: 14px;
  background: var(--text-muted); border-radius: 50%;
  transition: transform 0.2s, background 0.2s;
}
.toggle input:checked + .toggle-track .toggle-thumb {
  transform: translateX(16px);
  background: var(--bg-primary);
}

/* Sum bar */
.sum-bar {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 12px 16px; border-radius: 8px;
  font-size: 13px; font-weight: 500;
  border: 1px solid;
}
.sum-bar.ok {
  background: rgba(56, 161, 105, 0.08);
  border-color: rgba(56, 161, 105, 0.25);
  color: var(--risk-low);
}
.sum-bar.warn {
  background: rgba(214, 158, 46, 0.08);
  border-color: rgba(214, 158, 46, 0.25);
  color: var(--risk-medium);
}
.sum-progress {
  width: 100%; height: 2px;
  background: rgba(255,255,255,0.08); border-radius: 1px;
  margin-top: 6px; overflow: hidden;
}
.sum-fill { height: 100%; border-radius: 1px; transition: width 0.3s ease; }
.sum-fill.ok { background: var(--risk-low); }
.sum-fill.under { background: var(--risk-medium); }
.sum-fill.over { background: var(--risk-critical); }

.error-msg { font-size: 11px; color: var(--risk-critical); padding: 0 4px; }

/* Buttons */
.actions { display: flex; gap: 8px; }
.btn-reset {
  display: flex; align-items: center; gap: 6px;
  padding: 9px 16px; border-radius: 7px;
  background: transparent; border: 1px solid var(--border);
  color: var(--text-secondary); font-size: 13px; font-family: var(--font-sans);
  cursor: pointer; transition: all 0.15s;
}
.btn-reset:hover { border-color: var(--border-active); color: var(--text-primary); }

.btn-save {
  display: flex; align-items: center; gap: 6px;
  padding: 9px 20px; border-radius: 7px;
  background: var(--accent-cyan); color: #0a0c10;
  font-size: 13px; font-weight: 600; font-family: var(--font-sans);
  border: none; cursor: pointer; transition: filter 0.2s;
}
.btn-save:hover:not(:disabled) { filter: brightness(1.1); }
.btn-save:disabled { opacity: 0.35; cursor: not-allowed; filter: none; }
</style>
