<template>
  <Teleport to="body">
    <div class="modal-backdrop" @click.self="$emit('close')">
      <div class="modal-box">

        <!-- Header -->
        <div class="modal-header">
          <div class="modal-header-left">
            <span class="dot dot-purple"></span>
            <span class="modal-source mono">MITRE ATT&CK</span>
            <span class="modal-id mono">{{ techniqueId }}</span>
          </div>
          <button class="btn-close" @click="$emit('close')" aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <line x1="1" y1="1" x2="13" y2="13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              <line x1="13" y1="1" x2="1" y2="13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            </svg>
          </button>
        </div>

        <!-- Loading -->
        <div v-if="isLoading" class="modal-loading">
          <div class="spinner-lg"></div>
          <span class="mono" style="font-size:12px;color:var(--text-muted)">Fetching technique data...</span>
        </div>

        <!-- Error -->
        <div v-else-if="error" class="modal-error">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style="flex-shrink:0">
            <circle cx="8" cy="8" r="6.5" stroke="var(--risk-critical)" stroke-width="1.3"/>
            <line x1="8" y1="4" x2="8" y2="9" stroke="var(--risk-critical)" stroke-width="1.3" stroke-linecap="round"/>
            <circle cx="8" cy="12" r="0.8" fill="var(--risk-critical)"/>
          </svg>
          {{ error }}
        </div>

        <!-- Content -->
        <template v-else-if="data">
          <!-- Hero -->
          <div class="technique-hero">
            <div class="hero-left">
              <div class="technique-id mono">{{ data.id }}</div>
              <div class="technique-name">{{ data.name }}</div>
            </div>
            <div class="hero-badges">
              <span v-for="tactic in data.taktyki" :key="tactic" class="badge badge-medium">
                {{ formatTactic(tactic) }}
              </span>
              <span v-for="platform in data.platforms" :key="platform" class="badge badge-neutral">
                {{ platform }}
              </span>
            </div>
          </div>

          <div class="modal-body">
            <!-- Description -->
            <div v-if="data.opis" class="section">
              <div class="section-label mono">Description</div>
              <div class="technique-desc" v-html="cleanDesc(data.opis)"></div>
            </div>

            <!-- Detection -->
            <div v-if="data.detection" class="section">
              <div class="section-label mono">Detection</div>
              <div class="technique-desc" v-html="cleanDesc(data.detection)"></div>
            </div>

            <!-- Footer link -->
            <div v-if="data.url" class="modal-footer">
              <a :href="data.url" target="_blank" rel="noopener" class="ext-link">
                <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                  <path d="M10 2H7M10 2V5M10 2L5.5 6.5M9 7v3H2V3h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                View on MITRE ATT&CK
              </a>
            </div>
          </div>
        </template>

      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const props = defineProps({ techniqueId: { type: String, required: true } })
const emit = defineEmits(['close'])

const data = ref(null)
const isLoading = ref(true)
const error = ref(null)

async function fetchTechnique() {
  isLoading.value = true
  error.value = null
  try {
    const res = await fetch(`/api/analyze/apt/technique/?id=${encodeURIComponent(props.techniqueId)}`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    data.value = await res.json()
  } catch (e) {
    error.value = `Failed to load technique: ${e.message}`
  } finally {
    isLoading.value = false
  }
}

function formatTactic(t) {
  return t.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function cleanDesc(text) {
  if (!text) return ''
  return text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '<strong>$1</strong>')
    .replace(/\(Citation:[^)]+\)/g, '')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n\*/g, '</p><ul><li>')
    .replace(/\n/g, '<br>')
    .replace(/<\/li>\s*<li>/g, '</li><li>')
}

function onKey(e) { if (e.key === 'Escape') emit('close') }
onMounted(() => {
  fetchTechnique()
  document.addEventListener('keydown', onKey)
  document.body.style.overflow = 'hidden'
})
onUnmounted(() => {
  document.removeEventListener('keydown', onKey)
  document.body.style.overflow = ''
})
</script>

<style scoped>
.modal-backdrop {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0, 0, 0, 0.75);
  display: flex; align-items: center; justify-content: center;
  padding: 24px; backdrop-filter: blur(4px);
  animation: fadeIn 0.15s ease;
}
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

.modal-box {
  background: var(--bg-card); border: 1px solid var(--border-active);
  border-radius: 10px; width: 100%; max-width: 680px;
  max-height: 80vh; display: flex; flex-direction: column;
  animation: slideUp 0.2s ease; overflow: hidden;
}
@keyframes slideUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }

.modal-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 20px; border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.modal-header-left { display: flex; align-items: center; gap: 10px; }
.modal-source { font-size: 11px; color: var(--accent-purple); letter-spacing: 0.1em; }
.modal-id { font-size: 10px; color: var(--text-muted); }
.dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.dot-purple { background: var(--accent-purple); }

.btn-close {
  width: 28px; height: 28px; border-radius: 5px;
  display: flex; align-items: center; justify-content: center;
  border: 1px solid var(--border); background: transparent;
  color: var(--text-secondary); cursor: pointer; transition: all 0.15s;
}
.btn-close:hover { border-color: var(--border-active); color: var(--text-primary); background: rgba(255,255,255,0.05); }

.modal-loading, .modal-error {
  padding: 48px; display: flex; align-items: center; justify-content: center; gap: 14px;
}
.modal-error { color: var(--risk-critical); font-size: 13px; }
.spinner-lg {
  width: 22px; height: 22px; border: 2px solid var(--border);
  border-top-color: var(--accent-purple); border-radius: 50%;
  animation: spin 0.7s linear infinite; flex-shrink: 0;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* Hero */
.technique-hero {
  padding: 16px 20px; border-bottom: 1px solid var(--border);
  background: rgba(159, 122, 234, 0.04); flex-shrink: 0;
  display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap;
}
.technique-id { font-size: 11px; color: var(--accent-cyan); margin-bottom: 4px; }
.technique-name { font-size: 18px; font-weight: 700; color: var(--text-primary); }
.hero-badges { display: flex; flex-wrap: wrap; gap: 6px; align-items: flex-start; padding-top: 4px; }

/* Body */
.modal-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 20px; }

.section { display: flex; flex-direction: column; gap: 10px; }
.section-label { font-size: 10px; color: var(--text-muted); letter-spacing: 0.1em; text-transform: uppercase; }

.technique-desc {
  font-size: 13px; color: var(--text-secondary); line-height: 1.7;
  word-break: break-word;
}
.technique-desc :deep(code) {
  font-family: var(--font-mono); font-size: 11px;
  background: rgba(255,255,255,0.06); padding: 1px 5px;
  border-radius: 3px; color: var(--accent-cyan);
}
.technique-desc :deep(strong) { color: var(--text-primary); font-weight: 600; }
.technique-desc :deep(ul) { padding-left: 18px; margin: 6px 0; display: flex; flex-direction: column; gap: 4px; }
.technique-desc :deep(li) { color: var(--text-secondary); }
.technique-desc :deep(p) { margin-bottom: 8px; }

.modal-footer { padding-top: 12px; border-top: 1px solid var(--border); }
.ext-link {
  display: inline-flex; align-items: center; gap: 5px;
  font-family: var(--font-mono); font-size: 11px; color: var(--accent-purple);
  text-decoration: none;
}
.ext-link:hover { text-decoration: underline; }

.badge { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 4px; font-family: var(--font-mono); font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap; }
.badge-medium { background: rgba(214, 158, 46, 0.15); color: var(--risk-medium); border: 1px solid rgba(214, 158, 46, 0.3); }
.badge-neutral { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }
</style>
