<template>
  <Teleport to="body">
    <div class="modal-backdrop" @click.self="$emit('close')">
      <div class="modal-box" :class="{ loading: isLoading }">

        <!-- Header -->
        <div class="modal-header">
          <div class="modal-header-left">
            <span class="dot dot-purple"></span>
            <span class="modal-source mono">CIRCL EVENT</span>
            <span class="modal-uuid mono">{{ uuid }}</span>
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
          <span class="mono" style="font-size:12px;color:var(--text-muted)">Fetching event IOCs...</span>
        </div>

        <!-- Error -->
        <div v-else-if="error" class="modal-error">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <circle cx="8" cy="8" r="6.5" stroke="var(--risk-critical)" stroke-width="1.3"/>
            <line x1="8" y1="4" x2="8" y2="9" stroke="var(--risk-critical)" stroke-width="1.3" stroke-linecap="round"/>
            <circle cx="8" cy="12" r="0.8" fill="var(--risk-critical)"/>
          </svg>
          {{ error }}
        </div>

        <!-- Content -->
        <template v-else-if="data">
          <div class="modal-meta">
            <div class="meta-title">{{ data.info }}</div>
            <div class="meta-row">
              <span class="meta-item mono">
                <svg width="11" height="11" viewBox="0 0 11 11" fill="none"><rect x="1" y="2" width="9" height="8" rx="1" stroke="currentColor" stroke-width="1.2"/><line x1="3.5" y1="1" x2="3.5" y2="3.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/><line x1="7.5" y1="1" x2="7.5" y2="3.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
                {{ data.date }}
              </span>
              <span v-if="data.from_cache" class="badge badge-neutral" style="font-size:10px">cached</span>
              <span class="badge badge-info" style="margin-left:auto">{{ data.ioc_count }} IOCs</span>
            </div>
          </div>

          <!-- IOC table -->
          <div class="ioc-table-wrap">
            <table class="ioc-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Threat level</th>
                  <th>Kill chain</th>
                  <th>IDS</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(ioc, i) in data.iocs" :key="i" class="ioc-tr">
                  <td>
                    <span class="badge" :class="typeClass(ioc.type)">{{ ioc.type }}</span>
                  </td>
                  <td>
                    <span class="ioc-value mono">{{ ioc.value }}</span>
                    <div v-if="ioc.comment" class="ioc-comment">{{ ioc.comment }}</div>
                  </td>
                  <td>
                    <span v-if="threatLevel(ioc)" class="badge" :class="threatClass(ioc)">
                      {{ threatLevel(ioc) }}
                    </span>
                    <span v-else class="text-muted">—</span>
                  </td>
                  <td>
                    <span v-if="killChain(ioc)" class="kill-chain-badge">{{ killChain(ioc) }}</span>
                    <span v-else class="text-muted">—</span>
                  </td>
                  <td>
                    <span class="ids-dot" :class="{ active: ioc.to_ids }">
                      {{ ioc.to_ids ? '✓' : '—' }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Tag cloud -->
          <div v-if="allTags.length" class="tag-section">
            <div class="tag-section-label mono">All tags</div>
            <div class="tag-cloud">
              <span v-for="tag in allTags" :key="tag" class="tag-pill">{{ tag }}</span>
            </div>
          </div>
        </template>

      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'

const props = defineProps({ uuid: { type: String, required: true } })
const emit = defineEmits(['close'])

const data = ref(null)
const isLoading = ref(true)
const error = ref(null)

async function fetchEvent() {
  isLoading.value = true
  error.value = null
  try {
    const res = await fetch(`/api/circl/event/?uuid=${encodeURIComponent(props.uuid)}`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    data.value = await res.json()
  } catch (e) {
    error.value = `Failed to load event: ${e.message}`
  } finally {
    isLoading.value = false
  }
}

function handleKeydown(e) {
  if (e.key === 'Escape') emit('close')
}

onMounted(() => {
  fetchEvent()
  document.addEventListener('keydown', handleKeydown)
  document.body.style.overflow = 'hidden'
})

onUnmounted(() => {
  document.removeEventListener('keydown', handleKeydown)
  document.body.style.overflow = ''
})

// Helpers
function typeClass(type) {
  if (type?.startsWith('ip')) return 'badge-medium'
  if (type?.startsWith('domain') || type?.startsWith('hostname')) return 'badge-info'
  if (type?.startsWith('url')) return 'badge-high'
  if (type?.startsWith('md5') || type?.startsWith('sha')) return 'badge-neutral'
  return 'badge-neutral'
}

function threatLevel(ioc) {
  const tag = ioc.tags?.find(t => t.includes('threat-level'))
  if (!tag) return null
  const m = tag.match(/"([^"]+)"/)
  return m ? m[1] : null
}

function threatClass(ioc) {
  const lvl = threatLevel(ioc)
  if (!lvl) return 'badge-neutral'
  if (lvl.includes('high')) return 'badge-critical'
  if (lvl.includes('medium')) return 'badge-medium'
  if (lvl.includes('low')) return 'badge-low'
  return 'badge-neutral'
}

function killChain(ioc) {
  const tag = ioc.tags?.find(t => t.startsWith('kill-chain:'))
  return tag ? tag.replace('kill-chain:', '') : null
}

const allTags = computed(() => {
  if (!data.value?.iocs) return []
  const set = new Set()
  data.value.iocs.forEach(ioc => ioc.tags?.forEach(t => set.add(t)))
  return [...set]
})
</script>

<style scoped>
.modal-backdrop {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0, 0, 0, 0.75);
  display: flex; align-items: center; justify-content: center;
  padding: 24px;
  backdrop-filter: blur(4px);
  animation: fadeBackdrop 0.15s ease;
}
@keyframes fadeBackdrop {
  from { opacity: 0; }
  to { opacity: 1; }
}

.modal-box {
  background: var(--bg-card);
  border: 1px solid var(--border-active);
  border-radius: 10px;
  width: 100%; max-width: 820px;
  max-height: 80vh;
  display: flex; flex-direction: column;
  animation: slideUp 0.2s ease;
  overflow: hidden;
}
@keyframes slideUp {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Header */
.modal-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 20px; border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.modal-header-left { display: flex; align-items: center; gap: 10px; }
.modal-source { font-size: 11px; color: var(--accent-cyan); letter-spacing: 0.1em; }
.modal-uuid { font-size: 10px; color: var(--text-muted); }
.dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.dot-purple { background: var(--accent-purple); }

.btn-close {
  width: 28px; height: 28px; border-radius: 5px;
  display: flex; align-items: center; justify-content: center;
  border: 1px solid var(--border); background: transparent;
  color: var(--text-secondary); cursor: pointer; transition: all 0.15s;
}
.btn-close:hover { border-color: var(--border-active); color: var(--text-primary); background: rgba(255,255,255,0.05); }

/* States */
.modal-loading, .modal-error {
  padding: 48px; display: flex; align-items: center; justify-content: center; gap: 14px;
}
.modal-error { color: var(--risk-critical); font-size: 13px; }
.spinner-lg {
  width: 22px; height: 22px; border: 2px solid var(--border);
  border-top-color: var(--accent-cyan); border-radius: 50%;
  animation: spin 0.7s linear infinite; flex-shrink: 0;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* Meta */
.modal-meta {
  padding: 16px 20px; border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.meta-title { font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px; }
.meta-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.meta-item {
  display: flex; align-items: center; gap: 5px;
  font-size: 11px; color: var(--text-muted);
}

/* IOC table */
.ioc-table-wrap { flex: 1; overflow-y: auto; padding: 0 4px; }
.ioc-table { width: 100%; border-collapse: collapse; }
.ioc-table thead tr {
  position: sticky; top: 0;
  background: var(--bg-secondary);
}
.ioc-table th {
  padding: 10px 16px; text-align: left;
  font-size: 10px; font-weight: 600; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.08em;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
.ioc-tr { border-bottom: 1px solid var(--border); transition: background 0.1s; }
.ioc-tr:last-child { border-bottom: none; }
.ioc-tr:hover { background: rgba(255,255,255,0.03); }
.ioc-table td { padding: 10px 16px; vertical-align: top; }

.ioc-value { font-size: 12px; color: var(--accent-cyan); display: block; word-break: break-all; }
.ioc-comment { font-size: 11px; color: var(--text-muted); margin-top: 3px; line-height: 1.4; }

.kill-chain-badge {
  font-size: 11px; color: var(--accent-purple);
  font-family: var(--font-mono);
}

.ids-dot { font-size: 12px; font-family: var(--font-mono); }
.ids-dot.active { color: var(--accent-green); }
.ids-dot:not(.active) { color: var(--text-muted); }

/* Tags */
.tag-section {
  padding: 12px 20px; border-top: 1px solid var(--border); flex-shrink: 0;
}
.tag-section-label { font-size: 10px; color: var(--text-muted); letter-spacing: 0.08em; margin-bottom: 8px; }
.tag-cloud { display: flex; flex-wrap: wrap; gap: 5px; }
.tag-pill {
  font-family: var(--font-mono); font-size: 10px;
  padding: 2px 7px; border-radius: 3px;
  background: rgba(159, 122, 234, 0.08);
  border: 1px solid rgba(159, 122, 234, 0.2);
  color: var(--accent-purple);
}

.text-muted { color: var(--text-muted); font-size: 12px; }

/* Badge overrides for this context */
.badge { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 4px; font-family: var(--font-mono); font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap; }
.badge-critical { background: rgba(229, 62, 62, 0.15); color: var(--risk-critical); border: 1px solid rgba(229, 62, 62, 0.3); }
.badge-high { background: rgba(221, 107, 32, 0.15); color: var(--risk-high); border: 1px solid rgba(221, 107, 32, 0.3); }
.badge-medium { background: rgba(214, 158, 46, 0.15); color: var(--risk-medium); border: 1px solid rgba(214, 158, 46, 0.3); }
.badge-low { background: rgba(56, 161, 105, 0.15); color: var(--risk-low); border: 1px solid rgba(56, 161, 105, 0.3); }
.badge-info { background: rgba(66, 153, 225, 0.15); color: var(--accent-blue); border: 1px solid rgba(66, 153, 225, 0.3); }
.badge-neutral { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }
</style>
