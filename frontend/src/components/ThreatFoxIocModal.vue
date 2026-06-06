<template>
  <Teleport to="body">
    <div class="modal-backdrop" @click.self="$emit('close')">
      <div class="modal-box">

        <!-- Header -->
        <div class="modal-header">
          <div class="modal-header-left">
            <span class="dot dot-orange"></span>
            <span class="modal-source mono">THREATFOX IOC</span>
            <span class="modal-id mono" v-if="ioc.id">#{{ ioc.id }}</span>
          </div>
          <button class="btn-close" @click="$emit('close')" aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <line x1="1" y1="1" x2="13" y2="13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              <line x1="13" y1="1" x2="1" y2="13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            </svg>
          </button>
        </div>

        <!-- IOC value hero -->
        <div class="ioc-hero">
          <div class="ioc-value mono">{{ ioc.ioc || ioc.value }}</div>
          <div class="ioc-badges">
            <span v-if="ioc.ioc_type" class="badge badge-neutral">{{ ioc.ioc_type }}</span>
            <span v-if="ioc.malware" class="badge badge-high">{{ ioc.malware }}</span>
            <span v-if="ioc.malware_printable && ioc.malware_printable !== ioc.malware" class="badge badge-neutral">{{ ioc.malware_printable }}</span>
            <span v-if="ioc.confidence_level !== undefined" class="badge" :class="confidenceClass">
              confidence {{ ioc.confidence_level }}%
            </span>
            <span v-if="ioc.threat_type" class="badge badge-medium">{{ ioc.threat_type }}</span>
          </div>
        </div>

        <div class="modal-body">

          <!-- Main details -->
          <div class="detail-grid">
            <div class="detail-col">
              <div class="section-label mono">Details</div>
              <div class="kv-list">
                <div class="kv" v-if="ioc.ioc_type_desc">
                  <span class="kv-key">Type</span>
                  <span class="kv-val">{{ ioc.ioc_type_desc }}</span>
                </div>
                <div class="kv" v-if="ioc.malware_alias">
                  <span class="kv-key">Aliases</span>
                  <span class="kv-val mono">{{ ioc.malware_alias }}</span>
                </div>
                <div class="kv" v-if="ioc.reporter">
                  <span class="kv-key">Reporter</span>
                  <span class="kv-val mono">{{ ioc.reporter }}</span>
                </div>
                <div class="kv" v-if="ioc.first_seen">
                  <span class="kv-key">First seen</span>
                  <span class="kv-val mono">{{ formatDate(ioc.first_seen) }}</span>
                </div>
                <div class="kv" v-if="ioc.last_seen">
                  <span class="kv-key">Last seen</span>
                  <span class="kv-val mono">{{ formatDate(ioc.last_seen) }}</span>
                </div>
                <div class="kv" v-if="ioc.threat_type_desc">
                  <span class="kv-key">Threat</span>
                  <span class="kv-val">{{ ioc.threat_type_desc }}</span>
                </div>
              </div>
            </div>

            <div class="detail-col" v-if="ioc.malware_malpedia || ioc.reference || ioc.tags?.length">
              <div class="section-label mono">References</div>
              <div class="kv-list">
                <div class="kv" v-if="ioc.reference">
                  <span class="kv-key">Source</span>
                  <a :href="ioc.reference" target="_blank" rel="noopener" class="kv-val link mono">{{ ioc.reference }}</a>
                </div>
                <div class="kv" v-if="ioc.malware_malpedia">
                  <span class="kv-key">Malpedia</span>
                  <a :href="ioc.malware_malpedia" target="_blank" rel="noopener" class="kv-val link mono">{{ ioc.malware_malpedia }}</a>
                </div>
              </div>
              <div v-if="ioc.tags?.length" class="tags-wrap">
                <div class="section-label mono" style="margin-top:14px">Tags</div>
                <div class="tag-cloud">
                  <span v-for="tag in ioc.tags" :key="tag" class="tag-pill">{{ tag }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Ports -->
          <div v-if="ioc.ports?.length" class="subsection">
            <div class="section-label mono">Ports</div>
            <div class="port-list">
              <span v-for="p in ioc.ports" :key="p" class="port-chip mono">{{ p }}</span>
            </div>
          </div>

          <!-- Fallback: show all remaining keys that have values and aren't already shown -->
          <div v-if="extraFields.length" class="subsection">
            <div class="section-label mono">Additional data</div>
            <div class="kv-list">
              <div class="kv" v-for="f in extraFields" :key="f.key">
                <span class="kv-key">{{ f.key }}</span>
                <span class="kv-val mono">{{ f.val }}</span>
              </div>
            </div>
          </div>

          <!-- External link -->
          <div class="modal-footer" v-if="ioc.id">
            <a
              :href="`https://threatfox.abuse.ch/ioc/${ioc.id}/`"
              target="_blank"
              rel="noopener"
              class="ext-link"
            >
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M10 2H7M10 2V5M10 2L5.5 6.5M9 7v3H2V3h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
              View on ThreatFox
            </a>
          </div>

        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { computed, onMounted, onUnmounted } from 'vue'

const props = defineProps({ ioc: { type: Object, required: true } })
const emit = defineEmits(['close'])

const SHOWN_KEYS = new Set([
  'id', 'ioc', 'value', 'ioc_type', 'ioc_type_desc', 'malware', 'malware_printable',
  'malware_alias', 'malware_malpedia', 'confidence_level', 'threat_type', 'threat_type_desc',
  'reporter', 'first_seen', 'last_seen', 'reference', 'tags', 'ports',
])

const extraFields = computed(() =>
  Object.entries(props.ioc)
    .filter(([k, v]) => {
      if (SHOWN_KEYS.has(k)) return false
      if (v === null || v === undefined || v === '') return false
      if (Array.isArray(v) && v.length === 0) return false
      return true
    })
    .map(([k, v]) => ({ key: k, val: typeof v === 'object' ? JSON.stringify(v) : String(v) }))
)

const confidenceClass = computed(() => {
  const c = props.ioc.confidence_level
  if (c >= 75) return 'badge-critical'
  if (c >= 50) return 'badge-high'
  if (c >= 25) return 'badge-medium'
  return 'badge-low'
})

function formatDate(d) {
  if (!d) return ''
  try { return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) }
  catch { return d }
}

function onKey(e) { if (e.key === 'Escape') emit('close') }
onMounted(() => { document.addEventListener('keydown', onKey); document.body.style.overflow = 'hidden' })
onUnmounted(() => { document.removeEventListener('keydown', onKey); document.body.style.overflow = '' })
</script>

<style scoped>
.modal-backdrop {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0, 0, 0, 0.75);
  display: flex; align-items: center; justify-content: center;
  padding: 24px; backdrop-filter: blur(4px);
  animation: fadeBackdrop 0.15s ease;
}
@keyframes fadeBackdrop { from { opacity: 0; } to { opacity: 1; } }

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
.modal-source { font-size: 11px; color: var(--accent-orange); letter-spacing: 0.1em; }
.modal-id { font-size: 10px; color: var(--text-muted); }
.dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.dot-orange { background: var(--accent-orange); }

.btn-close {
  width: 28px; height: 28px; border-radius: 5px;
  display: flex; align-items: center; justify-content: center;
  border: 1px solid var(--border); background: transparent;
  color: var(--text-secondary); cursor: pointer; transition: all 0.15s;
}
.btn-close:hover { border-color: var(--border-active); color: var(--text-primary); background: rgba(255,255,255,0.05); }

/* IOC hero */
.ioc-hero {
  padding: 16px 20px 14px; border-bottom: 1px solid var(--border);
  background: rgba(221, 107, 32, 0.04); flex-shrink: 0;
}
.ioc-value { font-size: 15px; font-weight: 600; color: var(--accent-orange); word-break: break-word; overflow-wrap: break-word; margin-bottom: 10px; }
.ioc-badges { display: flex; flex-wrap: wrap; gap: 6px; }

/* Body */
.modal-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 16px; }

.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.detail-col { display: flex; flex-direction: column; }
.section-label { font-size: 10px; color: var(--text-muted); letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 10px; }

.kv-list { display: flex; flex-direction: column; gap: 7px; }
.kv { display: flex; gap: 8px; align-items: flex-start; font-size: 12px; }
.kv-key { color: var(--text-muted); min-width: 100px; width: max-content; flex-shrink: 0; padding-top: 1px; padding-right: 8px; }
.kv-val { color: var(--text-primary); word-break: break-word; overflow-wrap: break-word; line-height: 1.4; }
.link { color: var(--accent-cyan); text-decoration: none; font-size: 11px; }
.link:hover { text-decoration: underline; }

.tags-wrap { }
.tag-cloud { display: flex; flex-wrap: wrap; gap: 5px; }
.tag-pill {
  font-family: var(--font-mono); font-size: 10px; padding: 2px 7px;
  border-radius: 3px; background: rgba(221, 107, 32, 0.08);
  border: 1px solid rgba(221, 107, 32, 0.25); color: var(--accent-orange);
}

.subsection { display: flex; flex-direction: column; gap: 8px; }
.port-list { display: flex; flex-wrap: wrap; gap: 6px; }
.port-chip {
  font-size: 11px; padding: 3px 8px; border-radius: 4px;
  background: rgba(66, 153, 225, 0.1); border: 1px solid rgba(66, 153, 225, 0.25);
  color: var(--accent-blue);
}

/* Footer */
.modal-footer { padding-top: 12px; border-top: 1px solid var(--border); }
.ext-link {
  display: inline-flex; align-items: center; gap: 5px;
  font-family: var(--font-mono); font-size: 11px; color: var(--accent-orange);
  text-decoration: none;
}
.ext-link:hover { text-decoration: underline; }

/* Badges */
.badge { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 4px; font-family: var(--font-mono); font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap; }
.badge-critical { background: rgba(229, 62, 62, 0.15); color: var(--risk-critical); border: 1px solid rgba(229, 62, 62, 0.3); }
.badge-high { background: rgba(221, 107, 32, 0.15); color: var(--risk-high); border: 1px solid rgba(221, 107, 32, 0.3); }
.badge-medium { background: rgba(214, 158, 46, 0.15); color: var(--risk-medium); border: 1px solid rgba(214, 158, 46, 0.3); }
.badge-low { background: rgba(56, 161, 105, 0.15); color: var(--risk-low); border: 1px solid rgba(56, 161, 105, 0.3); }
.badge-neutral { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }

@media (max-width: 600px) { .detail-grid { grid-template-columns: 1fr; } }
</style>
