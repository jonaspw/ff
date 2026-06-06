<template>
  <Teleport to="body">
    <div class="modal-backdrop" @click.self="$emit('close')">
      <div class="modal-box">

        <!-- Header -->
        <div class="modal-header">
          <div class="modal-header-left">
            <span class="dot dot-shodan"></span>
            <span class="modal-source mono">SHODAN CERTIFICATE</span>
            <span class="modal-port mono">port {{ cert.port }}</span>
          </div>
          <button class="btn-close" @click="$emit('close')" aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <line x1="1" y1="1" x2="13" y2="13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              <line x1="13" y1="1" x2="1" y2="13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            </svg>
          </button>
        </div>

        <!-- CN hero -->
        <div class="cert-hero">
          <div class="cert-cn mono">{{ cert.subject?.CN || 'Unknown CN' }}</div>
          <div class="cert-validity" :class="validityClass">
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
              <circle cx="5" cy="5" r="4" stroke="currentColor" stroke-width="1.2"/>
              <path v-if="isValid" d="M3 5l1.5 1.5L7 3.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
              <line v-else x1="3" y1="3" x2="7" y2="7" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
            </svg>
            {{ isValid ? 'Valid' : 'Expired' }} · {{ validityLabel }}
          </div>
        </div>

        <div class="modal-body">
          <div class="detail-grid">

            <!-- Subject -->
            <div class="detail-section">
              <div class="section-label mono">Subject</div>
              <div class="kv-list">
                <div v-for="(val, key) in cert.subject" :key="'s-'+key" class="kv">
                  <span class="kv-key">{{ fieldLabel(key) }}</span>
                  <span class="kv-val mono">{{ val }}</span>
                </div>
              </div>
            </div>

            <!-- Issuer -->
            <div class="detail-section">
              <div class="section-label mono">Issuer</div>
              <div class="kv-list">
                <div v-for="(val, key) in cert.issuer" :key="'i-'+key" class="kv">
                  <span class="kv-key">{{ fieldLabel(key) }}</span>
                  <span class="kv-val mono">{{ val }}</span>
                </div>
              </div>
            </div>

          </div>

          <!-- Validity -->
          <div class="detail-section">
            <div class="section-label mono">Validity period</div>
            <div class="validity-bar-wrap">
              <div class="validity-track">
                <div class="validity-fill" :style="{ width: validityPercent + '%' }" :class="validityClass"></div>
              </div>
              <div class="validity-labels">
                <span class="mono">{{ formatCertDate(cert.issued) }}</span>
                <span class="mono validity-today" :style="{ left: validityPercent + '%' }">today</span>
                <span class="mono">{{ formatCertDate(cert.expires) }}</span>
              </div>
            </div>
            <div class="kv-list" style="margin-top:10px">
              <div class="kv">
                <span class="kv-key">Issued</span>
                <span class="kv-val mono">{{ formatCertDate(cert.issued) }}</span>
              </div>
              <div class="kv">
                <span class="kv-key">Expires</span>
                <span class="kv-val mono">{{ formatCertDate(cert.expires) }}</span>
              </div>
              <div class="kv">
                <span class="kv-key">Duration</span>
                <span class="kv-val mono">{{ durationDays }} days</span>
              </div>
              <div class="kv">
                <span class="kv-key">Remaining</span>
                <span class="kv-val mono" :class="isValid ? (daysRemaining < 30 ? 'warn' : '') : 'expired'">
                  {{ isValid ? daysRemaining + ' days' : 'Expired' }}
                </span>
              </div>
            </div>
          </div>

          <!-- Fingerprints -->
          <div v-if="cert.fingerprint" class="detail-section">
            <div class="section-label mono">Fingerprints</div>
            <div class="kv-list">
              <div v-if="cert.fingerprint.sha256" class="kv kv-fp">
                <span class="kv-key">SHA-256</span>
                <div class="fp-wrap">
                  <span class="kv-val mono fp">{{ formatFp(cert.fingerprint.sha256) }}</span>
                  <button class="copy-btn" @click="copy(cert.fingerprint.sha256)" :class="{ copied: copied === 'sha256' }">
                    <svg v-if="copied !== 'sha256'" width="11" height="11" viewBox="0 0 11 11" fill="none"><rect x="3.5" y="3.5" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.1"/><path d="M1.5 7.5V1.5h6" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>
                    <svg v-else width="11" height="11" viewBox="0 0 11 11" fill="none"><path d="M2 6l2.5 2.5L9 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  </button>
                </div>
              </div>
              <div v-if="cert.fingerprint.sha1" class="kv kv-fp">
                <span class="kv-key">SHA-1</span>
                <div class="fp-wrap">
                  <span class="kv-val mono fp">{{ formatFp(cert.fingerprint.sha1) }}</span>
                  <button class="copy-btn" @click="copy(cert.fingerprint.sha1)" :class="{ copied: copied === 'sha1' }">
                    <svg v-if="copied !== 'sha1'" width="11" height="11" viewBox="0 0 11 11" fill="none"><rect x="3.5" y="3.5" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.1"/><path d="M1.5 7.5V1.5h6" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>
                    <svg v-else width="11" height="11" viewBox="0 0 11 11" fill="none"><path d="M2 6l2.5 2.5L9 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  </button>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'

const props = defineProps({ cert: { type: Object, required: true } })
const emit = defineEmits(['close'])

const copied = ref(null)

// Parse Shodan date format: "20260713083725Z" → Date
function parseShodanDate(str) {
  if (!str) return null
  // Format: YYYYMMDDHHmmssZ
  const s = str.replace('Z', '')
  const year  = s.slice(0, 4)
  const month = s.slice(4, 6)
  const day   = s.slice(6, 8)
  const hour  = s.slice(8, 10)
  const min   = s.slice(10, 12)
  const sec   = s.slice(12, 14)
  return new Date(`${year}-${month}-${day}T${hour}:${min}:${sec}Z`)
}

function formatCertDate(str) {
  const d = parseShodanDate(str)
  if (!d) return str
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })
}

const issuedDate  = computed(() => parseShodanDate(props.cert.issued))
const expiresDate = computed(() => parseShodanDate(props.cert.expires))
const now = new Date()

const durationDays = computed(() => {
  if (!issuedDate.value || !expiresDate.value) return '?'
  return Math.round((expiresDate.value - issuedDate.value) / 86400000)
})

const daysRemaining = computed(() => {
  if (!expiresDate.value) return 0
  return Math.max(0, Math.round((expiresDate.value - now) / 86400000))
})

const isValid = computed(() => expiresDate.value && expiresDate.value > now)

const validityPercent = computed(() => {
  if (!issuedDate.value || !expiresDate.value) return 0
  const total = expiresDate.value - issuedDate.value
  const elapsed = now - issuedDate.value
  return Math.min(100, Math.max(0, (elapsed / total) * 100))
})

const validityClass = computed(() => {
  if (!isValid.value) return 'expired'
  if (daysRemaining.value < 30) return 'expiring'
  return 'valid'
})

const validityLabel = computed(() => {
  if (!isValid.value) return `expired ${Math.abs(daysRemaining.value)} days ago`
  if (daysRemaining.value < 30) return `expires in ${daysRemaining.value} days`
  return `${daysRemaining.value} days remaining`
})

function formatFp(fp) {
  // Insert colon every 2 chars for SHA-1, keep raw for SHA-256
  if (fp.length === 40) return fp.match(/.{2}/g).join(':').toUpperCase()
  return fp
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    const key = text.length === 64 ? 'sha256' : 'sha1'
    copied.value = key
    setTimeout(() => { copied.value = null }, 2000)
  } catch {}
}

const FIELD_LABELS = { CN: 'Common name', O: 'Organization', C: 'Country', L: 'Locality', ST: 'State', OU: 'Org unit' }
function fieldLabel(key) { return FIELD_LABELS[key] || key }

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
  animation: fadeIn 0.15s ease;
}
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

.modal-box {
  background: var(--bg-card); border: 1px solid var(--border-active);
  border-radius: 10px; width: 100%; max-width: 600px;
  max-height: 80vh; display: flex; flex-direction: column;
  animation: slideUp 0.2s ease; overflow: hidden;
}
@keyframes slideUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }

.modal-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 20px; border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.modal-header-left { display: flex; align-items: center; gap: 10px; }
.modal-source { font-size: 11px; color: #e8073a; letter-spacing: 0.1em; }
.modal-port { font-size: 10px; color: var(--text-muted); }
.dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.dot-shodan { background: #e8073a; }

.btn-close {
  width: 28px; height: 28px; border-radius: 5px;
  display: flex; align-items: center; justify-content: center;
  border: 1px solid var(--border); background: transparent;
  color: var(--text-secondary); cursor: pointer; transition: all 0.15s;
}
.btn-close:hover { border-color: var(--border-active); color: var(--text-primary); background: rgba(255,255,255,0.05); }

/* Hero */
.cert-hero {
  padding: 16px 20px 14px; border-bottom: 1px solid var(--border);
  background: rgba(232, 7, 58, 0.04); flex-shrink: 0;
  display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
}
.cert-cn { font-size: 16px; font-weight: 600; color: var(--text-primary); word-break: break-word; }
.cert-validity {
  display: flex; align-items: center; gap: 5px;
  font-size: 11px; font-family: var(--font-mono); flex-shrink: 0;
  padding: 4px 10px; border-radius: 4px;
}
.cert-validity.valid { background: rgba(56,161,105,0.12); color: var(--risk-low); border: 1px solid rgba(56,161,105,0.25); }
.cert-validity.expiring { background: rgba(214,158,46,0.12); color: var(--risk-medium); border: 1px solid rgba(214,158,46,0.25); }
.cert-validity.expired { background: rgba(229,62,62,0.12); color: var(--risk-critical); border: 1px solid rgba(229,62,62,0.25); }

/* Body */
.modal-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 20px; }

.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.detail-section { display: flex; flex-direction: column; gap: 0; }
.section-label { font-size: 10px; color: var(--text-muted); letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 10px; }

.kv-list { display: flex; flex-direction: column; gap: 7px; }
.kv { display: flex; gap: 8px; align-items: flex-start; font-size: 12px; }
.kv-key { color: var(--text-muted); min-width: 90px; flex-shrink: 0; padding-top: 1px; }
.kv-val { color: var(--text-primary); word-break: break-word; overflow-wrap: break-word; }
.kv-val.warn { color: var(--risk-medium); }
.kv-val.expired { color: var(--risk-critical); }

/* Validity bar */
.validity-bar-wrap { margin-top: 6px; }
.validity-track {
  height: 4px; background: var(--border); border-radius: 2px;
  overflow: hidden; position: relative;
}
.validity-fill {
  height: 100%; border-radius: 2px; transition: width 0.4s ease;
}
.validity-fill.valid { background: var(--risk-low); }
.validity-fill.expiring { background: var(--risk-medium); }
.validity-fill.expired { background: var(--risk-critical); width: 100% !important; }
.validity-labels {
  display: flex; justify-content: space-between; align-items: center;
  margin-top: 5px; font-size: 10px; color: var(--text-muted); position: relative;
}
.validity-today {
  position: absolute; transform: translateX(-50%);
  color: var(--accent-cyan); font-size: 9px;
}

/* Fingerprints */
.kv-fp { flex-direction: column; gap: 4px; }
.kv-fp .kv-key { min-width: unset; }
.fp-wrap { display: flex; align-items: center; gap: 6px; }
.fp {
  font-size: 11px; color: var(--text-secondary);
  word-break: break-all; line-height: 1.5;
  flex: 1;
}
.copy-btn {
  flex-shrink: 0; width: 22px; height: 22px;
  display: flex; align-items: center; justify-content: center;
  border: 1px solid var(--border); border-radius: 4px;
  background: transparent; color: var(--text-muted);
  cursor: pointer; transition: all 0.15s;
}
.copy-btn:hover { border-color: var(--border-active); color: var(--text-primary); }
.copy-btn.copied { border-color: rgba(56,161,105,0.4); color: var(--risk-low); }

@media (max-width: 600px) { .detail-grid { grid-template-columns: 1fr; } }
</style>
