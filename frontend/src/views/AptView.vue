<template>
  <div class="apt-list-page">
    <div class="page-inner">
      <div class="page-header">
        <div>
          <h1 class="page-title">APT Groups</h1>
          <p class="page-sub">Search and analyze Advanced Persistent Threat actor groups</p>
        </div>
      </div>

      <form class="search-row" @submit.prevent="searchApt">
        <div class="search-wrap">
          <svg class="search-icon" width="14" height="14" viewBox="0 0 14 14" fill="none">
            <circle cx="5.5" cy="5.5" r="4.5" stroke="currentColor" stroke-width="1.5"/>
            <line x1="9" y1="9" x2="13" y2="13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
          </svg>
          <input v-model="searchInput" type="text" class="search-input mono"
            placeholder="APT28, Fancy Bear, Lazarus, Cozy Bear..." />
        </div>
        <button type="submit" class="btn-primary" :disabled="!searchInput.trim() || loading">
          <span v-if="loading" class="spinner"></span>
          <template v-else>
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 1L13 7L7 13M13 7H1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
            Analyze
          </template>
        </button>
      </form>

      <!-- Known groups quick pick -->
      <div class="quick-groups">
        <span class="quick-label">Known groups:</span>
        <button v-for="g in knownGroups" :key="g.name"
          class="group-chip" :class="`origin-${g.origin}`"
          @click="quickSearch(g.name)">
          <span class="chip-flag">{{ g.flag }}</span>
          {{ g.name }}
        </button>
      </div>

      <!-- Loading -->
      <div v-if="loading" class="loading-row">
        <div class="spinner-lg"></div>
        <span class="mono" style="font-size:12px;color:var(--text-muted)">Fetching intelligence for {{ searchInput }}...</span>
      </div>

      <!-- Error — komunikaty z backendu -->
      <div v-else-if="errors.length" class="error-card card">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style="flex-shrink:0">
          <circle cx="8" cy="8" r="6.5" stroke="var(--risk-critical)" stroke-width="1.3"/>
          <line x1="8" y1="4" x2="8" y2="9" stroke="var(--risk-critical)" stroke-width="1.3" stroke-linecap="round"/>
          <circle cx="8" cy="12" r="0.8" fill="var(--risk-critical)"/>
        </svg>
        <ul class="error-list">
          <li v-for="(msg, i) in errors" :key="i">{{ msg }}</li>
        </ul>
      </div>

      <!-- Result -->
      <div v-else-if="result" class="fade-in">
        <AptDetail :data="result" />
      </div>


    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AptDetail from '../components/AptDetail.vue'

const route = useRoute()
const router = useRouter()

const searchInput = ref('')
const result = ref(null)
const loading = ref(false)
const errors = ref([])

const knownGroups = [
  { name: 'APT28', origin: 'ru', flag: '🇷🇺' },
  { name: 'APT29', origin: 'ru', flag: '🇷🇺' },
  { name: 'Lazarus', origin: 'kp', flag: '🇰🇵' },
  { name: 'APT41', origin: 'cn', flag: '🇨🇳' },
  { name: 'Sandworm', origin: 'ru', flag: '🇷🇺' },
  { name: 'Kimsuky', origin: 'kp', flag: '🇰🇵' },
  { name: 'APT10', origin: 'cn', flag: '🇨🇳' },
  { name: 'Turla', origin: 'ru', flag: '🇷🇺' },
]

const examples = [
  { name: 'APT28', flag: '🇷🇺', alias: 'Fancy Bear / Sofacy', risk: 'critical',
    desc: 'Russian GRU unit 26165. Responsible for DNC hack, election interference operations.', tactics: ['Phishing', 'C2', 'Credential theft'] },
  { name: 'APT29', flag: '🇷🇺', alias: 'Cozy Bear / Nobelium', risk: 'critical',
    desc: 'Russian SVR. SolarWinds supply chain attack, Microsoft breach.', tactics: ['Supply chain', 'Persistence', 'Exfil'] },
  { name: 'Lazarus', flag: '🇰🇵', alias: 'Hidden Cobra / ZINC', risk: 'high',
    desc: 'North Korean state actor. Financial theft, ransomware, crypto heists.', tactics: ['Ransomware', 'Banking', 'Crypto'] },
  { name: 'APT41', flag: '🇨🇳', alias: 'Double Dragon / Winnti', risk: 'high',
    desc: 'Chinese state-nexus group combining espionage with financial crime.', tactics: ['Espionage', 'Supply chain', 'Gaming'] },
  { name: 'Sandworm', flag: '🇷🇺', alias: 'Voodoo Bear / BlackEnergy', risk: 'critical',
    desc: 'Russian GRU unit 74455. Ukraine power grid attacks, NotPetya wiper.', tactics: ['ICS/SCADA', 'Wiper', 'Destruction'] },
  { name: 'Kimsuky', flag: '🇰🇵', alias: 'Velvet Chollima', risk: 'medium',
    desc: 'North Korean intel gathering, targeting think tanks and government entities.', tactics: ['Spearphishing', 'RAT', 'Recon'] },
]

function quickSearch(name) {
  searchInput.value = name
  searchApt()
}

async function searchApt() {
  const name = searchInput.value.trim()
  if (!name) return
  router.replace({ query: { name } })
  result.value = null
  errors.value = []
  loading.value = true
  try {
    const res = await fetch(`/api/analyze/apt/?name=${encodeURIComponent(name)}`)
    const data = await res.json()
    if (!res.ok) {
      // Parsuj błędy z backendu: { error: { name: ["..."], ... } }
      if (data?.error && typeof data.error === 'object') {
        errors.value = Object.values(data.error).flat()
      } else {
        errors.value = [data?.error || data?.detail || `Błąd serwera (HTTP ${res.status})`]
      }
    } else {
      result.value = data
    }
  } catch (e) {
    errors.value = [`Nie można połączyć się z backendem: ${e.message}`]
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  if (route.query.name) {
    searchInput.value = route.query.name
    searchApt()
  }
})
</script>

<style scoped>
.apt-list-page { padding: 32px 0 80px; }
.page-inner { max-width: 1200px; margin: 0 auto; padding: 0 24px; }

.page-header { margin-bottom: 28px; }
.page-title { font-size: 24px; font-weight: 700; margin-bottom: 6px; }
.page-sub { color: var(--text-secondary); font-size: 14px; }

.search-row { display: flex; gap: 8px; margin-bottom: 16px; }
.search-wrap { flex: 1; position: relative; display: flex; align-items: center; }
.search-icon { position: absolute; left: 12px; color: var(--text-muted); pointer-events: none; }
.search-input {
  width: 100%; padding: 10px 12px 10px 38px;
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 14px; outline: none;
  transition: border-color 0.2s;
}
.search-input:focus { border-color: var(--accent-cyan); }
.search-input::placeholder { color: var(--text-muted); }
.btn-primary {
  padding: 10px 20px; background: var(--accent-cyan); color: #0a0c10;
  font-weight: 600; font-size: 14px; border: none; border-radius: 8px;
  cursor: pointer; transition: filter 0.2s; display: flex; align-items: center; gap: 8px;
}
.btn-primary:hover:not(:disabled) { filter: brightness(1.1); }
.btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

.quick-groups { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 36px; }
.quick-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-right: 4px; }
.group-chip {
  display: flex; align-items: center; gap: 5px;
  padding: 4px 10px; border-radius: 4px; border: 1px solid var(--border);
  background: var(--bg-card); color: var(--text-secondary);
  font-family: var(--font-mono); font-size: 12px; cursor: pointer;
  transition: all 0.15s;
}
.group-chip:hover { border-color: var(--border-active); color: var(--text-primary); }
.chip-flag { font-size: 12px; }

.loading-row { display: flex; align-items: center; gap: 14px; padding: 40px; }
.spinner-lg {
  width: 24px; height: 24px; border: 2px solid var(--border);
  border-top-color: var(--accent-cyan); border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

.error-card {
  padding: 16px 20px; display: flex; align-items: flex-start;
  gap: 10px; color: var(--risk-critical); font-size: 13px;
}
.error-list { list-style: none; display: flex; flex-direction: column; gap: 4px; }
.error-list li::before { content: '— '; }

.examples-title { font-size: 11px; letter-spacing: 0.12em; color: var(--text-muted); margin-bottom: 16px; }
.examples-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.example-card { padding: 16px 18px; cursor: pointer; transition: all 0.2s; }
.example-card:hover { border-color: var(--accent-cyan); transform: translateY(-1px); }
.example-top { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.example-flag { font-size: 16px; }
.example-name { font-weight: 600; font-size: 14px; flex: 1; }
.example-alias { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 8px; }
.example-desc { font-size: 12px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 10px; }
.example-tactics { display: flex; flex-wrap: wrap; gap: 5px; }

.spinner {
  width: 14px; height: 14px; border: 2px solid rgba(10,12,16,0.3);
  border-top-color: #0a0c10; border-radius: 50%;
  animation: spin 0.7s linear infinite;
}

.badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-critical { background: rgba(229, 62, 62, 0.15); color: var(--risk-critical); border: 1px solid rgba(229, 62, 62, 0.3); }
.badge-high { background: rgba(221, 107, 32, 0.15); color: var(--risk-high); border: 1px solid rgba(221, 107, 32, 0.3); }
.badge-medium { background: rgba(214, 158, 46, 0.15); color: var(--risk-medium); border: 1px solid rgba(214, 158, 46, 0.3); }
.badge-neutral { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }

@media (max-width: 900px) { .examples-grid { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 600px) { .examples-grid { grid-template-columns: 1fr; } }
</style>
