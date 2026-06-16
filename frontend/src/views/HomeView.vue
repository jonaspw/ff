<template>
  <div class="dashboard">
    <div class="page-inner">
      <!-- Hero search -->
      <section class="hero">
        <h1 class="hero-title">Analyze. Identify. <span class="text-cyan">Track.</span></h1>
        <p class="hero-sub">Search IPs, domains, or APT group names to retrieve threat data from multiple intelligence sources.</p>

        <form class="search-form" @submit.prevent="handleSearch">
          <div class="search-wrap">
            <svg class="search-icon" width="16" height="16" viewBox="0 0 16 16" fill="none">
              <circle cx="6.5" cy="6.5" r="5" stroke="currentColor" stroke-width="1.5"/>
              <line x1="10.5" y1="10.5" x2="15" y2="15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            </svg>
            <input
              v-model="searchQuery"
              type="text"
              class="search-input mono"
              placeholder="185.220.101.47  /  update-service.net  /  APT28"
              autofocus
            />
            <span v-if="queryType" class="query-type-badge" :class="`badge badge-${queryType === 'apt' ? 'info' : queryType === 'ip' ? 'medium' : 'neutral'}`">
              {{ queryType.toUpperCase() }}
            </span>
          </div>
          <button type="submit" class="btn-search" :disabled="!searchQuery.trim()">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M7 1L13 7L7 13M13 7H1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            Analyze
          </button>
        </form>
      </section>

      <!-- Sources grid -->
      <section>
        <h2 class="section-title">Intelligence Sources</h2>
        <div class="sources-grid">
          <div v-for="src in sources" :key="src.name" class="source-card card">
            <div class="source-header">
              <span class="source-dot" :style="{ background: src.color }"></span>
              <span class="source-name mono">{{ src.name }}</span>
            </div>
            <p class="source-desc">{{ src.desc }}</p>
            <div class="source-tags">
              <span v-for="tag in src.tags" :key="tag" class="badge badge-neutral">{{ tag }}</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const searchQuery = ref('')

const queryType = computed(() => {
  const q = searchQuery.value.trim()
  if (!q) return null
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q)) return 'ip'
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q) && !q.includes(' ')) return 'domain'
  return 'apt'
})

function setQuery(q) {
  searchQuery.value = q
}

function handleSearch() {
  const q = searchQuery.value.trim()
  if (!q) return
  if (queryType.value === 'apt') {
    router.push({ name: 'apt-detail', query: { name: q } })
  } else {
    router.push({ name: 'analyze', query: { q } })
  }
}

const sources = [
  { name: 'VirusTotal', color: '#4299e1', desc: 'Multi-engine malware scanning and reputation scoring for IPs, domains, and files.', tags: ['IP', 'Domain', 'Hash'] },
  { name: 'Shodan', color: '#f6ad55', desc: 'Internet-wide scanner exposing open ports, banners, services, and vulnerabilities on IPs.', tags: ['IP', 'Ports', 'CVE', 'Banners'] },
  { name: 'AbuseIPDB', color: '#e53e3e', desc: 'Community-driven IP abuse reports with categorized threat types and abuse scores.', tags: ['IP', 'Abuse Score'] },
  { name: 'ThreatFox', color: '#dd6b20', desc: 'IOC repository from abuse.ch tracking malware infrastructure and C2 servers.', tags: ['IOC', 'Malware', 'C2'] },
  { name: 'CIRCL', color: '#9f7aea', desc: 'MISP events from CIRCL.lu Computer Incident Response Center Luxembourg.', tags: ['Events', 'MISP'] },
  { name: 'MITRE ATT&CK', color: '#00d4ff', desc: 'Tactics, techniques and procedures mapped to known threat actor groups.', tags: ['APT', 'TTP', 'STIX'] },
  { name: 'WHOIS', color: '#38a169', desc: 'IP ownership, ASN data, BGP routing information, and network registration records.', tags: ['IP', 'ASN', 'Network'] },
  { name: 'crt.sh', color: '#b794f4', desc: 'Certificate Transparency logs — history of TLS certificates issued for domains and IPs.', tags: ['Certificates', 'Domains', 'TLS'] },
]
</script>

<style scoped>
.dashboard { padding: 48px 0 80px; }
.page-inner { max-width: 1200px; margin: 0 auto; padding: 0 24px; }

.hero { max-width: 680px; margin: 0 auto 64px; text-align: center; }
.hero-label {
  font-size: 11px; letter-spacing: 0.15em; color: var(--accent-cyan);
  margin-bottom: 20px; text-transform: uppercase;
}
.hero-title { font-size: 42px; font-weight: 700; line-height: 1.1; margin-bottom: 16px; }
.text-cyan { color: var(--accent-cyan); }
.hero-sub { color: var(--text-secondary); font-size: 16px; line-height: 1.7; margin-bottom: 32px; }

.search-form { display: flex; gap: 8px; margin-bottom: 16px; }
.search-wrap {
  flex: 1; position: relative;
  display: flex; align-items: center;
}
.search-icon { position: absolute; left: 14px; color: var(--text-muted); pointer-events: none; }
.search-input {
  width: 100%; padding: 12px 48px 12px 42px;
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 14px;
  outline: none; transition: border-color 0.2s;
}
.search-input::placeholder { color: var(--text-muted); }
.search-input:focus { border-color: var(--accent-cyan); }
.query-type-badge { position: absolute; right: 10px; }

.btn-search {
  display: flex; align-items: center; gap: 8px;
  padding: 12px 20px; border-radius: 8px;
  background: var(--accent-cyan); color: #0a0c10;
  font-family: var(--font-sans); font-size: 14px; font-weight: 600;
  border: none; cursor: pointer; transition: all 0.2s; white-space: nowrap;
}
.btn-search:hover { filter: brightness(1.1); }
.btn-search:disabled { opacity: 0.4; cursor: not-allowed; }

.search-hints { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; }
.hint {
  font-family: var(--font-mono); font-size: 12px;
  color: var(--text-secondary); padding: 4px 10px;
  border: 1px solid var(--border); border-radius: 4px;
  cursor: pointer; transition: all 0.15s;
}
.hint:hover { color: var(--accent-cyan); border-color: rgba(0, 212, 255, 0.3); }

.stats-row {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 12px; margin-bottom: 48px;
}
.stat-card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px 20px;
  display: flex; align-items: center; gap: 14px;
}
.stat-value { font-size: 15px; font-weight: 600; color: var(--text-primary); }
.stat-label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2px; }
.stat-icon { flex-shrink: 0; }

.section-title {
  font-size: 13px; font-weight: 600; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--text-secondary);
  margin-bottom: 16px;
}

.sources-grid {
  display: grid; grid-template-columns: repeat(3, 1fr);
  gap: 12px;
}
.source-card { padding: 18px 20px; }
.source-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.source-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.source-name { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.source-desc { font-size: 13px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 12px; }
.source-tags { display: flex; flex-wrap: wrap; gap: 6px; }

@media (max-width: 900px) {
  .stats-row { grid-template-columns: repeat(2, 1fr); }
  .sources-grid { grid-template-columns: repeat(2, 1fr); }
  .hero-title { font-size: 32px; }
}
@media (max-width: 600px) {
  .sources-grid { grid-template-columns: 1fr; }
  .stats-row { grid-template-columns: repeat(2, 1fr); }
  .search-form { flex-direction: column; }
}
</style>
