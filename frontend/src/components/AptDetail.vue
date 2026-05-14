<template>
  <div class="apt-detail">

    <!-- Group header -->
    <div class="group-header card">
      <div class="group-main">
        <div class="group-id-wrap">
          <span class="group-attack-id mono">{{ mitre.attack_id || 'N/A' }}</span>
          <span v-if="mitre.url" class="ext-link">
            <a :href="mitre.url" target="_blank" rel="noopener">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M10 2H7M10 2V5M10 2L5.5 6.5M9 7v3H2V3h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
              MITRE
            </a>
          </span>
        </div>
        <h2 class="group-name">{{ data.name || mitre.name }}</h2>
        <div v-if="mitre.aliasy?.length" class="group-aliases">
          <span v-for="alias in mitre.aliasy" :key="alias" class="badge badge-neutral">{{ alias }}</span>
        </div>
      </div>
      <div class="group-stats">
        <div class="gstat">
          <div class="gstat-val mono">{{ mitre.techniki_count || 0 }}</div>
          <div class="gstat-label">Techniques</div>
        </div>
        <div class="gstat">
          <div class="gstat-val mono">{{ mitre.taktyki?.length || 0 }}</div>
          <div class="gstat-label">Tactics</div>
        </div>
        <div class="gstat">
          <div class="gstat-val mono">{{ mitre.software_count || 0 }}</div>
          <div class="gstat-label">Tools/Malware</div>
        </div>
        <div class="gstat">
          <div class="gstat-val mono">{{ circlCount }}</div>
          <div class="gstat-label">CIRCL Events</div>
        </div>
      </div>
    </div>

    <!-- Description -->
    <div v-if="mitre.opis" class="card section-card">
      <div class="section-header">
        <span class="dot dot-cyan"></span>
        <span class="section-title">Overview</span>
      </div>
      <p class="group-desc">{{ cleanOpisText }}</p>
    </div>

    <!-- Two-col layout -->
    <div class="detail-grid">

      <!-- Left -->
      <div class="detail-col">

        <!-- Tactics -->
        <div v-if="mitre.taktyki?.length" class="card section-card">
          <div class="section-header">
            <span class="dot dot-orange"></span>
            <span class="section-title">MITRE Tactics</span>
            <span class="badge badge-neutral" style="margin-left:auto">{{ mitre.taktyki.length }}</span>
          </div>
          <div class="tactics-grid">
            <div v-for="tactic in mitre.taktyki" :key="tactic" class="tactic-chip">
              <span class="tactic-icon">{{ tacticIcon(tactic) }}</span>
              <span>{{ formatTactic(tactic) }}</span>
            </div>
          </div>
        </div>

        <!-- Techniques sample -->
        <div v-if="mitre.techniki?.length" class="card section-card">
          <div class="section-header">
            <span class="dot dot-purple"></span>
            <span class="section-title">Techniques (sample)</span>
            <span class="badge badge-neutral" style="margin-left:auto">{{ mitre.techniki_count }} total</span>
          </div>
          <div class="techniques-list">
            <div v-for="tech in mitre.techniki" :key="tech.id" class="technique-row">
              <div class="tech-id-wrap">
                <span class="tech-id mono">{{ tech.id }}</span>
                <span v-for="tac in tech.taktyki" :key="tac" class="badge badge-neutral" style="font-size:10px">{{ formatTactic(tac) }}</span>
              </div>
              <div class="tech-name">{{ tech.name }}</div>
              <div class="tech-desc">{{ truncate(tech.opis, 120) }}</div>
            </div>
          </div>
          <div v-if="mitre.techniki_count > mitre.techniki.length" class="more-hint">
            + {{ mitre.techniki_count - mitre.techniki.length }} more techniques in full dataset
          </div>
        </div>

      </div>

      <!-- Right -->
      <div class="detail-col">

        <!-- Software/Tools -->
        <div v-if="mitre.software?.length" class="card section-card">
          <div class="section-header">
            <span class="dot dot-red"></span>
            <span class="section-title">Tools & Malware</span>
            <span class="badge badge-neutral" style="margin-left:auto">{{ mitre.software_count }}</span>
          </div>
          <div class="software-list">
            <div v-for="sw in mitre.software" :key="sw.name" class="sw-row">
              <span class="sw-icon" :class="sw.type">{{ sw.type === 'malware' ? '◆' : '◇' }}</span>
              <span class="sw-name">{{ sw.name }}</span>
              <span class="badge" :class="sw.type === 'malware' ? 'badge-high' : 'badge-neutral'">{{ sw.type }}</span>
            </div>
          </div>
          <div v-if="mitre.software_count > mitre.software.length" class="more-hint">
            + {{ mitre.software_count - mitre.software.length }} more
          </div>
        </div>

        <!-- ✦ CIRCL — nowy komponent z klikalnymi wierszami -->
        <CirclEvents
          v-if="data.circl?.found"
          :circl-data="data.circl"
          title="CIRCL Intelligence Events"
        />
        <div v-else-if="data.circl && !data.circl.found" class="card section-card not-found-card">
          <div class="section-header">
            <span class="dot dot-purple"></span>
            <span class="section-title">CIRCL Events</span>
            <span class="badge badge-low" style="margin-left:auto">No events found</span>
          </div>
        </div>

        <!-- ThreatFox -->
        <div v-if="data.threatfox?.found" class="card section-card">
          <div class="section-header">
            <span class="dot dot-orange"></span>
            <span class="section-title">ThreatFox IOCs</span>
            <span class="badge badge-high" style="margin-left:auto">{{ data.threatfox.count }}</span>
          </div>
          <div v-for="ioc in data.threatfox.iocs?.slice(0,6)" :key="ioc.id" class="ioc-row">
            <span class="mono ioc-val">{{ ioc.ioc || ioc.value }}</span>
            <div class="ioc-meta">
              <span v-if="ioc.malware" class="badge badge-high">{{ ioc.malware }}</span>
              <span v-if="ioc.ioc_type" class="badge badge-neutral">{{ ioc.ioc_type }}</span>
            </div>
          </div>
        </div>
        <div v-else-if="data.threatfox && !data.threatfox.found" class="card section-card not-found-card">
          <div class="section-header">
            <span class="dot dot-orange"></span>
            <span class="section-title">ThreatFox</span>
            <span class="badge badge-low" style="margin-left:auto">No IOCs found</span>
          </div>
        </div>

      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import CirclEvents from './CirclEvents.vue'

const props = defineProps({ data: Object })

const mitre = computed(() => props.data?.mitre || {})
const circlCount = computed(() => props.data?.circl?.count || props.data?.circl?.events_count || 0)

const cleanOpisText = computed(() => {
  return (mitre.value.opis || '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/\(Citation:[^)]+\)/g, '').trim()
})

function formatTactic(t) {
  return t.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function tacticIcon(t) {
  const icons = {
    'initial-access': '🚪', 'execution': '⚡', 'persistence': '🔒', 'privilege-escalation': '⬆️',
    'defense-evasion': '👻', 'credential-access': '🔑', 'discovery': '🔍', 'lateral-movement': '↔️',
    'collection': '📦', 'command-and-control': '📡', 'exfiltration': '📤', 'impact': '💥',
    'reconnaissance': '🎯', 'resource-development': '🛠️',
  }
  return icons[t] || '▸'
}

function truncate(str, len) {
  if (!str) return ''
  return str.length > len ? str.slice(0, len) + '…' : str
}
</script>

<style scoped>
.apt-detail { display: flex; flex-direction: column; gap: 16px; }

.group-header { padding: 24px 28px; display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; }
.group-main { flex: 1; }
.group-id-wrap { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.group-attack-id { font-size: 11px; color: var(--text-muted); letter-spacing: 0.1em; }
.ext-link a { display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--accent-cyan); text-decoration: none; font-family: var(--font-mono); }
.ext-link a:hover { text-decoration: underline; }
.group-name { font-size: 28px; font-weight: 700; margin-bottom: 12px; color: var(--text-primary); }
.group-aliases { display: flex; flex-wrap: wrap; gap: 6px; }

.group-stats { display: flex; gap: 0; flex-shrink: 0; }
.gstat { text-align: center; padding: 12px 20px; border-left: 1px solid var(--border); }
.gstat:first-child { border-left: none; }
.gstat-val { font-size: 22px; font-weight: 700; color: var(--accent-cyan); }
.gstat-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-top: 2px; }

.section-card { padding: 16px 20px; }
.section-header { display: flex; align-items: center; gap: 8px; margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }
.section-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.not-found-card .section-header { margin-bottom: 0; padding-bottom: 0; border-bottom: none; }

.dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.dot-cyan { background: var(--accent-cyan); }
.dot-orange { background: var(--accent-orange); }
.dot-purple { background: var(--accent-purple); }
.dot-red { background: var(--risk-critical); }

.group-desc { font-size: 13px; color: var(--text-secondary); line-height: 1.7; }

.tactics-grid { display: flex; flex-wrap: wrap; gap: 8px; }
.tactic-chip { display: flex; align-items: center; gap: 5px; padding: 5px 10px; background: rgba(255,255,255,0.04); border: 1px solid var(--border); border-radius: 5px; font-size: 12px; color: var(--text-secondary); }
.tactic-icon { font-size: 12px; }

.techniques-list { display: flex; flex-direction: column; gap: 1px; }
.technique-row { padding: 10px 0; border-bottom: 1px solid var(--border); }
.technique-row:last-child { border-bottom: none; }
.tech-id-wrap { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; }
.tech-id { font-size: 11px; color: var(--accent-cyan); }
.tech-name { font-size: 13px; font-weight: 500; color: var(--text-primary); margin-bottom: 3px; }
.tech-desc { font-size: 11px; color: var(--text-muted); line-height: 1.4; }

.software-list { display: flex; flex-direction: column; gap: 4px; }
.sw-row { display: flex; align-items: center; gap: 8px; padding: 7px 0; border-bottom: 1px solid var(--border); }
.sw-row:last-child { border-bottom: none; }
.sw-icon { font-size: 10px; }
.sw-icon.malware { color: var(--risk-high); }
.sw-icon.tool { color: var(--text-muted); }
.sw-name { flex: 1; font-size: 13px; color: var(--text-primary); }

.ioc-row { padding: 7px 0; border-bottom: 1px solid var(--border); display: flex; flex-direction: column; gap: 4px; }
.ioc-row:last-child { border-bottom: none; }
.ioc-val { font-size: 11px; color: var(--accent-cyan); word-break: break-all; }
.ioc-meta { display: flex; gap: 5px; flex-wrap: wrap; }

.more-hint { font-size: 11px; color: var(--text-muted); margin-top: 10px; font-style: italic; }

.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
.detail-col { display: flex; flex-direction: column; gap: 16px; }

.badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-high { background: rgba(221, 107, 32, 0.15); color: var(--risk-high); border: 1px solid rgba(221, 107, 32, 0.3); }
.badge-low { background: rgba(56, 161, 105, 0.15); color: var(--risk-low); border: 1px solid rgba(56, 161, 105, 0.3); }
.badge-neutral { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }

@media (max-width: 800px) {
  .detail-grid { grid-template-columns: 1fr; }
  .group-header { flex-direction: column; }
  .group-stats { border-top: 1px solid var(--border); padding-top: 16px; width: 100%; }
}
</style>
