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

        <!-- Techniques -->
        <div v-if="mitre.techniki?.length" class="card section-card flex-card">
          <div class="section-header">
            <span class="dot dot-purple"></span>
            <span class="section-title">Techniques</span>
            <span class="badge badge-neutral" style="margin-left:auto">{{ mitre.techniki_count }} total</span>
          </div>
          <div class="techniques-list">
            <div v-for="tech in techVisible" :key="tech.id"
              class="technique-row"
              @click="activeTechniqueId = tech.id"
              style="cursor:pointer"
            >
              <div class="tech-id-wrap">
                <span class="tech-id mono">{{ tech.id }}</span>
                <span v-for="tac in tech.taktyki" :key="tac" class="badge badge-neutral" style="font-size:10px">{{ formatTactic(tac) }}</span>
              </div>
              <div class="tech-name">{{ tech.name }}</div>
              <div class="tech-desc">{{ truncate(tech.opis, 120) }}</div>
            </div>
          </div>
          <div class="pagination-row">
            <button v-if="techLimit < mitre.techniki.length" class="show-more-btn" @click="techLimit += 20">
              Show 20 more
              <span class="text-muted">(left {{ mitre.techniki.length - techLimit }})</span>
            </button>
            <button v-if="techLimit > 20" class="show-more-btn" @click="techLimit = 20">Collapse</button>
          </div>
        </div>

      </div>

      <!-- Right -->
      <div class="detail-col">

        <!-- Tools & Malware -->
        <div v-if="mitre.software?.length" class="card section-card">
          <div class="section-header">
            <span class="dot dot-red"></span>
            <span class="section-title">Tools & Malware</span>
            <span class="badge badge-neutral" style="margin-left:auto">{{ mitre.software_count }}</span>
          </div>
          <div class="software-list">
            <div v-for="sw in swVisible" :key="sw.name" class="sw-row">
              <span class="sw-icon" :class="sw.type">{{ sw.type === 'malware' ? '◆' : '◇' }}</span>
              <span class="sw-name">{{ sw.name }}</span>
              <span class="badge" :class="sw.type === 'malware' ? 'badge-high' : 'badge-neutral'">{{ sw.type }}</span>
            </div>
          </div>
          <div class="pagination-row">
            <button v-if="swLimit < mitre.software.length" class="show-more-btn" @click="swLimit += 20">
              Show 20 more
              <span class="text-muted">(left {{ mitre.software.length - swLimit }})</span>
            </button>
            <button v-if="swLimit > 20" class="show-more-btn" @click="swLimit = 20">Collapse</button>
          </div>
        </div>

        <!-- CIRCL -->
        <div v-if="data.circl?.found" class="card section-card flex-card">
          <div class="section-header">
            <span class="dot dot-purple"></span>
            <span class="section-title">CIRCL Intelligence Events</span>
            <span class="badge badge-info" style="margin-left:auto">{{ circlCount }}</span>
          </div>
          <div v-for="ev in circlVisible" :key="ev.event_id || ev.uuid" class="event-row" @click="openCirclModal(ev.event_id || ev.uuid)" title="Click to view IOCs">
            <div class="event-left">
              <div class="event-date mono">{{ ev.date }}</div>
              <div class="event-info">{{ ev.info }}</div>
              <div class="event-org mono">{{ ev.org }}</div>
            </div>
            <div class="event-right">
              <svg class="event-arrow" width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path d="M5 3l4 4-4 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
              <span class="event-hint">IOCs</span>
            </div>
          </div>
          <div class="pagination-row">
            <button v-if="circlLimit < (data.circl?.events?.length || 0)" class="show-more-btn" @click="circlLimit += 10">
              Show 10 more
              <span class="text-muted">(left {{ data.circl.events.length - circlLimit }})</span>
            </button>
            <button v-if="circlLimit > 10" class="show-more-btn" @click="circlLimit = 10">Collapse</button>
          </div>
        </div>
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
          <div
            v-for="ioc in data.threatfox.iocs"
            :key="ioc.id"
            class="tf-ioc-row"
            @click="activeTfIoc = ioc"
            title="Click to view details"
          >
            <div class="tf-ioc-left">
              <span class="mono ioc-val">{{ ioc.ioc || ioc.value }}</span>
              <div class="ioc-meta">
                <span v-if="ioc.ioc_type" class="badge badge-neutral">{{ ioc.ioc_type }}</span>
                <span v-if="ioc.malware" class="badge badge-high">{{ ioc.malware }}</span>
                <span v-if="ioc.threat_type" class="badge badge-medium">{{ ioc.threat_type }}</span>
              </div>
            </div>
            <div class="tf-ioc-right">
              <span class="ioc-hint">Details</span>
              <svg class="ioc-arrow" width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path d="M5 3l4 4-4 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
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

        <ThreatFoxIocModal
          v-if="activeTfIoc"
          :ioc="activeTfIoc"
          @close="activeTfIoc = null"
        />

        <CirclEventModal
          v-if="activeCirclUuid"
          :uuid="activeCirclUuid"
          @close="activeCirclUuid = null"
        />

        <TechniqueModal
          v-if="activeTechniqueId"
          :technique-id="activeTechniqueId"
          @close="activeTechniqueId = null"
        />

      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, inject } from 'vue'
import CirclEventModal from './CirclEventModal.vue'
import ThreatFoxIocModal from './ThreatFoxIocModal.vue'
import TechniqueModal from './TechniqueModal.vue'

const activeTechniqueId = ref(null)

const props = defineProps({ data: Object })

const activeTfIoc = ref(null)
const activeCirclUuid = ref(null)
const openCirclModal = inject('openCirclModal', (uuid) => { activeCirclUuid.value = uuid })

const mitre = computed(() => props.data?.mitre || {})
const circlCount = computed(() => props.data?.circl?.count || props.data?.circl?.events_count || 0)

const cleanOpisText = computed(() => {
  return (mitre.value.opis || '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/\(Citation:[^)]+\)/g, '').trim()
})

const techLimit = ref(20)
const swLimit = ref(20)
const circlLimit = ref(10)

const techVisible = computed(() => (mitre.value.techniki || []).slice(0, techLimit.value))
const swVisible = computed(() => (mitre.value.software || []).slice(0, swLimit.value))
const circlVisible = computed(() => (props.data?.circl?.events || []).slice(0, circlLimit.value))

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

.tf-ioc-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 8px; border-radius: 6px; border-bottom: 1px solid var(--border); cursor: pointer; transition: all 0.15s; }
.tf-ioc-row:last-child { border-bottom: none; }
.tf-ioc-row:hover { background: rgba(221, 107, 32, 0.06); border-bottom-color: transparent; }
.tf-ioc-row:hover .ioc-arrow { color: var(--accent-orange); transform: translateX(2px); }
.tf-ioc-row:hover .ioc-hint { opacity: 1; }
.tf-ioc-left { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 5px; }
.tf-ioc-right { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
.ioc-arrow { color: var(--text-muted); transition: all 0.15s; }
.ioc-hint { font-family: var(--font-mono); font-size: 10px; color: var(--accent-orange); opacity: 0; transition: opacity 0.15s; text-transform: uppercase; letter-spacing: 0.06em; }
.ioc-val { font-size: 12px; color: var(--accent-orange); word-break: break-all; font-family: var(--font-mono); }
.ioc-meta { display: flex; flex-wrap: wrap; gap: 5px; }

.detail-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px;
  align-items: start;
  width: 100%;
}
.detail-col {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-width: 0;
  width: 100%;
}

.flex-card {
  flex: 1;
  display: flex;
  flex-direction: column;
}
.flex-card .techniques-list,
.flex-card .events-list-inner {
  flex: 1;
}

.pagination-row { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.show-more-btn { padding: 5px 10px; font-size: 11px; color: var(--text-secondary); background: transparent; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; transition: all 0.15s; font-family: var(--font-sans); }
.show-more-btn:hover { border-color: var(--border-active); color: var(--text-primary); }

.event-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 8px; border-radius: 6px; border-bottom: 1px solid var(--border); cursor: pointer; transition: all 0.15s; }
.event-row:last-child { border-bottom: none; }
.event-row:hover { background: rgba(159, 122, 234, 0.06); border-bottom-color: transparent; }
.event-row:hover .event-arrow { color: var(--accent-purple); transform: translateX(2px); }
.event-row:hover .event-hint { opacity: 1; }
.event-left { flex: 1; min-width: 0; }
.event-date { font-size: 10px; color: var(--text-muted); margin-bottom: 3px; }
.event-info { font-size: 12px; color: var(--text-primary); line-height: 1.4; margin-bottom: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.event-org { font-size: 10px; color: var(--accent-cyan); }
.event-right { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
.event-arrow { color: var(--text-muted); transition: all 0.15s; }
.event-hint { font-family: var(--font-mono); font-size: 10px; color: var(--accent-purple); opacity: 0; transition: opacity 0.15s; text-transform: uppercase; letter-spacing: 0.06em; }

.badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-high { background: rgba(221, 107, 32, 0.15); color: var(--risk-high); border: 1px solid rgba(221, 107, 32, 0.3); }
.badge-medium { background: rgba(214, 158, 46, 0.15); color: var(--risk-medium); border: 1px solid rgba(214, 158, 46, 0.3); }
.badge-low { background: rgba(56, 161, 105, 0.15); color: var(--risk-low); border: 1px solid rgba(56, 161, 105, 0.3); }
.badge-neutral { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }
.badge-info { background: rgba(66, 153, 225, 0.15); color: var(--accent-blue); border: 1px solid rgba(66, 153, 225, 0.3); }

.more-hint { font-size: 11px; color: var(--text-muted); margin-top: 10px; font-style: italic; }

@media (max-width: 800px) {
  .detail-grid { grid-template-columns: 1fr; }
  .group-header { flex-direction: column; }
  .group-stats { border-top: 1px solid var(--border); padding-top: 16px; width: 100%; }
}
</style>
