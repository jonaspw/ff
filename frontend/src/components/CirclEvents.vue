<template>
  <div class="card section-card">
    <div class="section-header">
      <span class="dot dot-purple"></span>
      <span class="section-title">{{ title || 'CIRCL Events' }}</span>
      <span class="badge badge-info" style="margin-left:auto">{{ totalCount }}</span>
    </div>

    <div class="events-list">
      <div
        v-for="ev in events"
        :key="ev.event_id || ev.uuid"
        class="event-row"
        @click="handleClick(ev.event_id || ev.uuid)"
        title="Click to view IOCs"
      >
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
    </div>

    <div v-if="hiddenCount > 0" class="more-hint">
      + {{ hiddenCount }} more events not shown
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  circlData: { type: Object, required: true },
  title: { type: String, default: 'CIRCL Events' },
  maxEvents: { type: Number, default: 10 },
})

const emit = defineEmits(['open'])

const totalCount = computed(() => props.circlData?.count ?? props.circlData?.events_count ?? 0)
const events = computed(() => (props.circlData?.events || []).slice(0, props.maxEvents))
const hiddenCount = computed(() => totalCount.value - events.value.length)

function handleClick(uuid) {
  console.log('[CirclEvents] kliknięto, uuid:', uuid)
  emit('open', uuid)
  console.log('[CirclEvents] emit wysłany')
}
</script>

<style scoped>
.section-card { padding: 16px 20px; }
.section-header {
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 12px; padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.section-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.dot-purple { background: var(--accent-purple); }

.events-list { display: flex; flex-direction: column; }

.event-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; padding: 10px 8px; border-radius: 6px;
  border-bottom: 1px solid var(--border);
  cursor: pointer; transition: all 0.15s;
}
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

.more-hint { font-size: 11px; color: var(--text-muted); margin-top: 10px; font-style: italic; padding: 0 8px; }

.badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-info { background: rgba(66, 153, 225, 0.15); color: var(--accent-blue); border: 1px solid rgba(66, 153, 225, 0.3); }
</style>
