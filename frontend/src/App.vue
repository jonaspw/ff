<template>
  <div id="app">
    <AppHeader />
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script setup>
import AppHeader from './components/AppHeader.vue'
</script>

<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');

:root {
  --bg-primary: #0a0c10;
  --bg-secondary: #0f1117;
  --bg-card: #13161e;
  --bg-card-hover: #181c26;
  --border: rgba(255, 255, 255, 0.06);
  --border-active: rgba(255, 255, 255, 0.15);

  --accent-red: #e53e3e;
  --accent-orange: #dd6b20;
  --accent-yellow: #d69e2e;
  --accent-green: #38a169;
  --accent-blue: #4299e1;
  --accent-cyan: #00d4ff;
  --accent-purple: #9f7aea;

  --text-primary: #e8eaf2;
  --text-secondary: #8892a4;
  --text-muted: #4a5568;

  --font-mono: 'JetBrains Mono', monospace;
  --font-sans: 'Space Grotesk', sans-serif;

  --risk-critical: #e53e3e;
  --risk-high: #dd6b20;
  --risk-medium: #d69e2e;
  --risk-low: #38a169;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}

#app { min-height: 100vh; display: flex; flex-direction: column; }

.main-content { flex: 1; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: #2d3748; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #4a5568; }

/* Utility */
.mono { font-family: var(--font-mono); }
.text-muted { color: var(--text-secondary); }
.badge {
  display: inline-flex; align-items: center;
  padding: 2px 8px; border-radius: 4px;
  font-family: var(--font-mono); font-size: 11px; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.05em;
}
.badge-critical { background: rgba(229, 62, 62, 0.15); color: var(--risk-critical); border: 1px solid rgba(229, 62, 62, 0.3); }
.badge-high { background: rgba(221, 107, 32, 0.15); color: var(--risk-high); border: 1px solid rgba(221, 107, 32, 0.3); }
.badge-medium { background: rgba(214, 158, 46, 0.15); color: var(--risk-medium); border: 1px solid rgba(214, 158, 46, 0.3); }
.badge-low { background: rgba(56, 161, 105, 0.15); color: var(--risk-low); border: 1px solid rgba(56, 161, 105, 0.3); }
.badge-info { background: rgba(66, 153, 225, 0.15); color: var(--accent-blue); border: 1px solid rgba(66, 153, 225, 0.3); }
.badge-neutral { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }

.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  transition: border-color 0.2s;
}
.card:hover { border-color: var(--border-active); }

/* Animations */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
.fade-in { animation: fadeIn 0.3s ease forwards; }

@keyframes pulse-dot {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

@keyframes scanline {
  0% { transform: translateY(-100%); }
  100% { transform: translateY(100vh); }
}
</style>
