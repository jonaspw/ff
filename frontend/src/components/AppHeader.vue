<template>
  <header class="header">
    <div class="header-inner">
      <router-link to="/" class="logo">
        <span class="logo-icon">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <circle cx="10" cy="10" r="8" stroke="#00d4ff" stroke-width="1.5" />
            <circle cx="10" cy="10" r="4" stroke="#00d4ff" stroke-width="1" stroke-dasharray="2 2" />
            <circle cx="10" cy="10" r="1.5" fill="#00d4ff" />
            <line x1="10" y1="2" x2="10" y2="5" stroke="#00d4ff" stroke-width="1" />
            <line x1="10" y1="15" x2="10" y2="18" stroke="#00d4ff" stroke-width="1" />
            <line x1="2" y1="10" x2="5" y2="10" stroke="#00d4ff" stroke-width="1" />
            <line x1="15" y1="10" x2="18" y2="10" stroke="#00d4ff" stroke-width="1" />
          </svg>
        </span>
        <span class="logo-text">APT<span class="logo-accent">tracker</span></span>
      </router-link>

      <nav class="nav">
        <router-link to="/" class="nav-link" exact-active-class="nav-link--active">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><rect x="1" y="1" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.2"/><rect x="8" y="1" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.2"/><rect x="1" y="8" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.2"/><rect x="8" y="8" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.2"/></svg>
          Dashboard
        </router-link>
        <router-link to="/analyze" class="nav-link" active-class="nav-link--active">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="6" cy="6" r="4.5" stroke="currentColor" stroke-width="1.2"/><line x1="9.5" y1="9.5" x2="13" y2="13" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
          Analyze
        </router-link>
        <router-link to="/apt" class="nav-link" active-class="nav-link--active">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 1L2 4v4c0 2.8 2.1 5.4 5 6 2.9-.6 5-3.2 5-6V4L7 1z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/></svg>
          APT Groups
        </router-link>
        <router-link to="/settings" class="nav-link" active-class="nav-link--active">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <circle cx="7" cy="7" r="2" stroke="currentColor" stroke-width="1.2"/>
            <path d="M7 1v1.5M7 11.5V13M1 7h1.5M11.5 7H13M2.6 2.6l1.1 1.1M10.3 10.3l1.1 1.1M2.6 11.4l1.1-1.1M10.3 3.7l1.1-1.1" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
          </svg>
          Settings
        </router-link>
      </nav>

    </div>
  </header>
</template>

<style scoped>
.header {
  position: sticky; top: 0; z-index: 100;
  background: rgba(10, 12, 16, 0.92);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}
.header-inner {
  max-width: 1200px; margin: 0 auto;
  padding: 0 24px; height: 56px;
  display: flex; align-items: center; gap: 32px;
}
.logo {
  display: flex; align-items: center; gap: 10px;
  text-decoration: none; flex-shrink: 0;
}
.logo-text {
  font-family: var(--font-mono); font-size: 15px;
  font-weight: 600; color: var(--text-primary);
  letter-spacing: 0.05em; text-transform: uppercase;
}
.logo-accent { color: var(--accent-cyan); }

.nav { display: flex; align-items: center; gap: 4px; flex: 1; }
.nav-link {
  display: flex; align-items: center; gap: 6px;
  padding: 6px 12px; border-radius: 6px;
  text-decoration: none; color: var(--text-secondary);
  font-size: 13px; font-weight: 500;
  transition: all 0.15s;
}
.nav-link:hover { color: var(--text-primary); background: rgba(255,255,255,0.05); }
.nav-link--active { color: var(--accent-cyan); background: rgba(0, 212, 255, 0.08); }

.status-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--accent-green);
  animation: pulse-dot 2s ease-in-out infinite;
}
.header-status { display: flex; align-items: center; gap: 6px; margin-left: auto; }
</style>
