<template>
  <div class="analyze-page">
    <div class="page-inner">

      <!-- Search bar -->
      <div class="search-bar-wrap">
        <form class="search-row" @submit.prevent="runAnalysis">
          <div class="search-wrap">
            <svg class="search-icon" width="14" height="14" viewBox="0 0 14 14" fill="none">
              <circle cx="5.5" cy="5.5" r="4.5" stroke="currentColor" stroke-width="1.5"/>
              <line x1="9" y1="9" x2="13" y2="13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            </svg>
            <input v-model="query" type="text" class="search-input mono"
              placeholder="IP address or domain..." @keydown.enter.prevent="runAnalysis" />
          </div>
          <button type="submit" class="btn-primary" :disabled="loading || !query.trim()">
            <span v-if="loading" class="spinner"></span>
            <span v-else>Analyze</span>
          </button>
        </form>
      </div>

      <!-- Loading -->
      <div v-if="loading" class="loading-state">
        <div class="loading-grid">
          <div v-for="src in loadingSources" :key="src" class="loading-card card">
            <div class="loading-header">
              <div class="loading-dot" :class="{ active: activeSrc === src }"></div>
              <span class="mono" style="font-size:12px">{{ src }}</span>
            </div>
            <div class="loading-bar">
              <div class="loading-fill" :class="{ done: completedSrc.includes(src) }"></div>
            </div>
          </div>
        </div>
      </div>

      <!-- Error -->
      <div v-else-if="errors.length" class="error-state card">
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" style="flex-shrink:0"><circle cx="10" cy="10" r="8" stroke="var(--risk-critical)" stroke-width="1.5"/><line x1="10" y1="6" x2="10" y2="11" stroke="var(--risk-critical)" stroke-width="1.5" stroke-linecap="round"/><circle cx="10" cy="14" r="1" fill="var(--risk-critical)"/></svg>
        <ul class="error-list">
          <li v-for="(msg, i) in errors" :key="i">{{ msg }}</li>
        </ul>
      </div>

      <!-- Results -->
      <template v-else-if="result">
        <div class="results-grid fade-in">

          <!-- Left column -->
          <div class="col-left">

            <!-- Summary card -->
            <div class="summary-card card">
              <div class="summary-top">
                <div>
                  <div class="summary-query mono">{{ result.query }}</div>
                  <div class="summary-type" v-if="result.query_type">
                    <span class="badge badge-neutral">{{ result.query_type.toUpperCase() }}</span>
                    <span v-if="result.summary?.resolved_ip" class="mono" style="font-size:11px;color:var(--text-muted)">→ {{ result.summary.resolved_ip }}</span>
                  </div>
                </div>
                <div class="risk-badge" :class="riskClass(result.summary?.risk_level)">
                  {{ result.summary?.risk_level || 'UNKNOWN' }}
                </div>
              </div>
              <div class="summary-desc" v-if="result.summary?.risk_description">
                {{ result.summary.risk_description }}
              </div>
              <div class="source-flags">
                <span v-for="(found, src) in sourcesFound" :key="src"
                  class="source-flag" :class="{ active: found }">
                  <span class="flag-dot" :class="{ active: found }"></span>
                  <span>{{ src }}</span>
                </span>
              </div>
            </div>

            <!-- AbuseIPDB -->
            <div v-if="result.abuseipdb?.success" class="card section-card">              <div class="section-header">
                <span class="section-icon abuse"></span>
                <span class="section-title">AbuseIPDB</span>
                <span v-if="!result.abuseipdb.found" class="badge badge-low" style="margin-left:auto">Clean</span>
                <template v-else>
                <span class="mono" style="font-size:11px;margin-left:auto;color:var(--text-muted)">Score</span>
                <div class="score-bar-wrap">
                  <div class="score-bar" :style="{ width: result.abuseipdb.abuse_score + '%', background: scoreColor(result.abuseipdb.abuse_score) }"></div>
                </div>
                <span class="mono score-val" :style="{ color: scoreColor(result.abuseipdb.abuse_score) }">{{ result.abuseipdb.abuse_score }}%</span>
                </template>
              </div>
              <div class="kv-grid">
                <div class="kv"><span class="kv-key">ISP</span><span class="kv-val mono">{{ result.abuseipdb.isp }}</span></div>
                <div class="kv"><span class="kv-key">Country</span><span class="kv-val mono">{{ result.abuseipdb.country }}</span></div>
                <div class="kv"><span class="kv-key">Reports</span><span class="kv-val mono">{{ result.abuseipdb.total_reports }} ({{ result.abuseipdb.distinct_users }} reporters)</span></div>
                <div class="kv" v-if="result.abuseipdb.last_reported">
                  <span class="kv-key">Last seen</span>
                  <span class="kv-val mono">{{ formatDate(result.abuseipdb.last_reported) }}</span>
                </div>
                <div class="kv" v-if="result.abuseipdb.is_tor">
                  <span class="kv-key">TOR exit</span>
                  <span class="kv-val"><span class="badge badge-high">YES</span></span>
                </div>
              </div>
              <div v-if="result.abuseipdb.categories?.length" class="tag-row">
                <span v-for="cat in result.abuseipdb.categories" :key="cat" class="badge badge-high">{{ cat }}</span>
              </div>
            </div>
            <div v-else-if="result.abuseipdb && !result.abuseipdb.success" class="card section-card not-found">              <div class="section-header">
                <span class="section-icon abuse"></span>
                <span class="section-title">AbuseIPDB</span>
                <span class="badge badge-low" style="margin-left:auto">Not found</span>
              </div>
            </div>

            <!-- VirusTotal -->
            <div v-if="result.virustotal?.success" class="card section-card">
              <div class="section-header">
                <span class="section-icon vt"></span>
                <span class="section-title">VirusTotal</span>
                <span v-if="!result.virustotal.found" class="badge badge-low" style="margin-left:auto">Clean</span>
              </div>
              <div class="vt-engines">
                <div class="vt-bar-wrap">
                  <div class="vt-segment vt-malicious" :style="{ flex: result.virustotal.malicious }"></div>
                  <div class="vt-segment vt-suspicious" :style="{ flex: result.virustotal.suspicious }"></div>
                  <div class="vt-segment vt-clean" :style="{ flex: result.virustotal.clean }"></div>
                </div>
                <div class="vt-legend">
                  <span class="vt-leg-item"><i class="vt-dot vt-malicious"></i>Malicious: {{ result.virustotal.malicious }}</span>
                  <span class="vt-leg-item"><i class="vt-dot vt-suspicious"></i>Suspicious: {{ result.virustotal.suspicious }}</span>
                  <span class="vt-leg-item"><i class="vt-dot vt-clean"></i>Clean: {{ result.virustotal.clean }}</span>
                  <span class="vt-leg-item" style="margin-left:auto;color:var(--text-muted)">/ {{ result.virustotal.total_engines }} engines</span>
                </div>
              </div>
              <div class="kv-grid">
                <div class="kv" v-if="result.virustotal.org"><span class="kv-key">Org</span><span class="kv-val mono">{{ result.virustotal.org }}</span></div>
                <div class="kv" v-if="result.virustotal.asn"><span class="kv-key">ASN</span><span class="kv-val mono">{{ result.virustotal.asn }}</span></div>
                <div class="kv" v-if="result.virustotal.country"><span class="kv-key">Country</span><span class="kv-val mono">{{ result.virustotal.country }}</span></div>
                <div class="kv" v-if="result.virustotal.reputation !== undefined">
                  <span class="kv-key">Reputation</span>
                  <span class="kv-val mono" :style="{ color: result.virustotal.reputation < 0 ? 'var(--risk-critical)' : 'var(--risk-low)' }">{{ result.virustotal.reputation }}</span>
                </div>
              </div>
              <div v-if="result.virustotal.tags?.length" class="tag-row">
                <span v-for="tag in result.virustotal.tags" :key="tag" class="badge badge-info">{{ tag }}</span>
              </div>
              <div v-if="result.virustotal.dns_records?.length" class="dns-records">
                <div class="sub-title">DNS Records</div>
                <div v-for="rec in result.virustotal.dns_records" :key="rec.hostname" class="dns-row mono">
                  {{ rec.hostname }}
                </div>
              </div>
            </div>
            <div v-else-if="result.virustotal && !result.virustotal.success" class="card section-card not-found">
              <div class="section-header">
                <span class="section-icon vt"></span>
                <span class="section-title">VirusTotal</span>
                <span class="badge badge-low" style="margin-left:auto">Not found</span>
              </div>
            </div>

          </div>

          <!-- Right column -->
          <div class="col-right">

            <!-- WHOIS -->
            <div v-if="result.whois?.found" class="card section-card">
              <div class="section-header">
                <span class="section-icon whois"></span>
                <span class="section-title">WHOIS{{ result.whois.type === 'ip' ? ' / BGP' : '' }}</span>
              </div>
              <div class="kv-grid">
                <!-- IP fields -->
                <div class="kv" v-if="result.whois.asn"><span class="kv-key">ASN</span><span class="kv-val mono">AS{{ result.whois.asn }} — {{ result.whois.asn_name }}</span></div>
                <div class="kv" v-if="result.whois.network_name"><span class="kv-key">Network</span><span class="kv-val mono">{{ result.whois.network_name }}</span></div>
                <div class="kv" v-if="result.whois.network_cidr"><span class="kv-key">CIDR</span><span class="kv-val mono">{{ result.whois.network_cidr }}</span></div>
                <div class="kv" v-if="result.whois.country"><span class="kv-key">Country</span><span class="kv-val mono">{{ result.whois.country }}</span></div>
                <div class="kv" v-if="result.whois.org"><span class="kv-key">Org</span><span class="kv-val mono">{{ result.whois.org }}</span></div>
                <!-- Domain fields -->
                <div class="kv" v-if="result.whois.domain"><span class="kv-key">Domain</span><span class="kv-val mono">{{ result.whois.domain }}</span></div>
                <div class="kv" v-if="result.whois.registrar"><span class="kv-key">Registrar</span><span class="kv-val mono">{{ result.whois.registrar }}</span></div>
                <div class="kv" v-if="result.whois.created"><span class="kv-key">Created</span><span class="kv-val mono">{{ formatDate(result.whois.created) }}</span></div>
                <div class="kv" v-if="result.whois.updated"><span class="kv-key">Updated</span><span class="kv-val mono">{{ formatDate(result.whois.updated) }}</span></div>
                <div class="kv" v-if="result.whois.expires"><span class="kv-key">Expires</span><span class="kv-val mono">{{ formatDate(result.whois.expires) }}</span></div>
                <div class="kv" v-if="result.whois.nameservers?.length">
                  <span class="kv-key">Nameservers</span>
                  <span class="kv-val mono">{{ result.whois.nameservers.join(', ') }}</span>
                </div>
                <div class="kv" v-if="result.whois.status?.length">
                  <span class="kv-key">Status</span>
                  <span class="kv-val mono">{{ result.whois.status.join(', ') }}</span>
                </div>
                <div class="kv" v-if="result.whois.emails?.length">
                  <span class="kv-key">Emails</span>
                  <span class="kv-val mono">{{ result.whois.emails.join(', ') }}</span>
                </div>
              </div>
            </div>
            <div v-else-if="result.whois && !result.whois.found" class="card section-card not-found">
              <div class="section-header">
                <span class="section-icon whois"></span>
                <span class="section-title">WHOIS / BGP</span>
                <span class="badge badge-low" style="margin-left:auto">Not found</span>
              </div>
            </div>

            <!-- Shodan -->
            <div v-if="result.shodan?.found" class="card section-card">
              <div class="section-header">
                <span class="section-icon shodan"></span>
                <span class="section-title">Shodan</span>
                <span v-if="result.shodan.tags?.length" class="badge badge-info" style="margin-left:auto">{{ result.shodan.tags.join(', ') }}</span>
              </div>
              <div class="kv-grid">
                <div class="kv" v-if="result.shodan.organization"><span class="kv-key">Org</span><span class="kv-val mono">{{ result.shodan.organization }}</span></div>
                <div class="kv" v-if="result.shodan.isp"><span class="kv-key">ISP</span><span class="kv-val mono">{{ result.shodan.isp }}</span></div>
                <div class="kv" v-if="result.shodan.country"><span class="kv-key">Country</span><span class="kv-val mono">{{ result.shodan.country }}<span v-if="result.shodan.city"> — {{ result.shodan.city }}</span></span></div>
                <div class="kv" v-if="result.shodan.asn"><span class="kv-key">ASN</span><span class="kv-val mono">{{ result.shodan.asn }}</span></div>
                <div class="kv" v-if="result.shodan.ports?.length"><span class="kv-key">Open ports</span><span class="kv-val mono">{{ result.shodan.ports.join(', ') }}</span></div>
                <div class="kv" v-if="result.shodan.hostnames?.length"><span class="kv-key">Hostnames</span><span class="kv-val mono">{{ result.shodan.hostnames.join(', ') }}</span></div>
                <div class="kv" v-if="result.shodan.domains?.length"><span class="kv-key">Domains</span><span class="kv-val mono">{{ result.shodan.domains.join(', ') }}</span></div>
                <div class="kv" v-if="result.shodan.os"><span class="kv-key">OS</span><span class="kv-val mono">{{ result.shodan.os }}</span></div>
                <div class="kv" v-if="result.shodan.last_update"><span class="kv-key">Last seen</span><span class="kv-val mono">{{ formatDate(result.shodan.last_update) }}</span></div>
              </div>

              <!-- HTTP banners -->
              <template v-if="result.shodan.bannery_http?.length">
                <div class="sub-title">HTTP Banners</div>
                <div v-for="b in result.shodan.bannery_http" :key="b.port" class="banner-row">
                  <span class="mono banner-port">:{{ b.port }}</span>
                  <span class="mono banner-status" :class="b.status === 200 ? 'ok' : 'err'">{{ b.status }}</span>
                  <span v-if="b.server" class="banner-server mono">{{ b.server }}</span>
                  <span v-if="b.title" class="banner-title">{{ b.title }}</span>
                </div>
              </template>

              <!-- Certificates -->
              <template v-if="result.shodan.certyfikaty?.length">
                <div class="sub-title" style="margin-top:12px">Certificates</div>
                <div v-for="cert in result.shodan.certyfikaty" :key="cert.fingerprint?.sha1"
                  class="cert-row cert-row--clickable"
                  @click="activeShodanCert = cert"
                  title="Click to view full certificate"
                >
                  <div class="cert-line">
                    <span class="mono cert-port">port {{ cert.port }}</span>
                    <span class="cert-cn">{{ cert.subject?.CN }}</span>
                  </div>
                  <div class="cert-issuer mono">issued by {{ cert.issuer?.CN }}</div>
                  <div class="cert-fp mono">{{ cert.fingerprint?.sha256?.slice(0, 32) }}…</div>
                  <svg class="cert-chevron" width="14" height="14" viewBox="0 0 14 14" fill="none">
                    <path d="M5 3l4 4-4 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
                  </svg>
                </div>
              </template>

              <!-- CVEs -->
              <template v-if="result.shodan.vulns?.length">
                <div class="sub-title" style="margin-top:12px">
                  Vulnerabilities
                  <span class="badge badge-critical" style="margin-left:6px;vertical-align:middle">{{ result.shodan.vulns.length }}</span>
                </div>
                <div class="cve-grid">
                  <a
                    v-for="cve in result.shodan.vulns"
                    :key="cve"
                    :href="`https://nvd.nist.gov/vuln/detail/${cve}`"
                    target="_blank"
                    rel="noopener"
                    class="cve-chip mono"
                  >{{ cve }}</a>
                </div>
              </template>
            </div>
            <div v-else-if="result.shodan && !result.shodan.found" class="card section-card not-found">
              <div class="section-header">
                <span class="section-icon shodan"></span>
                <span class="section-title">Shodan</span>
                <span class="badge badge-low" style="margin-left:auto">Not found</span>
              </div>
            </div>

            <!-- ThreatFox -->
            <div v-if="result.threatfox?.found" class="card section-card">
              <div class="section-header">
                <span class="section-icon tf"></span>
                <span class="section-title">ThreatFox IOCs</span>
                <span class="badge badge-high" style="margin-left:auto">{{ result.threatfox.count }} hits</span>
              </div>
              <div
                v-for="ioc in threatfoxVisible"
                :key="ioc.id || ioc.ioc"
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
              <div class="pagination-row">
                <button v-if="threatfoxLimit < result.threatfox.iocs.length" class="show-more-btn" @click="threatfoxLimit += 10">
                  Show 10 more<span class="text-muted">(zostało {{ result.threatfox.iocs.length - threatfoxLimit }})</span>
                </button>
                <button v-if="threatfoxLimit > 10" class="show-more-btn" @click="threatfoxLimit = 10">Collapse</button>
              </div>
            </div>
            <div v-else-if="result.threatfox && !result.threatfox.found" class="card section-card not-found">
              <div class="section-header">
                <span class="section-icon tf"></span>
                <span class="section-title">ThreatFox</span>
                <span class="badge badge-low" style="margin-left:auto">Not found</span>
              </div>
            </div>

            <!-- CIRCL -->
            <div v-if="result.circl?.found" class="card section-card">
              <div class="section-header">
                <span class="section-icon circl"></span>
                <span class="section-title">CIRCL Events</span>
                <span class="badge badge-info" style="margin-left:auto">{{ result.circl.events_count || result.circl.count }}</span>
              </div>
              <div v-for="ev in circlEventsVisible" :key="ev.event_id || ev.uuid"
                class="circl-row" @click="activeCirclUuid = ev.event_id || ev.uuid">
                <div class="event-left">
                  <div class="event-date mono">{{ ev.date }}</div>
                  <div class="event-info">{{ ev.info }}</div>
                  <div class="event-org mono">{{ ev.org }}</div>
                </div>
                <div class="event-right">
                  <span class="circl-hint">IOCs</span>
                  <svg class="circl-arrow" width="14" height="14" viewBox="0 0 14 14" fill="none">
                    <path d="M5 3l4 4-4 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
                  </svg>
                </div>
              </div>
              <div class="pagination-row">
                <button v-if="circlLimit < result.circl.events.length" class="show-more-btn" @click="circlLimit += 10">
                  Show 10 more<span class="text-muted">(zostało {{ result.circl.events.length - circlLimit }})</span>
                </button>
                <button v-if="circlLimit > 10" class="show-more-btn" @click="circlLimit = 10">Collapse</button>
              </div>
            </div>
            <div v-else-if="result.circl && !result.circl.found" class="card section-card not-found">
              <div class="section-header">
                <span class="section-icon circl"></span>
                <span class="section-title">CIRCL</span>
                <span class="badge badge-low" style="margin-left:auto">Not found</span>
              </div>
            </div>

            <!-- Subdomains -->
            <div v-if="result.summary?.subdomeny?.length" class="card section-card">
              <div class="section-header">
                <span class="section-title">Subdomains</span>
                <span class="badge badge-neutral" style="margin-left:auto">
                  {{ result.summary.subdomeny.length }}
                </span>
              </div>
              <div class="subdomain-list">
                <span
                  v-for="sub in subdomainsVisible"
                  :key="sub"
                  class="mono subdomain-item"
                >{{ sub }}</span>
              </div>
              <div class="subdomain-controls" v-if="result.summary.subdomeny.length > 20">
                <button
                  v-if="subdomainsLimit < result.summary.subdomeny.length"
                  class="show-more-btn"
                  @click="subdomainsLimit += 20"
                >
                  Show 20 more
                  <span class="text-muted">
                    (left {{ result.summary.subdomeny.length - subdomainsLimit }})
                  </span>
                </button>
                <button
                  v-if="subdomainsLimit > 20"
                  class="show-more-btn"
                  @click="subdomainsLimit = 20"
                >
                  Collapse
                </button>
              </div>
            </div>

            <!-- crt.sh -->
            <div v-if="result.crtsh?.found" class="card section-card">
              <div class="section-header">
                <span class="section-icon crtsh"></span>
                <span class="section-title">crt.sh</span>
                <span class="badge badge-info" style="margin-left:auto">{{ result.crtsh.cert_count }} certs</span>
              </div>

              <!-- Domains from certificates -->
              <template v-if="result.crtsh.domeny?.length">
                <div class="sub-title">Domains in certificates</div>
                <div class="crtsh-domains">
                  <span
                    v-for="d in crtshDomainsVisible"
                    :key="d"
                    class="mono crtsh-domain"
                  >{{ d }}</span>
                </div>
                <button
                  v-if="result.crtsh.domeny.length > crtshDomainsLimit"
                  class="show-more-btn"
                  @click="crtshDomainsLimit = crtshDomainsLimit + 20"
                >
                  Show {{ Math.min(20, result.crtsh.domeny.length - crtshDomainsLimit) }} more
                  <span class="text-muted">({{ result.crtsh.domeny.length - crtshDomainsLimit }} remaining)</span>
                </button>
              </template>

              <!-- Recent certificates -->
              <template v-if="result.crtsh.certyfikaty?.length">
                <div class="sub-title" style="margin-top:14px">
                  Recent certificates
                  <span class="text-muted" style="font-size:10px;margin-left:6px">showing {{ result.crtsh.certyfikaty.length }} of {{ result.crtsh.cert_count }}</span>
                </div>
                <div class="crtsh-cert-list">
                  <div
                    v-for="cert in crtshCertsVisible"
                    :key="cert.id"
                    class="crtsh-cert-row"
                  >
                    <div class="cert-cn mono">{{ cert.common_name }}</div>
                    <div class="cert-meta">
                      <span class="mono cert-issuer-short">{{ cert.issuer }}</span>
                    </div>
                    <div class="cert-dates mono">
                      {{ formatCertDate(cert.not_before) }} → {{ formatCertDate(cert.not_after) }}
                    </div>
                    <a
                      :href="`https://crt.sh/?id=${cert.id}`"
                      target="_blank"
                      rel="noopener"
                      class="cert-link"
                    >
                      <svg width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M10 2H7M10 2V5M10 2L5.5 6.5M9 7v3H2V3h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    </a>
                  </div>
                </div>
                <button
                  v-if="result.crtsh.certyfikaty.length > crtshCertsLimit"
                  class="show-more-btn"
                  @click="crtshCertsLimit = crtshCertsLimit + 10"
                >
                  Show {{ Math.min(10, result.crtsh.certyfikaty.length - crtshCertsLimit) }} more
                </button>
              </template>
            </div>
            <div v-else-if="result.crtsh && !result.crtsh.found" class="card section-card not-found">
              <div class="section-header">
                <span class="section-icon crtsh"></span>
                <span class="section-title">crt.sh</span>
                <span class="badge badge-low" style="margin-left:auto">Not found</span>
              </div>
            </div>

          </div>
        </div>
      </template>

      <ThreatFoxIocModal
        v-if="activeTfIoc"
        :ioc="activeTfIoc"
        @close="activeTfIoc = null"
      />

      <ShodanCertModal
        v-if="activeShodanCert"
        :cert="activeShodanCert"
        @close="activeShodanCert = null"
      />

      <CirclEventModal
        v-if="activeCirclUuid"
        :uuid="activeCirclUuid"
        @close="activeCirclUuid = null"
      />

      <!-- Empty state -->
      <div v-if="!result && !loading && !errors.length" class="empty-state">
        <div class="empty-icon">
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <circle cx="22" cy="22" r="16" stroke="var(--text-muted)" stroke-width="1.5" stroke-dasharray="4 3"/>
            <circle cx="22" cy="22" r="6" stroke="var(--text-muted)" stroke-width="1.5"/>
            <line x1="34" y1="34" x2="44" y2="44" stroke="var(--text-muted)" stroke-width="2" stroke-linecap="round"/>
          </svg>
        </div>
        <p>Enter an IP address or domain name to begin analysis.</p>
      </div>

    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import CirclEvents from '../components/CirclEvents.vue'
import CirclEventModal from '../components/CirclEventModal.vue'
import ThreatFoxIocModal from '../components/ThreatFoxIocModal.vue'
import ShodanCertModal from '../components/ShodanCertModal.vue'

const route = useRoute()
const router = useRouter()

const query = ref('')
const result = ref(null)
const loading = ref(false)
const errors = ref([])
const activeSrc = ref('')
const completedSrc = ref([])
const activeTfIoc = ref(null)
const activeShodanCert = ref(null)
const activeCirclUuid = ref(null)
const crtshDomainsLimit = ref(10)
const threatfoxLimit = ref(10)
const circlLimit = ref(10)
const threatfoxVisible = computed(() => result.value?.threatfox?.iocs?.slice(0, threatfoxLimit.value) ?? [])
const circlEventsVisible = computed(() => result.value?.circl?.events?.slice(0, circlLimit.value) ?? [])
const subdomainsLimit = ref(20)
const subdomainsVisible = computed(
  () => result.value?.summary?.subdomeny?.slice(0, subdomainsLimit.value) ?? []
)
const crtshCertsLimit = ref(10)

const crtshDomainsVisible = computed(() => result.value?.crtsh?.domeny?.slice(0, crtshDomainsLimit.value) ?? [])
const crtshCertsVisible = computed(() => result.value?.crtsh?.certyfikaty?.slice(0, crtshCertsLimit.value) ?? [])

const loadingSources = ['VirusTotal', 'AbuseIPDB', 'ThreatFox', 'CIRCL', 'WHOIS', 'Shodan', 'crt.sh']

const sourcesFound = computed(() => {
  if (!result.value?.summary) return {}
  const s = result.value.summary
  return {
    VirusTotal: result.value?.virustotal?.success ?? s.found_in_virustotal,
    AbuseIPDB: result.value?.abuseipdb?.success ?? s.found_in_abuseipdb,
    ThreatFox: s.found_in_threatfox,
    CIRCL: s.found_in_circl,
    WHOIS: s.found_in_whois,
    Shodan: s.found_in_shodan,
    'crt.sh': s.found_in_crtsh,
  }
})

function riskClass(level) {
  const m = { CRITICAL: 'risk-critical', HIGH: 'risk-high', MEDIUM: 'risk-medium', LOW: 'risk-low' }
  return m[level] || 'risk-unknown'
}

function scoreColor(score) {
  if (score >= 80) return 'var(--risk-critical)'
  if (score >= 50) return 'var(--risk-high)'
  if (score >= 20) return 'var(--risk-medium)'
  return 'var(--risk-low)'
}

function formatDate(dateStr) {
  try { return new Date(dateStr).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) }
  catch { return dateStr }
}

function formatCertDate(dateStr) {
  try { return new Date(dateStr).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) }
  catch { return dateStr }
}

async function runAnalysis() {
  const q = query.value.trim()
  if (!q) return
  router.replace({ query: { q } })
  result.value = null
  errors.value = []
  loading.value = true
  completedSrc.value = []
  crtshDomainsLimit.value = 10
  crtshCertsLimit.value = 10
  threatfoxLimit.value = 10
  circlLimit.value = 10

  const srcInterval = setInterval(() => {
    const remaining = loadingSources.filter(s => !completedSrc.value.includes(s))
    if (remaining.length) {
      activeSrc.value = remaining[0]
      completedSrc.value.push(remaining[0])
    } else {
      clearInterval(srcInterval)
    }
  }, 400)

  try {
    const res = await fetch(`/api/analyze/?q=${encodeURIComponent(q)}`)
    const data = await res.json()
    if (!res.ok) {
      // Parsuj błędy z backendu: { error: { q: ["..."], ... } }
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
    clearInterval(srcInterval)
    completedSrc.value = [...loadingSources]
    loading.value = false
    activeSrc.value = ''
  }
}

onMounted(() => {
  if (route.query.q) {
    query.value = route.query.q
    runAnalysis()
  }
})
</script>

<style scoped>
.pagination-row { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.circl-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 8px; border-radius: 6px; border-bottom: 1px solid var(--border); cursor: pointer; transition: all 0.15s; }
.circl-row:last-child { border-bottom: none; }
.circl-row:hover { background: rgba(159, 122, 234, 0.06); border-bottom-color: transparent; }
.circl-row:hover .circl-arrow { color: var(--accent-purple); transform: translateX(2px); }
.circl-row:hover .circl-hint { opacity: 1; }
.circl-arrow { color: var(--text-muted); transition: all 0.15s; }
.circl-hint { font-family: var(--font-mono); font-size: 10px; color: var(--accent-purple); opacity: 0; transition: opacity 0.15s; text-transform: uppercase; letter-spacing: 0.06em; }

.analyze-page { padding: 32px 0 80px; }
.page-inner { max-width: 1200px; margin: 0 auto; padding: 0 24px; }

.search-bar-wrap { margin-bottom: 32px; }
.search-row { display: flex; gap: 8px; }
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

.loading-state { margin-top: 16px; }
.loading-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
.loading-card { padding: 14px 16px; }
.loading-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.loading-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--text-muted); transition: background 0.3s; }
.loading-dot.active { background: var(--accent-cyan); animation: pulse-dot 0.8s ease-in-out infinite; }
.loading-bar { height: 2px; background: var(--border); border-radius: 1px; overflow: hidden; }
.loading-fill { height: 100%; width: 0%; background: var(--accent-cyan); transition: width 1s ease; }
.loading-fill.done { width: 100%; background: var(--accent-green); }

.error-state { padding: 20px; display: flex; align-items: flex-start; gap: 12px; color: var(--risk-critical); font-size: 14px; }
.error-list { list-style: none; display: flex; flex-direction: column; gap: 4px; }
.error-list li::before { content: '— '; }

.results-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
.col-left, .col-right { display: flex; flex-direction: column; gap: 16px; }

.summary-card { padding: 20px 24px; }
.summary-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
.summary-query { font-size: 18px; font-weight: 600; color: var(--accent-cyan); }
.summary-type { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.risk-badge { flex-shrink: 0; padding: 6px 14px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; }
.risk-critical { background: rgba(229,62,62,0.15); color: var(--risk-critical); border: 1px solid rgba(229,62,62,0.3); }
.risk-high { background: rgba(221,107,32,0.15); color: var(--risk-high); border: 1px solid rgba(221,107,32,0.3); }
.risk-medium { background: rgba(214,158,46,0.15); color: var(--risk-medium); border: 1px solid rgba(214,158,46,0.3); }
.risk-low { background: rgba(56,161,105,0.15); color: var(--risk-low); border: 1px solid rgba(56,161,105,0.3); }
.risk-unknown { background: rgba(255,255,255,0.05); color: var(--text-secondary); border: 1px solid var(--border); }
.summary-desc { font-size: 13px; color: var(--text-secondary); margin-bottom: 16px; }

.source-flags { display: flex; flex-wrap: wrap; gap: 6px; }
.source-flag { display: flex; align-items: center; gap: 5px; padding: 4px 10px; border-radius: 4px; font-size: 12px; color: var(--text-muted); border: 1px solid var(--border); background: var(--bg-secondary); transition: all 0.2s; }
.source-flag.active { color: var(--text-secondary); border-color: var(--border-active); }
.flag-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--text-muted); }
.flag-dot.active { background: var(--accent-green); }

.section-card { padding: 16px 20px; }
.section-header { display: flex; align-items: center; gap: 8px; margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }
.section-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.not-found .section-header { margin-bottom: 0; padding-bottom: 0; border-bottom: none; }

.section-icon { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.section-icon.abuse { background: var(--risk-critical); }
.section-icon.vt { background: var(--accent-blue); }
.section-icon.whois { background: var(--accent-green); }
.section-icon.tf { background: var(--accent-orange); }
.section-icon.circl { background: var(--accent-purple); }
.section-icon.shodan { background: #e8073a; }
.section-icon.crtsh { background: #b794f4; }

.subdomain-list { display: flex; flex-direction: column; gap: 4px; }
.subdomain-item { font-size: 11px; color: var(--accent-cyan); }

.crtsh-domains { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 8px; }
.crtsh-domain {
  font-size: 11px; color: var(--text-secondary);
  padding: 2px 7px; border-radius: 3px;
  background: rgba(255,255,255,0.04); border: 1px solid var(--border);
  word-break: break-all;
}

.crtsh-cert-list { display: flex; flex-direction: column; }
.crtsh-cert-row {
  display: grid;
  grid-template-columns: 1fr auto;
  grid-template-rows: auto auto auto;
  gap: 2px 8px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
  align-items: start;
}
.crtsh-cert-row:last-child { border-bottom: none; }
.cert-cn { font-size: 12px; color: var(--accent-cyan); grid-column: 1; }
.cert-meta { grid-column: 1; }
.cert-issuer-short { font-size: 10px; color: var(--text-muted); }
.cert-dates { font-size: 10px; color: var(--text-muted); grid-column: 1; }
.cert-link {
  grid-column: 2; grid-row: 1 / 4;
  align-self: center;
  color: var(--text-muted); text-decoration: none;
  padding: 4px; border-radius: 4px; border: 1px solid var(--border);
  display: flex; align-items: center; justify-content: center;
  transition: all 0.15s;
}
.cert-link:hover { color: var(--accent-cyan); border-color: rgba(0,212,255,0.3); }

.show-more-btn {
  margin-top: 8px; padding: 5px 10px;
  font-size: 11px; color: var(--text-secondary);
  background: transparent; border: 1px solid var(--border);
  border-radius: 4px; cursor: pointer; transition: all 0.15s;
  font-family: var(--font-sans);
}
.show-more-btn:hover { border-color: var(--border-active); color: var(--text-primary); }

.crtsh-error { font-size: 11px; color: var(--text-muted); padding: 4px 0; }

.kv-grid { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
.kv { display: flex; gap: 8px; align-items: flex-start; font-size: 12px; }
.kv:last-child { margin-bottom: 0; }
.kv-key { color: var(--text-muted); width: 80px; flex-shrink: 0; padding-top: 1px; }
.kv-val { color: var(--text-primary); word-break: break-all; }

.tag-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }

.score-bar-wrap { flex: 1; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; max-width: 80px; }
.score-bar { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
.score-val { font-size: 12px; font-weight: 600; }

.vt-bar-wrap { display: flex; height: 6px; border-radius: 3px; overflow: hidden; margin-bottom: 8px; gap: 2px; }
.vt-segment { border-radius: 2px; }
.vt-malicious { background: var(--risk-critical); }
.vt-suspicious { background: var(--risk-medium); }
.vt-clean { background: var(--risk-low); }
.vt-legend { display: flex; flex-wrap: wrap; gap: 12px; font-size: 11px; color: var(--text-secondary); margin-bottom: 12px; }
.vt-leg-item { display: flex; align-items: center; gap: 5px; }
.vt-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }

.dns-records { margin-top: 10px; }
.sub-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 6px; }
.dns-row { font-size: 11px; color: var(--text-secondary); padding: 3px 0; border-bottom: 1px solid var(--border); }

.tf-ioc-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; padding: 10px 8px; border-radius: 6px;
  border-bottom: 1px solid var(--border);
  cursor: pointer; transition: all 0.15s;
}
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

.banner-row {
  display: flex; align-items: center; flex-wrap: wrap; gap: 8px;
  padding: 5px 0; border-bottom: 1px solid var(--border); font-size: 12px;
}
.banner-row:last-child { border-bottom: none; }
.banner-port { color: var(--accent-cyan); width: 40px; flex-shrink: 0; }
.banner-status { font-weight: 600; }
.banner-status.ok { color: var(--risk-low); }
.banner-status.err { color: var(--risk-high); }
.banner-server { color: var(--text-muted); }
.banner-title { color: var(--text-secondary); font-size: 11px; }

.cert-row { padding: 7px 0; border-bottom: 1px solid var(--border); }
.cert-row:last-child { border-bottom: none; }
.cert-row--clickable {
  padding: 8px 6px; border-radius: 5px; border-bottom: 1px solid var(--border);
  cursor: pointer; transition: all 0.15s; position: relative;
  display: grid; grid-template-columns: 1fr auto; grid-template-rows: auto auto auto;
  align-items: start; gap: 2px 8px;
}
.cert-row--clickable:last-child { border-bottom: none; }
.cert-row--clickable:hover { background: rgba(232, 7, 58, 0.05); border-bottom-color: transparent; }
.cert-row--clickable:hover .cert-chevron { color: #e8073a; transform: translateX(2px); }
.cert-row--clickable .cert-line { grid-column: 1; }
.cert-row--clickable .cert-issuer { grid-column: 1; }
.cert-row--clickable .cert-fp { grid-column: 1; }
.cert-chevron { grid-column: 2; grid-row: 1 / 4; align-self: center; color: var(--text-muted); transition: all 0.15s; flex-shrink: 0; }
.cert-line { display: flex; align-items: center; gap: 8px; margin-bottom: 3px; }
.cert-port { font-size: 10px; color: var(--text-muted); }
.cert-cn { font-size: 12px; color: var(--text-primary); font-weight: 500; }
.cert-issuer { font-size: 11px; color: var(--text-muted); margin-bottom: 2px; }
.cert-fp { font-size: 10px; color: var(--text-muted); word-break: break-all; }

.cve-grid { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 6px; }
.cve-chip {
  font-size: 10px; padding: 2px 7px; border-radius: 3px;
  background: rgba(229, 62, 62, 0.08); border: 1px solid rgba(229, 62, 62, 0.25);
  color: var(--risk-critical); text-decoration: none; transition: all 0.15s;
}
.cve-chip:hover { background: rgba(229, 62, 62, 0.18); border-color: rgba(229, 62, 62, 0.5); }


.subdomain-item { font-size: 11px; color: var(--accent-cyan); }

.spinner { width: 14px; height: 14px; border: 2px solid rgba(10,12,16,0.3); border-top-color: #0a0c10; border-radius: 50%; animation: spin 0.7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.empty-state { text-align: center; padding: 80px 24px; color: var(--text-muted); font-size: 14px; }
.empty-icon { margin-bottom: 20px; }

.badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-high { background: rgba(221, 107, 32, 0.15); color: var(--risk-high); border: 1px solid rgba(221, 107, 32, 0.3); }
.badge-low { background: rgba(56, 161, 105, 0.15); color: var(--risk-low); border: 1px solid rgba(56, 161, 105, 0.3); }
.badge-info { background: rgba(66, 153, 225, 0.15); color: var(--accent-blue); border: 1px solid rgba(66, 153, 225, 0.3); }
.badge-neutral { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }

@media (max-width: 800px) {
  .results-grid { grid-template-columns: 1fr; }
  .loading-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>
