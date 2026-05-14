# backend/analyzer/services.py

import ipaddress
import socket
import sqlite3
import json

from django.conf import settings
from mitreattack.stix20 import MitreAttackData

from threatfox.services import ThreatFoxService
from circl.services import CIRCLFeedService
from shodanapp.services import ShodanService
from crtsh.services import CrtShService
from whois_lookup.services import WhoisService
from abuseipdb.services import AbuseIPDBService
from virustotal.services import VirusTotalService


class AnalyzerService:

    # Słownik aliasów — atrybut klasy (poza __init__)
    ALIASES = {
        "apt28":      ["apt28", "fancy bear", "sofacy", "strontium",
                       "pawn storm", "sednit", "forest blizzard"],
        "apt29":      ["apt29", "cozy bear", "nobelium",
                       "midnight blizzard", "the dukes"],
        "apt41":      ["apt41", "double dragon", "winnti",
                       "barium", "earth baku"],
        "lazarus":    ["lazarus", "hidden cobra", "zinc",
                       "apt38", "nickel academy"],
        "sandworm":   ["sandworm", "telebots", "voodoo bear",
                       "electrum", "seashell blizzard"],
        "kimsuky":    ["kimsuky", "thallium", "emerald sleet", "apt43"],
        "muddywater": ["muddywater", "mercury", "seedworm",
                       "mango sandstorm"],
        "apt35":      ["apt35", "charming kitten", "phosphorus",
                       "mint sandstorm", "ta453"],
        "ta505":      ["ta505", "hive0065", "spandex tempest"],
    }

    def __init__(self):
        self.threatfox  = ThreatFoxService()
        self.circl      = CIRCLFeedService()
        self.shodan     = ShodanService()
        self.crtsh      = CrtShService()
        self.whois      = WhoisService()
        self.abuseipdb  = AbuseIPDBService()
        self.virustotal = VirusTotalService()
        self._mitre     = None

    # ============================================================
    # HELPERS
    # ============================================================

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _resolve_domain(self, domain: str) -> str | None:
        """Rozwiązuje domenę na IP przez DNS."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    # ============================================================
    # GŁÓWNA METODA — IP / DOMENA
    # ============================================================

    def analyze(self, query: str) -> dict:
        is_ip       = self._is_ip(query)
        resolved_ip = None

        if not is_ip:
            resolved_ip = self._resolve_domain(query)

        ip_for_shodan = query if is_ip else resolved_ip

        tf_data     = self._query_threatfox(query, resolved_ip)
        circl_data  = self._query_circl(query, resolved_ip)
        shodan_data = self._query_shodan(ip_for_shodan, query)
        crtsh_data  = self._query_crtsh(query, ip_for_shodan)
        whois_data = self.whois.lookup(query)
        abuse_data = None
        if is_ip:
            abuse_data = self.abuseipdb.check_ip(query)
        vt_data = self.virustotal.lookup(query)

        summary = self._build_summary(
            query, resolved_ip, tf_data, circl_data,
            shodan_data, crtsh_data, vt_data, abuse_data, whois_data
        )

        return {
            "success":     True,
            "query":       query,
            "query_type":  "ip" if is_ip else "domain",
            "resolved_ip": resolved_ip,
            "summary":     summary,
            "threatfox":   tf_data,
            "circl":       circl_data,
            "shodan":      shodan_data,
            "crtsh":       crtsh_data,
            "whois":       whois_data,
            "abuseipdb":   abuse_data,
            "virustotal":  vt_data,
        }

    # ============================================================
    # THREATFOX
    # ============================================================

    def _query_threatfox(
        self, query: str, resolved_ip: str | None
    ) -> dict:
        wszystkie_ioc = []
        widziane      = set()

        def dodaj_ioc(ioc_lista):
            for ioc in ioc_lista:
                klucz = ioc.get("ioc", "")
                if klucz not in widziane:
                    widziane.add(klucz)
                    wszystkie_ioc.append(ioc)

        result1 = self.threatfox.search_ioc(query)
        if result1.get("success"):
            dodaj_ioc(result1.get("iocs", []))

        if resolved_ip:
            result2 = self.threatfox.search_ioc(resolved_ip)
            if result2.get("success"):
                dodaj_ioc(result2.get("iocs", []))

        return {
            "found":        len(wszystkie_ioc) > 0,
            "count":        len(wszystkie_ioc),
            "iocs":         wszystkie_ioc,
            "searched_for": [query] + ([resolved_ip] if resolved_ip else []),
        }

    # ============================================================
    # CIRCL
    # ============================================================

    def _query_circl(
        self, query: str, resolved_ip: str | None
    ) -> dict:
        matched_iocs   = []
        matched_events = []
        widziane_uuid  = set()

        def szukaj(fraza: str):
            conn = sqlite3.connect("cache.db")
            try:
                rows = conn.execute(
                    "SELECT uuid, data FROM circl_events"
                ).fetchall()
            except Exception:
                conn.close()
                return
            conn.close()

            fraza_lower = fraza.lower()
            for uuid, data_json in rows:
                event    = json.loads(data_json)
                pasujace = [
                    ioc for ioc in event.get("iocs", [])
                    if fraza_lower in ioc.get("value", "").lower()
                ]
                if pasujace and uuid not in widziane_uuid:
                    widziane_uuid.add(uuid)
                    matched_iocs.extend(pasujace)
                    matched_events.append({
                        "event_id": uuid,
                        "info":     event.get("info", ""),
                        "date":     event.get("date", ""),
                        "matched":  len(pasujace),
                    })

        szukaj(query)
        if resolved_ip:
            szukaj(resolved_ip)

        return {
            "found":        len(matched_iocs) > 0,
            "events_count": len(matched_events),
            "iocs":         matched_iocs,
            "events":       matched_events,
            "searched_for": [query] + ([resolved_ip] if resolved_ip else []),
        }

    # ============================================================
    # SHODAN — tylko IP
    # ============================================================

    def _query_shodan(
        self, ip: str | None, original_query: str
    ) -> dict:
        if ip is None:
            return {
                "found": False,
                "error": f"Nie można rozwiązać domeny {original_query} na IP",
                "code":  "DNS_ERROR",
            }

        result = self.shodan.get_host_info(ip)

        if result["success"]:
            return {
                "found":        True,
                "queried_ip":   ip,
                "organization": result.get("organization"),
                "asn":          result.get("asn"),
                "country":      result.get("country"),
                "city":         result.get("city"),
                "isp":          result.get("isp"),
                "hostnames":    result.get("hostnames", []),
                "domains":      result.get("domains", []),
                "ports":        result.get("ports", []),
                "tags":         result.get("tags", []),
                "vulns":        result.get("vulns", []),
                "certyfikaty":  result.get("certyfikaty", []),
                "bannery_http": result.get("bannery_http", []),
                "os":           result.get("os"),
                "last_update":  result.get("last_update"),
            }

        return {
            "found":      False,
            "queried_ip": ip,
            "error":      result.get("error"),
            "code":       result.get("code"),
        }

    # ============================================================
    # crt.sh
    # ============================================================

    def _query_crtsh(
        self, query: str, resolved_ip: str | None
    ) -> dict:
        is_ip = self._is_ip(query)

        if is_ip:
            result = self.crtsh.get_ip_certs(query)
            if result["success"] and result.get("found"):
                return {
                    "found":       True,
                    "type":        "ip",
                    "domeny":      result.get("domeny", []),
                    "cert_count":  result.get("count", 0),
                    "certyfikaty": result.get("certyfikaty", []),
                }
            return {
                "found": False,
                "type":  "ip",
                "error": result.get("error", "Brak certyfikatów dla tego IP"),
            }

        result = self.crtsh.get_domain_certs(query)
        if result["success"] and result.get("found"):
            return {
                "found":       True,
                "type":        "domain",
                "subdomeny":   result.get("subdomeny", []),
                "cert_count":  result.get("count", 0),
                "certyfikaty": result.get("certyfikaty", []),
                "wystawcy":    result.get("wystawcy", []),
            }
        return {
            "found": False,
            "type":  "domain",
            "error": result.get("error", "Brak certyfikatów dla tej domeny"),
        }

    # ============================================================
    # PODSUMOWANIE
    # ============================================================

    def calculate_risk_level(self, summary, threatfox, virustotal, shodan, crtsh, circl):
        """
        Wieloczynnikowy scoring ryzyka na podstawie wszystkich źródeł TI.
        Zwraca (risk_level, risk_description).
        """
        score = 0
        reasons = []

        # --- ThreatFox (najsilniejszy sygnał) ---
        if threatfox.get("found"):
            iocs = threatfox.get("iocs", [])
            max_confidence = max((i.get("confidence_level", 0) for i in iocs), default=0)
            
            score += 40
            if max_confidence == 100:
                score += 15
            
            malware = summary.get("malware_families", [])
            if malware:
                reasons.append(f"ThreatFox: {', '.join(malware)} (pewność: {max_confidence}%)")
            
            threat_types = summary.get("threat_types", [])
            if "payload_delivery" in threat_types:
                score += 10
                reasons.append("aktywna dystrybucja payloadu")
            if "c2" in threat_types or "botnet_cc" in threat_types:
                score += 20
                reasons.append("C2/botnet")

        # --- VirusTotal ---
        if virustotal.get("found"):
            vt_malicious = virustotal.get("malicious", 0)
            vt_suspicious = virustotal.get("suspicious", 0)
            vt_reputation = virustotal.get("reputation", 0)
            vt_total = virustotal.get("total_engines", 1)

            detection_ratio = (vt_malicious + vt_suspicious) / vt_total if vt_total > 0 else 0

            if vt_malicious >= 10:
                score += 25
            elif vt_malicious >= 5:
                score += 15
            elif vt_malicious >= 1:
                score += 8

            if vt_suspicious >= 3:
                score += 5

            if vt_reputation < -10:
                score += 10
            elif vt_reputation < 0:
                score += 5

            if vt_malicious > 0 or vt_suspicious > 0:
                reasons.append(f"VirusTotal: {vt_malicious} malicious, {vt_suspicious} suspicious / {vt_total} silników")

        # --- CIRCL (powiązania z kampaniami APT) ---
        if circl.get("found"):
            events_count = circl.get("events_count", 0)
            score += 20
            if events_count > 3:
                score += 10
            reasons.append(f"CIRCL: {events_count} powiązanych zdarzeń APT")

        # --- Shodan (ekspozycja infrastruktury) ---
        if shodan and shodan.get("found"):
            open_ports = shodan.get("open_ports", [])
            vulns = shodan.get("vulns", [])
            score += 10
            if vulns:
                score += 15
                reasons.append(f"Shodan: {len(open_ports)} portów, {len(vulns)} CVE")
            else:
                reasons.append(f"Shodan: ekspozycja infrastruktury ({len(open_ports)} portów)")

        # --- Certyfikaty (rekonesans / phishing infra) ---
        cert_count = summary.get("cert_count", 0)
        if crtsh and crtsh.get("found") and cert_count > 0:
            score += 5
            if cert_count > 10:
                score += 5
                reasons.append(f"crt.sh: {cert_count} certyfikatów (rozbudowana infrastruktura)")
            else:
                reasons.append(f"crt.sh: {cert_count} certyfikatów")

        # --- Mapowanie score → poziom ---
        if score >= 80:
            risk_level = "CRITICAL"
        elif score >= 55:
            risk_level = "HIGH"
        elif score >= 30:
            risk_level = "MEDIUM"
        elif score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "UNKNOWN"

        # --- Opis ---
        total_sources = summary.get("total_sources", 0)

        if not reasons:
            risk_desc = "Nie znaleziono w żadnym źródle TI"
        else:
            primary = reasons[0]
            if len(reasons) > 1:
                risk_desc = f"{primary} + {len(reasons) - 1} dodatkowych sygnałów (score: {score})"
            else:
                risk_desc = f"{primary} (score: {score})"

        return risk_level, risk_desc
    

    def _build_summary(
        self, query, resolved_ip, threatfox, circl, shodan, crtsh, vt_data=None, abuse_data=None, whois_data=None
    ) -> dict:

        found_tf     = threatfox["found"]
        found_circl  = circl["found"]
        found_shodan = shodan.get("found", False)
        found_crtsh  = crtsh.get("found", False)
        found_vt = vt_data.get("found", False) if vt_data else False
        found_abuse = (abuse_data.get("abuse_score", 0) > 0) \
            if abuse_data and abuse_data.get("success") else False

        malware_families = list({
            ioc.get("malware_printable", "")
            for ioc in threatfox["iocs"]
            if ioc.get("malware_printable")
        })
        threat_types = list({
            ioc.get("threat_type", "")
            for ioc in threatfox["iocs"]
            if ioc.get("threat_type")
        })
        tags = list({
            tag
            for ioc in threatfox["iocs"]
            for tag in (ioc.get("tags") or [])
        })

        risk_level, risk_desc = self.calculate_risk_level(
            {
                "malware_families": malware_families,
                "threat_types": threat_types,
                "cert_count": crtsh.get("cert_count", 0),
                "total_sources": sum([found_tf, found_circl, found_shodan, found_crtsh, found_vt, found_abuse]),
            },
            threatfox,
            vt_data or {},
            shodan,
            crtsh,
            circl,
        )

        shodan_summary = None
        if found_shodan:
            shodan_summary = {
                "queried_ip":   shodan.get("queried_ip"),
                "organization": shodan.get("organization"),
                "asn":          shodan.get("asn"),
                "country":      shodan.get("country"),
                "open_ports":   shodan.get("ports", []),
                "hostnames":    shodan.get("hostnames", []),
                "vulns":        shodan.get("vulns", []),
            }

        return {
            "query":              query,
            "resolved_ip":        resolved_ip,
            "risk_level":         risk_level,
            "risk_description":   risk_desc,
            "found_in_threatfox": found_tf,
            "found_in_circl":     found_circl,
            "found_in_shodan":    found_shodan,
            "found_in_crtsh":     found_crtsh,
            "found_in_crtsh":     found_crtsh,
            "found_in_virustotal":found_vt,       
            "found_in_abuseipdb": found_abuse,    
            "found_in_whois":     whois_data.get("found", False) if whois_data else False, 
            "malware_families":   malware_families,
            "threat_types":       threat_types,
            "tags":               tags,
            "related_campaigns":  [
                e.get("info") for e in circl["events"]
            ],
            "shodan":             shodan_summary,
            "subdomeny":          crtsh.get("subdomeny", []) if found_crtsh else [],
            "cert_count":         crtsh.get("cert_count", 0),
            "total_sources":      sum([
                found_tf, found_circl, found_shodan, found_crtsh, found_vt, found_abuse
            ]),
        }

    # ============================================================
    # PROFIL GRUPY APT
    # ============================================================

    def get_apt_profile(self, name: str) -> dict:
        """Buduje pełny profil grupy APT."""
        aliases    = self._find_aliases(name)
        mitre_data = self._get_mitre_profile(name)

        if mitre_data.get("found"):
            mitre_aliases = [
                a.lower() for a in mitre_data.get("aliasy", [])
            ]
            aliases = list(set(aliases + mitre_aliases))

        tf_data    = self._get_apt_threatfox(aliases)
        circl_data = self._get_apt_circl(aliases)

        if not mitre_data.get("found"):
            return {
                "success":   False,
                "error":     f"Nie znaleziono grupy '{name}' w MITRE ATT&CK",
                "threatfox": tf_data,
                "circl":     circl_data,
            }

        return {
            "success":    True,
            "query_type": "apt_group",
            "name":       mitre_data["name"],
            "mitre":      mitre_data,
            "threatfox":  tf_data,
            "circl":      circl_data,
        }

    def _find_aliases(self, name: str) -> list:
        """Zwraca wszystkie aliasy dla podanej nazwy grupy."""
        name_lower = name.lower().strip()
        for _, aliases in self.ALIASES.items():
            if name_lower in aliases:
                return aliases
        return [name_lower]

    def _get_mitre(self) -> MitreAttackData:
        """Lazy load danych MITRE ATT&CK."""
        if self._mitre is None:
            self._mitre = MitreAttackData(settings.MITRE_ATTACK_FILE)
        return self._mitre

    def _get_mitre_profile(self, name: str) -> dict:
        """Pobiera profil grupy z MITRE ATT&CK."""
        mitre      = self._get_mitre()
        groups     = mitre.get_groups()
        name_lower = name.lower().strip()

        znaleziona = None
        for group in groups:
            group_name = group.get("name", "").lower()
            if name_lower in group_name or group_name in name_lower:
                znaleziona = group
                break
            aliasy = [a.lower() for a in group.get("x_mitre_aliases", [])]
            if any(name_lower in a or a in name_lower for a in aliasy):
                znaleziona = group
                break

        if not znaleziona:
            return {"found": False}

        group_id     = znaleziona["id"]
        techniki_raw = mitre.get_techniques_used_by_group(group_id)

        techniki = []
        for entry in techniki_raw:
            tech = entry["object"]
            if tech.get("revoked") or tech.get("x_mitre_deprecated"):
                continue
            taktyki = [
                p["phase_name"]
                for p in tech.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            opis = tech.get("description", "")
            techniki.append({
                "id":      self._get_attack_id(tech),
                "name":    tech.get("name", ""),
                "taktyki": taktyki,
                "opis":    opis[:300] + "..." if len(opis) > 300 else opis,
            })

        software_raw = mitre.get_software_used_by_group(group_id)
        software = [
            {"name": s["object"].get("name", ""),
             "type": s["object"].get("type", "")}
            for s in software_raw
            if not s["object"].get("revoked")
        ]

        wszystkie_taktyki = list({
            t for tech in techniki for t in tech["taktyki"]
        })
        attack_id = self._get_attack_id(znaleziona)

        return {
            "found":          True,
            "name":           znaleziona.get("name", ""),
            "attack_id":      attack_id,
            "url":            f"https://attack.mitre.org/groups/{attack_id}/",
            "opis":           znaleziona.get("description", ""),
            "aliasy":         znaleziona.get("x_mitre_aliases", []),
            "taktyki":        sorted(wszystkie_taktyki),
            "techniki":       techniki,
            "techniki_count": len(techniki),
            "software":       software,
            "software_count": len(software),
        }

    def _get_attack_id(self, obj) -> str:
        """Wyciąga ATT&CK ID z obiektu STIX."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id", "")
        return ""

    def _get_apt_threatfox(self, aliases: list) -> dict:
        """Szuka IOC w ThreatFox dla wszystkich aliasów grupy."""
        wszystkie_ioc = []
        widziane      = set()

        for alias in aliases:
            result = self.threatfox.search_ioc(alias)
            if result.get("success"):
                for ioc in result.get("iocs", []):
                    klucz = ioc.get("ioc", "")
                    if klucz not in widziane:
                        widziane.add(klucz)
                        wszystkie_ioc.append(ioc)

        return {
            "found": len(wszystkie_ioc) > 0,
            "count": len(wszystkie_ioc),
            "iocs":  wszystkie_ioc,
        }

    def _get_apt_circl(self, aliases: list) -> dict:
        """Szuka eventów CIRCL dla wszystkich aliasów grupy."""
        matched_events = []
        widziane_uuid  = set()

        conn = sqlite3.connect("cache.db")
        try:
            rows = conn.execute(
                "SELECT uuid, info, date, org FROM circl_manifest"
            ).fetchall()
        except Exception:
            conn.close()
            return {"found": False, "count": 0, "events": []}
        conn.close()

        for uuid, info, date, org in rows:
            info_lower = (info or "").lower()
            for alias in aliases:
                if alias in info_lower and uuid not in widziane_uuid:
                    widziane_uuid.add(uuid)
                    matched_events.append({
                        "uuid": uuid,
                        "info": info,
                        "date": date,
                        "org":  org,
                    })
                    break

        return {
            "found":  len(matched_events) > 0,
            "count":  len(matched_events),
            "events": matched_events,
        }