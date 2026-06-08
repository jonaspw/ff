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

    # Słownik aliasów
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

    def _is_ip(self, value: str, weights=None) -> bool:
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

    def analyze(self, query: str, weights=None) -> dict:
        is_ip       = self._is_ip(query)
        resolved_ip = None

        if not is_ip:
            resolved_ip = self._resolve_domain(query)

        ip_for_shodan = query if is_ip else resolved_ip

        # ThreatFox
        tf_data = self._query_threatfox(query, resolved_ip)

        # CIRCL
        circl_data = self._query_circl(query, resolved_ip)

        # Shodan
        shodan_data = self._query_shodan(ip_for_shodan, query)

        # crt.sh
        crtsh_data = self._query_crtsh(query, ip_for_shodan)

        # WHOIS
        whois_data = self.whois.lookup(query)

        # AbuseIPDB
        abuse_data = None
        ip_for_abuse = query if is_ip else resolved_ip
        if ip_for_abuse:
            abuse_data = self.abuseipdb.check_ip(ip_for_abuse)
            if abuse_data.get("success"):
                abuse_data["queried_ip"] = ip_for_abuse
                if not is_ip:
                    abuse_data["resolved_from"] = query

        # VirusTotal
        vt_data = self.virustotal.lookup(query)

        summary = self._build_summary(
            query, resolved_ip, tf_data, circl_data,
            shodan_data, crtsh_data, vt_data, abuse_data,
            whois_data, weights=weights
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
        # Zapytanie domenowe
        if not self._is_ip(original_query) and ip is None:
            return {
                "found": False,
                "error": f"Nie można rozwiązać domeny {original_query} na IP",
                "code":  "DNS_ERROR",
            }

        # Dane hosta po IP
        if ip is None:
            return {
                "found": False,
                "error": f"Brak IP dla {original_query}",
                "code":  "DNS_ERROR",
            }

        result = self.shodan.get_host_info(ip)

        if result["success"]:
            shodan_data = {
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

            # Jeśli zapytanie było domeną dołącz też dane DNS
            if not self._is_ip(original_query):
                dns_result = self.shodan.get_domain_info(original_query)
                if dns_result["success"]:
                    shodan_data["dns"] = {
                        "subdomeny":       dns_result.get("subdomeny", []),
                        "subdomeny_count": dns_result.get("subdomeny_count", 0),
                        "ip_adresy":       dns_result.get("ip_adresy", []),
                        "rekordy":         dns_result.get("rekordy", {}),
                    }

            return shodan_data

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

    def calculate_risk_level(self, summary, threatfox, virustotal,
                              shodan, crtsh, circl, abuse_data=None, weights=None):
        score   = 0
        reasons = []
        # Domyślne wagi — każde źródło ma równy udział
        default_weights = {
            "virustotal": 20,
            "abuseipdb":  20,
            "threatfox":  20,
            "circl":      20,
            "shodan":     20,
        }
        w = weights if weights else default_weights

        # Źródła aktywne — te które mają wagę > 0
        active_weights = {k: v for k, v in w.items() if v > 0}
        total_weight   = sum(active_weights.values()) or 1

        def scale(source_id, raw_score):
            """
            Skaluje raw_score (0-20) proporcjonalnie do wagi źródła.
            Wynik zawsze w skali 0-20 niezależnie od wagi.
            Źródła z wagą 0 są pomijane.
            """
            if w.get(source_id, 0) == 0:
                return 0
            # raw_score jest już w skali 0-20
            # waga wpływa na udział w max_score, nie na wartość
            return raw_score

        # ── VirusTotal (max 20 pkt) ────────────────────────────
        if virustotal and virustotal.get("success"):
            vt_score      = 0
            vt_malicious  = virustotal.get("malicious", 0)
            vt_suspicious = virustotal.get("suspicious", 0)
            vt_reputation = virustotal.get("reputation", 0)
            vt_total      = virustotal.get("total_engines", 1)
            vt_categories = virustotal.get("categories", {})

            detection_ratio = (vt_malicious + vt_suspicious) / vt_total \
                              if vt_total > 0 else 0

            # Liczba silników malicious (0–12 pkt)
            if vt_malicious >= 12:
                vt_score += 12
            elif vt_malicious >= 7:
                vt_score += 10
            elif vt_malicious >= 5:
                vt_score += 8
            elif vt_malicious >= 3:
                vt_score += 6
            elif vt_malicious >= 1:
                vt_score += 4

            # Liczba silników suspicious (0–3 pkt)
            if vt_suspicious >= 3:
                vt_score += 3
            elif vt_suspicious >= 2:
                vt_score += 2
            elif vt_suspicious >= 1:
                vt_score += 1

            # Detection ratio (0–3 pkt)
            if detection_ratio >= 0.3:
                vt_score += 3
            elif detection_ratio >= 0.15:
                vt_score += 2
            elif detection_ratio >= 0.05:
                vt_score += 1

            # Reputacja VT (0–2 pkt)
            if vt_reputation <= -20:
                vt_score += 2
            elif vt_reputation < 0:
                vt_score += 1

            # Kategoria malicious (0–1 pkt)
            malicious_cats = [
                v for v in vt_categories.values()
                if any(k in v.lower() for k in
                       ["malicious", "phishing", "malware"])
            ]
            if malicious_cats:
                vt_score = min(vt_score + 1, 20)

            vt_score = min(vt_score, 20)

            if w.get("virustotal", 0) > 0:
                score += vt_score
                reasons.append(
                    f"VirusTotal: {vt_malicious} malicious, "
                    f"{vt_suspicious} suspicious / {vt_total} engines "
                    f"({detection_ratio:.0%} detect) [{vt_score}/20 pkt]"
                )


        # ── AbuseIPDB (max 20 pkt) ─────────────────────────────
        # Bazuje na: abuse_score, total_reports, distinct_users, kategorie
        if abuse_data and abuse_data.get("success"):
            print(f"[DEBUG ABUSE] abuse_data={abuse_data}")
            ab_score       = 0
            abuse_score    = abuse_data.get("abuse_score", 0)
            total_reports  = abuse_data.get("total_reports", 0)
            distinct_users = abuse_data.get("distinct_users", 0)
            categories     = abuse_data.get("categories", [])

            # Abuse score 0-100 → 0-12 pkt
            if abuse_score > 75:
                ab_score += 12
            elif abuse_score > 50:
                ab_score += 9
            elif abuse_score > 25:
                ab_score += 6
            elif abuse_score > 10:
                ab_score += 3
            elif abuse_score > 0:
                ab_score += 1

            # Liczba unikalnych zgłaszających (0–5 pkt)
            if distinct_users >= 50:
                ab_score += 5
            elif distinct_users >= 20:
                ab_score += 4
            elif distinct_users >= 10:
                ab_score += 3
            elif distinct_users >= 5:
                ab_score += 2
            elif distinct_users >= 1:
                ab_score += 1

            # Groźne kategorie (0–3 pkt)
            high_risk = {"Hacking", "Exploited Host",
                         "Web App Attack", "DDoS Attack"}
            matched = high_risk & set(categories)
            if len(matched) >= 3:
                ab_score += 3
            elif len(matched) >= 2:
                ab_score += 2
            elif len(matched) >= 1:
                ab_score += 1

            ab_score = min(ab_score, 20)
            print(f"[DEBUG ABUSE SCORE] ab_score={ab_score} score_przed={score}")

            ab_score = min(ab_score, 20)

            if w.get("abuseipdb", 0) > 0:
                score += ab_score
                reasons.append(
                    f"AbuseIPDB: score {abuse_score}/100 "
                    f"({distinct_users} reporters) [{ab_score}/20 pkt]"
                )

        # ── ThreatFox (max 20 pkt) ─────────────────────────────
        # Bazuje na: confidence_level, threat_type
        if threatfox.get("found"):
            tf_score       = 0
            iocs           = threatfox.get("iocs", [])
            max_confidence = max(
                (i.get("confidence_level", 0) for i in iocs), default=0
            )
            threat_types = summary.get("threat_types", [])
            malware      = summary.get("malware_families", [])

            # Confidence level → 0-14 pkt
            if max_confidence == 100:
                tf_score += 14
            elif max_confidence >= 75:
                tf_score += 10
            elif max_confidence >= 50:
                tf_score += 7
            else:
                tf_score += 4

            # Typ zagrożenia (0–6 pkt)
            if "c2" in threat_types or "botnet_cc" in threat_types:
                tf_score += 6
            elif "payload_delivery" in threat_types:
                tf_score += 4
            elif threat_types:
                tf_score += 2

            tf_score = min(tf_score, 20)

            label = ', '.join(malware) if malware else "IOC"

            if w.get("threatfox", 0) > 0:
                score += tf_score
                if "c2" in threat_types or "botnet_cc" in threat_types:
                    reasons.append(
                        f"ThreatFox: C2/botnet — {label} "
                        f"(confidence: {max_confidence}%) [{tf_score}/20 pkt]"
                    )
                else:
                    reasons.append(
                        f"ThreatFox: {label} "
                        f"(confidence: {max_confidence}%) [{tf_score}/20 pkt]"
                    )

        # ── CIRCL (max 20 pkt) ─────────────────────────────────
        # Bazuje na: events_count, tagi MISP threat-level i kill-chain
        if circl.get("found"):
            ci_score     = 0
            events_count = circl.get("events_count", 0)
            iocs         = circl.get("iocs", [])

            # Liczba eventów (0–12 pkt)
            if events_count >= 10:
                ci_score += 12
            elif events_count >= 5:
                ci_score += 9
            elif events_count >= 3:
                ci_score += 6
            elif events_count >= 1:
                ci_score += 4

            # Tagi MISP threat-level (0–5 pkt)
            all_tags = [
                tag for ioc in iocs
                for tag in (ioc.get("tags") or [])
            ]
            if any("high-risk" in t.lower() for t in all_tags):
                ci_score += 5
            elif any("medium-risk" in t.lower() for t in all_tags):
                ci_score += 3
            elif any("low-risk" in t.lower() for t in all_tags):
                ci_score += 1

            # Tag kill-chain (0–3 pkt)
            if any("kill-chain" in t.lower() for t in all_tags):
                ci_score += 3

            ci_score = min(ci_score, 20)

            if w.get("circl", 0) > 0:
                score += ci_score
                reasons.append(
                    f"CIRCL: {events_count} APT events [{ci_score}/20 pkt]"
                )

        # ── Shodan (max 20 pkt) ────────────────────────────────
        if shodan and shodan.get("found"):
            sh_score   = 0
            open_ports = shodan.get("open_ports") or shodan.get("ports", [])
            vulns      = shodan.get("vulns", [])
            tags       = shodan.get("tags", [])
            bannery    = shodan.get("bannery_http", [])

            # Znane bezpieczne infrastruktury — nie dodają punktów
            safe_tags = {"cdn", "cloud", "hosting", "isp"}
            if safe_tags & {t.lower() for t in tags}:
                # Jeśli jedyne tagi to cdn/cloud/hosting
                # i nie ma CVE ani podejrzanych bannerów
                # — Shodan jest tylko źródłem informacyjnym
                pass

            # CVE — jedyny silny sygnał z Shodan (0–15 pkt)
            if len(vulns) >= 5:
                sh_score += 15
            elif len(vulns) >= 3:
                sh_score += 11
            elif len(vulns) >= 1:
                sh_score += 7

            # Podejrzane tagi — złośliwa infrastruktura (0–8 pkt)
            malicious_tags = {
                "tor", "vpn", "proxy", "compromised",
                "malware", "botnet"
            }
            matched_malicious = malicious_tags & {t.lower() for t in tags}
            if matched_malicious:
                sh_score += 8

            # Bannery HTTP wskazujące na złośliwą infrastrukturę (0–5 pkt)
            podejrzane_tytuly = [
                "tor exit", "exit router", "anonymizer",
                "i2p", "darknet", "this is a tor",
            ]
            for banner in bannery:
                title = (banner.get("title") or "").lower()
                if any(s in title for s in podejrzane_tytuly):
                    sh_score += 5
                    break

            # Porty C2 — tylko te naprawdę podejrzane (0–4 pkt)
            # Usuwamy 8080 i 8443 bo są używane przez CDN
            c2_ports = {4444, 4445, 1337, 31337,
                        6666, 6667, 9001, 9030}
            if c2_ports & set(open_ports):
                sh_score += 4

            sh_score = min(sh_score, 20)

            opis_czesci = []
            if vulns:
                opis_czesci.append(f"{len(vulns)} CVE")
            if matched_malicious:
                opis_czesci.append(
                    f"tagi: {', '.join(matched_malicious)}"
                )
            if not opis_czesci:
                opis_czesci.append(f"{len(open_ports)} ports")

            if w.get("shodan", 0) > 0:
                score += sh_score
                reasons.append(
                    f"Shodan: {', '.join(opis_czesci)} [{sh_score}/20 pkt]"
                )

        # ── Mapowanie score → poziom ──────────────────────────
        # Policz aktywne źródła — tylko te z wagą > 0 które zwróciły dane
        active_sources = 0
        if virustotal and virustotal.get("success") and w.get("virustotal", 0) > 0:
            active_sources += 1
        if abuse_data and abuse_data.get("success") and w.get("abuseipdb", 0) > 0:
            active_sources += 1
        if threatfox.get("found") and w.get("threatfox", 0) > 0:
            active_sources += 1
        if circl.get("found") and w.get("circl", 0) > 0:
            active_sources += 1
        if shodan and shodan.get("found") and w.get("shodan", 0) > 0:
            active_sources += 1

        # Max score
        max_score = 0
        if virustotal and virustotal.get("success") and w.get("virustotal", 0) > 0:
            max_score += 20
        if abuse_data and abuse_data.get("success") and w.get("abuseipdb", 0) > 0:
            max_score += 20
        if threatfox.get("found") and w.get("threatfox", 0) > 0:
            max_score += 20
        if circl.get("found") and w.get("circl", 0) > 0:
            max_score += 20
        if shodan and shodan.get("found") and w.get("shodan", 0) > 0:
            max_score += 20

        print(f"[DEBUG FINAL] score={score} max_score={max_score} w={w}")
        ratio = score / max_score if max_score > 0 else 0

        if ratio >= 0.75:
            risk_level = "CRITICAL"
        elif ratio >= 0.50:
            risk_level = "HIGH"
        elif ratio >= 0.25:
            risk_level = "MEDIUM"
        elif ratio >= 0:
            risk_level = "LOW"
        else:
            risk_level = "UNKNOWN"

        # ── Opis ──────────────────────────────────────────────
        if not reasons:
            risk_desc = "Nie znaleziono w żadnym źródle TI"
        elif len(reasons) == 1:
            risk_desc = f"{reasons[0]} (score: {score}/{max_score}, {ratio:.0%})"
        else:
            wszystkie = " | ".join(reasons)
            risk_desc = f"{wszystkie} (score: {score}/{max_score}, {ratio:.0%})"

        return risk_level, risk_desc


    def _build_summary(
        self, query, resolved_ip, threatfox, circl,
        shodan, crtsh, vt_data=None, abuse_data=None,
        whois_data=None, weights=None
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
            abuse_data,
            weights,
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
                "error":     f"Group '{name}' not found in MITRE ATT&CK",
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