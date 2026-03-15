import ipaddress
import socket
import sqlite3
import json

from threatfox.services import ThreatFoxService
from circl.services import CIRCLFeedService
from shodanapp.services import ShodanService
from crtsh.services import CrtShService


class AnalyzerService:

    def __init__(self):
        self.threatfox = ThreatFoxService()
        self.circl     = CIRCLFeedService()
        self.shodan    = ShodanService()
        self.crtsh     = CrtShService()

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
        """
        Rozwiązuje domenę na IP przez DNS.
        Zwraca IP jako string lub None jeśli się nie uda.
        """
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    # ============================================================
    # GŁÓWNA METODA
    # ============================================================

    def analyze(self, query: str) -> dict:
        """
        Analizuje podany IP lub domenę.

        Jeśli domena — najpierw rozwiązuje na IP,
        następnie odpytuje wszystkie źródła zarówno
        dla domeny jak i dla rozwiązanego IP.
        """
        is_ip       = self._is_ip(query)
        resolved_ip = None

        # Jeśli domena — rozwiąż na IP
        if not is_ip:
            resolved_ip = self._resolve_domain(query)

        # IP które trafi do Shodan
        ip_for_shodan = query if is_ip else resolved_ip

        # ── ThreatFox ─────────────────────────────────────────
        # Szukamy zarówno po domenie jak i po rozwiązanym IP
        tf_data = self._query_threatfox(query, resolved_ip)

        # ── CIRCL ─────────────────────────────────────────────
        # Szukamy zarówno po domenie jak i po rozwiązanym IP
        circl_data = self._query_circl(query, resolved_ip)

        # ── Shodan ────────────────────────────────────────────
        # Zawsze odpytujemy po IP (nawet jeśli user podał domenę)
        shodan_data = self._query_shodan(ip_for_shodan, query)

        # ── crt.sh ────────────────────────────────────────────
        crtsh_data = self._query_crtsh(query, ip_for_shodan)

        # ── Podsumowanie ───────────────────────────────────────
        summary = self._build_summary(
            query, resolved_ip, tf_data, circl_data, shodan_data, crtsh_data
        )

        return {
            "success":      True,
            "query":        query,
            "query_type":   "ip" if is_ip else "domain",
            "resolved_ip":  resolved_ip,
            "summary":      summary,
            "threatfox":    tf_data,
            "circl":        circl_data,
            "shodan":       shodan_data,
            "crtsh":        crtsh_data, 
        }

    # ============================================================
    # THREATFOX
    # ============================================================

    def _query_threatfox(
        self, query: str, resolved_ip: str | None
    ) -> dict:
        """
        Szuka w ThreatFox po oryginalnym zapytaniu
        i dodatkowo po rozwiązanym IP (jeśli jest).
        Łączy wyniki bez duplikatów.
        """
        wszystkie_ioc = []
        widziane      = set()

        def dodaj_ioc(ioc_lista):
            for ioc in ioc_lista:
                klucz = ioc.get("ioc", "")
                if klucz not in widziane:
                    widziane.add(klucz)
                    wszystkie_ioc.append(ioc)

        # Szukaj po oryginalnym zapytaniu (domena lub IP)
        result1 = self.threatfox.search_ioc(query)
        if result1.get("success"):
            dodaj_ioc(result1.get("iocs", []))

        # Jeśli domena — szukaj też po rozwiązanym IP
        if resolved_ip:
            result2 = self.threatfox.search_ioc(resolved_ip)
            if result2.get("success"):
                dodaj_ioc(result2.get("iocs", []))

        found = len(wszystkie_ioc) > 0

        return {
            "found":          found,
            "count":          len(wszystkie_ioc),
            "iocs":           wszystkie_ioc,
            "searched_for":   [query] + ([resolved_ip] if resolved_ip else []),
        }

    # ============================================================
    # CIRCL
    # ============================================================

    def _query_circl(
        self, query: str, resolved_ip: str | None
    ) -> dict:
        """
        Szuka w lokalnej bazie CIRCL po oryginalnym zapytaniu
        i dodatkowo po rozwiązanym IP.
        """
        matched_iocs   = []
        matched_events = []
        widziane_uuid  = set()

        def szukaj(szukana_fraza: str):
            conn = sqlite3.connect("cache.db")
            try:
                rows = conn.execute(
                    "SELECT uuid, data FROM circl_events"
                ).fetchall()
            except Exception:
                conn.close()
                return
            conn.close()

            fraza_lower = szukana_fraza.lower()

            for uuid, data_json in rows:
                event = json.loads(data_json)
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

        # Szukaj po oryginalnym zapytaniu
        szukaj(query)

        # Jeśli domena — szukaj też po rozwiązanym IP
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
    # SHODAN
    # ============================================================

    def _query_shodan(
        self, ip: str | None, original_query: str
    ) -> dict:
        """
        Odpytuje Shodan po IP.
        Jeśli IP jest None (nie udało się rozwiązać DNS) —
        zwraca informację o błędzie.
        """
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
        else:
            return {
                "found":      False,
                "queried_ip": ip,
                "error":      result.get("error"),
                "code":       result.get("code"),
            }


    def _query_crtsh(
        self, query: str, resolved_ip: str | None
    ) -> dict:
        """
        Odpytuje crt.sh po domenie lub IP.
        Dla domeny — subdomeny i certyfikaty.
        Dla IP — domeny hostowane na tym IP.
        """
        is_ip = self._is_ip(query)

        if is_ip:
            result = self.crtsh.get_ip_certs(query)
            if result["success"] and result.get("found"):
                return {
                    "found":        True,
                    "type":         "ip",
                    "domeny":       result.get("domeny", []),
                    "cert_count":   result.get("count", 0),
                    "certyfikaty":  result.get("certyfikaty", []),
                }
            return {
                "found": False,
                "type":  "ip",
                "error": result.get("error", "Brak certyfikatów dla tego IP"),
            }
        else:
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

    def _build_summary(
        self, query, resolved_ip, threatfox, circl, shodan, crtsh
    ) -> dict:

        found_tf     = threatfox["found"]
        found_circl  = circl["found"]
        found_shodan = shodan.get("found", False)

        # Dane z ThreatFox
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

        # Poziom zagrożenia
        if found_tf and found_circl:
            risk_level = "CRITICAL"
            risk_desc  = "Potwierdzone zagrożenie — w ThreatFox i CIRCL"
        elif found_tf:
            risk_level = "HIGH"
            risk_desc  = "Aktywne zagrożenie — znaleziono w ThreatFox"
        elif found_circl:
            risk_level = "MEDIUM"
            risk_desc  = "Powiązanie z kampanią APT — znaleziono w CIRCL"
        elif found_shodan:
            risk_level = "LOW"
            risk_desc  = "Brak w bazach TI — dane infrastruktury z Shodan"
        else:
            risk_level = "UNKNOWN"
            risk_desc  = "Nie znaleziono w żadnym źródle"

        # Dane infrastruktury z Shodan
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
            "malware_families":   malware_families,
            "threat_types":       threat_types,
            "tags":               tags,
            "related_campaigns":  [
                e.get("info") for e in circl["events"]
            ],
            "shodan":             shodan_summary,
            "total_sources":      sum([
                found_tf, found_circl, found_shodan
            ]),
            "subdomeny":          crtsh.get("subdomeny", []) if crtsh.get("found") else [],
            "cert_count":         crtsh.get("cert_count", 0),
        }