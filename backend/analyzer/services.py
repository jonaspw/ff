from threatfox.services import ThreatFoxService
from circl.services import CIRCLFeedService
from shodanapp.services import ShodanService
import ipaddress


class AnalyzerService:
    """
    Łączy wyniki z ThreatFox, CIRCL i Shodan
    w jeden zagregowany raport.
    """

    def __init__(self):
        self.threatfox = ThreatFoxService()
        self.circl     = CIRCLFeedService()
        self.shodan    = ShodanService()

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def analyze(self, query: str) -> dict:
        """
        Główna metoda analizy.
        Dla IP: odpytuje ThreatFox + CIRCL + Shodan
        Dla domeny: odpytuje ThreatFox + CIRCL
        """

        # ── ThreatFox ─────────────────────────────────────────
        tf_result = self.threatfox.search_ioc(query)
        threatfox_data = {
            "found":  tf_result.get("success") and
                      tf_result.get("count", 0) > 0,
            "count":  tf_result.get("count", 0),
            "iocs":   tf_result.get("iocs", []),
            "error":  tf_result.get("error")
                      if not tf_result.get("success") else None,
        }

        # ── CIRCL ─────────────────────────────────────────────
        circl_ioc_result = self._search_circl_iocs(query)
        circl_data = {
            "found":        circl_ioc_result["found"],
            "events_count": circl_ioc_result["events_count"],
            "iocs":         circl_ioc_result["iocs"],
            "events":       circl_ioc_result["events"],
        }

        # ── Shodan — tylko dla IP ──────────────────────────────
        shodan_data = None
        if self._is_ip(query):
            shodan_result = self.shodan.get_host_info(query)
            if shodan_result["success"]:
                shodan_data = {
                    "found":        True,
                    "organization": shodan_result.get("organization"),
                    "asn":          shodan_result.get("asn"),
                    "country":      shodan_result.get("country"),
                    "city":         shodan_result.get("city"),
                    "isp":          shodan_result.get("isp"),
                    "hostnames":    shodan_result.get("hostnames", []),
                    "domains":      shodan_result.get("domains", []),
                    "ports":        shodan_result.get("ports", []),
                    "tags":         shodan_result.get("tags", []),
                    "vulns":        shodan_result.get("vulns", []),
                    "certyfikaty":  shodan_result.get("certyfikaty", []),
                    "bannery_http": shodan_result.get("bannery_http", []),
                    "os":           shodan_result.get("os"),
                    "last_update":  shodan_result.get("last_update"),
                }
            else:
                shodan_data = {
                    "found": False,
                    "error": shodan_result.get("error"),
                }

        # ── Podsumowanie ───────────────────────────────────────
        summary = self._build_summary(
            query, threatfox_data, circl_data, shodan_data
        )

        return {
            "success":   True,
            "query":     query,
            "query_type": "ip" if self._is_ip(query) else "domain",
            "summary":   summary,
            "threatfox": threatfox_data,
            "circl":     circl_data,
            "shodan":    shodan_data,
        }

    def _search_circl_iocs(self, query: str) -> dict:
        import sqlite3, json
        conn = sqlite3.connect("cache.db")
        try:
            rows = conn.execute(
                "SELECT uuid, data FROM circl_events"
            ).fetchall()
        except Exception:
            conn.close()
            return {
                "found": False, "events_count": 0,
                "iocs": [], "events": []
            }
        conn.close()

        matched_iocs   = []
        matched_events = []
        query_lower    = query.lower()

        for uuid, data_json in rows:
            event = json.loads(data_json)
            pasujace = [
                ioc for ioc in event.get("iocs", [])
                if query_lower in ioc.get("value", "").lower()
            ]
            if pasujace:
                matched_iocs.extend(pasujace)
                matched_events.append({
                    "event_id": uuid,
                    "info":     event.get("info", ""),
                    "date":     event.get("date", ""),
                    "matched":  len(pasujace),
                })

        return {
            "found":        len(matched_iocs) > 0,
            "events_count": len(matched_events),
            "iocs":         matched_iocs,
            "events":       matched_events,
        }

    def _build_summary(
        self, query, threatfox, circl, shodan
    ) -> dict:

        found_tf     = threatfox["found"]
        found_circl  = circl["found"]
        found_shodan = shodan is not None and shodan.get("found")

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
            risk_desc  = "Aktywne zagrożenie — w ThreatFox"
        elif found_circl:
            risk_level = "MEDIUM"
            risk_desc  = "Powiązanie z kampanią APT — w CIRCL"
        else:
            risk_level = "UNKNOWN"
            risk_desc  = "Nie znaleziono w bazach TI"

        # Dane z Shodan
        shodan_summary = None
        if found_shodan:
            shodan_summary = {
                "organization": shodan.get("organization"),
                "asn":          shodan.get("asn"),
                "country":      shodan.get("country"),
                "open_ports":   shodan.get("ports", []),
                "hostnames":    shodan.get("hostnames", []),
                "vulns":        shodan.get("vulns", []),
            }

        return {
            "query":              query,
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
            "total_sources":      sum([found_tf, found_circl,
                                       found_shodan or False]),
        }