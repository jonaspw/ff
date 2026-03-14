from threatfox.services import ThreatFoxService
from circl.services import CIRCLFeedService


class AnalyzerService:
    """
    Główny serwis aplikacji — łączy wyniki z ThreatFox i CIRCL
    w jeden zagregowany raport dla podanego IP lub domeny.
    """

    def __init__(self):
        self.threatfox = ThreatFoxService()
        self.circl     = CIRCLFeedService()

    def analyze(self, query: str) -> dict:
        """
        Główna metoda — odpytuje oba źródła i łączy wyniki.

        query: adres IP lub domena podana przez użytkownika
        """

        # ── 1. ThreatFox ──────────────────────────────────────
        tf_result = self.threatfox.search_ioc(query)

        threatfox_data = {
            "found":  tf_result.get("success") and tf_result.get("count", 0) > 0,
            "count":  tf_result.get("count", 0),
            "iocs":   tf_result.get("iocs", []),
            "error":  tf_result.get("error") if not tf_result.get("success") else None,
        }

        # ── 2. CIRCL — szukaj w lokalnej bazie ────────────────
        circl_result = self.circl.search_by_actor(query)

        # search_by_actor szuka po nazwie w polu info eventu
        # dla IP/domeny szukamy inaczej — w eventach już pobranych
        circl_ioc_result = self._search_circl_iocs(query)

        circl_data = {
            "found":        circl_ioc_result["found"],
            "events_count": circl_ioc_result["events_count"],
            "iocs":         circl_ioc_result["iocs"],
            "events":       circl_ioc_result["events"],
        }

        # ── 3. Zagregowane podsumowanie ───────────────────────
        summary = self._build_summary(query, threatfox_data, circl_data)

        return {
            "success":   True,
            "query":     query,
            "summary":   summary,
            "threatfox": threatfox_data,
            "circl":     circl_data,
        }

    def _search_circl_iocs(self, query: str) -> dict:
        """
        Szuka podanego IP lub domeny w pobranych eventach CIRCL.
        Przeszukuje lokalną bazę SQLite — zero HTTP.
        """
        import sqlite3

        conn = sqlite3.connect("cache.db")

        # Sprawdź czy tabela eventów istnieje i ma dane
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
            import json
            event = json.loads(data_json)

            # Szukaj query w wartościach IOC tego eventu
            pasujace_ioc = [
                ioc for ioc in event.get("iocs", [])
                if query_lower in ioc.get("value", "").lower()
            ]

            if pasujace_ioc:
                matched_iocs.extend(pasujace_ioc)
                matched_events.append({
                    "event_id": uuid,
                    "info":     event.get("info", ""),
                    "date":     event.get("date", ""),
                    "matched":  len(pasujace_ioc),
                })

        return {
            "found":        len(matched_iocs) > 0,
            "events_count": len(matched_events),
            "iocs":         matched_iocs,
            "events":       matched_events,
        }

    def _build_summary(
        self, query: str,
        threatfox: dict,
        circl: dict
    ) -> dict:
        """
        Buduje czytelne podsumowanie dla użytkownika.
        Określa poziom zagrożenia na podstawie danych z obu źródeł.
        """
        found_in_threatfox = threatfox["found"]
        found_in_circl     = circl["found"]

        # Zbierz wszystkie unikalne tagi i malware z ThreatFox
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

        # Określ poziom zagrożenia
        if found_in_threatfox and found_in_circl:
            risk_level = "CRITICAL"
            risk_desc  = "Znaleziony w ThreatFox i CIRCL — potwierdzone zagrożenie"
        elif found_in_threatfox:
            risk_level = "HIGH"
            risk_desc  = "Znaleziony w ThreatFox — aktywne zagrożenie"
        elif found_in_circl:
            risk_level = "MEDIUM"
            risk_desc  = "Znaleziony w CIRCL — powiązanie z kampanią APT"
        else:
            risk_level = "UNKNOWN"
            risk_desc  = "Nie znaleziono w żadnym źródle"

        # Zbierz powiązane eventy CIRCL (nazwy kampanii)
        related_campaigns = [
            e.get("info", "") for e in circl["events"]
        ]

        return {
            "query":               query,
            "risk_level":          risk_level,
            "risk_description":    risk_desc,
            "found_in_threatfox":  found_in_threatfox,
            "found_in_circl":      found_in_circl,
            "malware_families":    malware_families,
            "threat_types":        threat_types,
            "tags":                tags,
            "related_campaigns":   related_campaigns,
            "total_iocs_found":    threatfox["count"] + circl["events_count"],
        }