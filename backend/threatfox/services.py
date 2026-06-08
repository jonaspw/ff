import requests
from django.conf import settings


class ThreatFoxService:
    """
    Klasa obsługująca komunikację z ThreatFox API.
    """

    def __init__(self):
        self.api_url = settings.THREATFOX_API_URL
        self.headers = {
            "Auth-Key":     settings.THREATFOX_API_KEY,
            "Content-Type": "application/json",
        }

    def _post(self, payload: dict) -> dict:
        """
        Prywatna metoda — wysyła zapytanie POST do API.
        Obsługuje błędy sieciowe.
        """
        try:
            response = requests.post(
                self.api_url,
                headers=self.headers,
                json=payload,
                timeout=30,
            )
            response.raise_for_status()
            return {"success": True, "data": response.json()}

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error":   "Timeout — ThreatFox API not responding"
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "error":   "No internet connection"
            }
        except requests.exceptions.HTTPError as e:
            return {
                "success": False,
                "error":   f"Błąd HTTP: {str(e)}"
            }

    def get_recent_iocs(self, days: int = 1) -> dict:
        """
        Pobiera najnowsze IOC z ostatnich X dni.
        Endpoint: get_iocs
        """
        result = self._post({
            "query": "get_iocs",
            "days":  days,
        })

        if not result["success"]:
            return result

        data = result["data"]

        if data.get("query_status") == "ok":
            return {
                "success": True,
                "count":   len(data.get("data", [])),
                "iocs":    data.get("data", []),
            }

        return {
            "success": False,
            "error":   data.get("query_status", "Unknown API error"),
        }

    def search_ioc(self, search_term: str) -> dict:
        """
        Wyszukuje konkretny IOC (IP, domenę, hash).
        Endpoint: search_ioc
        """
        result = self._post({
            "query":      "search_ioc",
            "search_term": search_term,
        })

        if not result["success"]:
            return result

        data = result["data"]

        if data.get("query_status") == "ok":
            return {
                "success": True,
                "count":   len(data.get("data", [])),
                "iocs":    data.get("data", []),
            }

        return {
            "success": False,
            "error":   data.get("query_status", "Not found"),
        }