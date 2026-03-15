# backend/virustotal/services.py

import requests
import ipaddress
from django.conf import settings


class VirusTotalService:
    """
    Pobiera dane reputacji z VirusTotal API v3.
    Dokumentacja: https://docs.virustotal.com/reference/overview

    Darmowy plan: 500 zapytań dziennie, 4 na minutę.
    Działa dla IP i domen.
    """

    def __init__(self):
        self.api_url = settings.VIRUSTOTAL_API_URL
        self.headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY,
            "Accept":   "application/json",
        }

    def _get(self, endpoint: str) -> dict:
        """Wykonaj GET do VirusTotal API."""
        try:
            response = requests.get(
                f"{self.api_url}{endpoint}",
                headers=self.headers,
                timeout=30,
            )

            if response.status_code == 401:
                return {
                    "success": False,
                    "error":   "Nieprawidłowy klucz API VirusTotal",
                    "code":    "AUTH_ERROR",
                }
            if response.status_code == 404:
                return {
                    "success": False,
                    "error":   "Nie znaleziono w VirusTotal",
                    "code":    "NOT_FOUND",
                }
            if response.status_code == 429:
                return {
                    "success": False,
                    "error":   "Przekroczono limit zapytań VirusTotal (4/min)",
                    "code":    "RATE_LIMIT",
                }

            response.raise_for_status()
            return {"success": True, "data": response.json()}

        except requests.exceptions.Timeout:
            return {"success": False, "error": "Timeout — VirusTotal nie odpowiada"}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Brak połączenia z internetem"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _parse_stats(self, stats: dict) -> dict:
        """Parsuje statystyki wykryć AV."""
        return {
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "clean":       stats.get("undetected", 0),
            "total":       sum(stats.values()),
        }

    def check_ip(self, ip: str) -> dict:
        """
        Sprawdza reputację IP w VirusTotal.
        Zwraca: wyniki AV, historyczne DNS, powiązane domeny.
        """
        result = self._get(f"ip_addresses/{ip}")
        if not result["success"]:
            return result

        attrs = result["data"].get("data", {}).get("attributes", {})
        stats = self._parse_stats(
            attrs.get("last_analysis_stats", {})
        )

        # Historyczne rozwiązania DNS
        dns_result = self._get(f"ip_addresses/{ip}/resolutions")
        dns_records = []
        if dns_result["success"]:
            for item in dns_result["data"].get("data", [])[:10]:
                dns_attrs = item.get("attributes", {})
                dns_records.append({
                    "hostname":  dns_attrs.get("host_name"),
                    "date":      dns_attrs.get("date"),
                })

        return {
            "success":       True,
            "found":         stats["malicious"] > 0 or stats["suspicious"] > 0,
            "type":          "ip",
            "query":         ip,
            "malicious":     stats["malicious"],
            "suspicious":    stats["suspicious"],
            "clean":         stats["clean"],
            "total_engines": stats["total"],
            "reputation":    attrs.get("reputation", 0),
            "country":       attrs.get("country"),
            "asn":           attrs.get("asn"),
            "org":           attrs.get("as_owner"),
            "last_analysis": attrs.get("last_analysis_date"),
            "dns_records":   dns_records,
            "tags":          attrs.get("tags", []),
        }

    def check_domain(self, domain: str) -> dict:
        """
        Sprawdza reputację domeny w VirusTotal.
        Zwraca: wyniki AV, kategorie, subdomeny, rekordy DNS.
        """
        result = self._get(f"domains/{domain}")
        if not result["success"]:
            return result

        attrs = result["data"].get("data", {}).get("attributes", {})
        stats = self._parse_stats(
            attrs.get("last_analysis_stats", {})
        )

        # Rekordy DNS
        dns_records = []
        for record_type, values in attrs.get("last_dns_records", {}).items() \
                if isinstance(attrs.get("last_dns_records"), dict) else []:
            for val in (values if isinstance(values, list) else [values]):
                dns_records.append({
                    "type":  record_type,
                    "value": val,
                })

        return {
            "success":        True,
            "found":          stats["malicious"] > 0 or stats["suspicious"] > 0,
            "type":           "domain",
            "query":          domain,
            "malicious":      stats["malicious"],
            "suspicious":     stats["suspicious"],
            "clean":          stats["clean"],
            "total_engines":  stats["total"],
            "reputation":     attrs.get("reputation", 0),
            "registrar":      attrs.get("registrar"),
            "creation_date":  attrs.get("creation_date"),
            "categories":     attrs.get("categories", {}),
            "dns_records":    dns_records,
            "tags":           attrs.get("tags", []),
            "last_analysis":  attrs.get("last_analysis_date"),
        }

    def lookup(self, query: str) -> dict:
        """Automatycznie wykrywa typ i wywołuje odpowiednią metodę."""
        try:
            ipaddress.ip_address(query)
            return self.check_ip(query)
        except ValueError:
            return self.check_domain(query)