# backend/abuseipdb/services.py

import requests
from django.conf import settings


class AbuseIPDBService:
    """
    Pobiera dane o złośliwości IP z AbuseIPDB.
    Dokumentacja: https://www.abuseipdb.com/api.html

    Darmowy plan: 1000 zapytań dziennie.
    Działa tylko dla adresów IP — nie dla domen.
    """

    def __init__(self):
        self.api_url = settings.ABUSEIPDB_API_URL
        self.headers = {
            "Key":    settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }

    def check_ip(self, ip: str, days: int = 90) -> dict:
        """
        Sprawdza reputację IP w AbuseIPDB.

        ip:   adres IP do sprawdzenia
        days: za ile ostatnich dni sprawdzić raporty (max 365)

        Zwraca: abuse score (0-100), liczba raportów,
                kategorie ataków, ostatni raport.
        """
        try:
            response = requests.get(
                f"{self.api_url}check",
                headers=self.headers,
                params={
                    "ipAddress":          ip,
                    "maxAgeInDays":       days,
                    "verbose":            True,
                },
                timeout=30,
            )

            if response.status_code == 401:
                return {
                    "success": False,
                    "error":   "Nieprawidłowy klucz API AbuseIPDB",
                    "code":    "AUTH_ERROR",
                }

            if response.status_code == 429:
                return {
                    "success": False,
                    "error":   "Przekroczono limit zapytań AbuseIPDB",
                    "code":    "RATE_LIMIT",
                }

            response.raise_for_status()
            data = response.json().get("data", {})

            # Kategorie ataków — mapowanie ID na nazwy
            kategorie_map = {
                1:  "DNS Compromise",
                2:  "DNS Poisoning",
                3:  "Fraud Orders",
                4:  "DDoS Attack",
                5:  "FTP Brute-Force",
                6:  "Ping of Death",
                7:  "Phishing",
                8:  "Fraud VoIP",
                9:  "Open Proxy",
                10: "Web Spam",
                11: "Email Spam",
                12: "Blog Spam",
                13: "VPN IP",
                14: "Port Scan",
                15: "Hacking",
                16: "SQL Injection",
                17: "Spoofing",
                18: "Brute-Force",
                19: "Bad Web Bot",
                20: "Exploited Host",
                21: "Web App Attack",
                22: "SSH Abuse",
                23: "IoT Targeted",
            }

            # Wyciągnij unikalne kategorie z raportów
            wszystkie_kategorie = set()
            for raport in data.get("reports", []):
                for kat_id in raport.get("categories", []):
                    nazwa = kategorie_map.get(kat_id, f"Category {kat_id}")
                    wszystkie_kategorie.add(nazwa)

            abuse_score = data.get("abuseConfidenceScore", 0)

            # Określ poziom zagrożenia na podstawie score
            if abuse_score >= 80:
                risk = "CRITICAL"
            elif abuse_score >= 50:
                risk = "HIGH"
            elif abuse_score >= 25:
                risk = "MEDIUM"
            elif abuse_score > 0:
                risk = "LOW"
            else:
                risk = "CLEAN"

            return {
                "success":          True,
                "found":            abuse_score > 0,
                "ip":               ip,
                "abuse_score":      abuse_score,
                "risk":             risk,
                "total_reports":    data.get("totalReports", 0),
                "distinct_users":   data.get("numDistinctUsers", 0),
                "last_reported":    data.get("lastReportedAt"),
                "isp":              data.get("isp"),
                "domain":           data.get("domain"),
                "country":          data.get("countryCode"),
                "usage_type":       data.get("usageType"),
                "is_tor":           data.get("isTor", False),
                "is_public":        data.get("isPublic", True),
                "categories":       list(wszystkie_kategorie),
            }

        except requests.exceptions.Timeout:
            return {"success": False, "error": "Timeout — AbuseIPDB nie odpowiada"}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Brak połączenia z internetem"}
        except Exception as e:
            return {"success": False, "error": str(e)}