import shodan
from django.conf import settings


class ShodanService:
    """
    Obsługuje komunikację z Shodan API.
    """

    def __init__(self):
        self.api = shodan.Shodan(settings.SHODAN_API_KEY)

    def get_host_info(self, ip: str) -> dict:
        """
        Pobiera wszystkie informacje o danym IP z Shodan.
        Endpoint: GET /shodan/host/{ip}

        Zwraca: porty, bannery, certyfikaty, ASN, lokalizację.
        """
        try:
            host = self.api.host(ip)

            # Wyciągnij certyfikaty TLS ze wszystkich portów
            certyfikaty = []
            for serwis in host.get("data", []):
                ssl = serwis.get("ssl", {})
                cert = ssl.get("cert", {})
                if cert:
                    certyfikaty.append({
                        "port":       serwis.get("port"),
                        "subject":    cert.get("subject", {}),
                        "issuer":     cert.get("issuer", {}),
                        "expires":    cert.get("expires", ""),
                        "issued":     cert.get("issued", ""),
                        "fingerprint": ssl.get("cert", {}).get(
                            "fingerprint", {}
                        ),
                    })

            # Wyciągnij bannery HTTP
            bannery = []
            for serwis in host.get("data", []):
                if serwis.get("http"):
                    bannery.append({
                        "port":   serwis.get("port"),
                        "title":  serwis.get("http", {}).get("title", ""),
                        "server": serwis.get("http", {}).get("server", ""),
                        "status": serwis.get("http", {}).get("status", ""),
                    })

            return {
                "success":      True,
                "ip":           host.get("ip_str"),
                "organization": host.get("org", ""),
                "asn":          host.get("asn", ""),
                "country":      host.get("country_name", ""),
                "country_code": host.get("country_code", ""),
                "city":         host.get("city", ""),
                "isp":          host.get("isp", ""),
                "hostnames":    host.get("hostnames", []),
                "domains":      host.get("domains", []),
                "ports":        host.get("ports", []),
                "tags":         host.get("tags", []),
                "vulns":        list(host.get("vulns", {}).keys())
                                if isinstance(host.get("vulns"), dict)
                                else host.get("vulns", []),
                "last_update":  host.get("last_update", ""),
                "certyfikaty":  certyfikaty,
                "bannery_http": bannery,
                "os":           host.get("os", ""),
            }

        except shodan.APIError as e:
            error_msg = str(e)
            print(f"[SHODAN DEBUG] IP: {ip} | Błąd: '{error_msg}'")

            if "No information available" in error_msg:
                return {
                    "success": False,
                    "error":   f"Shodan nie ma danych dla IP {ip}",
                    "code":    "NOT_FOUND",
                }

            if "Invalid API key" in error_msg:
                return {
                    "success": False,
                    "error":   (
                        f"Shodan nie udostępnia danych dla IP {ip}"
                    ),
                    "code":    "PLAN_LIMIT",
                }

            if "Access denied" in error_msg or "403" in error_msg:
                return {
                    "success": False,
                    "error":   "Brak dostępu do Shodan API — sprawdź klucz",
                    "code":    "AUTH_ERROR",
                }

            return {
                "success": False,
                "error":   f"Shodan: {error_msg}",
                "code":    "API_ERROR",
            }