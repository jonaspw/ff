# backend/whois_lookup/services.py

import ipaddress
import whois
from ipwhois import IPWhois


class WhoisService:
    """
    Pobiera dane rejestracyjne dla domen i IP.
    Nie wymaga klucza API.

    Dla domen: python-whois (registrar, daty, NS)
    Dla IP: ipwhois RDAP (ASN, właściciel, kraj)
    """

    def get_domain_whois(self, domain: str) -> dict:
        """
        Pobiera dane WHOIS dla domeny.
        Zwraca: registrar, daty, nameservery, status.
        """
        try:
            w = whois.whois(domain)

            # Normalizuj daty — mogą być listą lub pojedynczą wartością
            def normalize_date(d):
                if isinstance(d, list):
                    return str(d[0]) if d else None
                return str(d) if d else None

            # Normalizuj nameservery
            nameservers = w.name_servers
            if isinstance(nameservers, list):
                nameservers = [ns.lower() for ns in nameservers]
            elif isinstance(nameservers, str):
                nameservers = [nameservers.lower()]
            else:
                nameservers = []

            # Normalizuj status
            status = w.status
            if isinstance(status, list):
                status = status
            elif isinstance(status, str):
                status = [status]
            else:
                status = []

            return {
                "success":      True,
                "found":        True,
                "type":         "domain",
                "domain":       domain,
                "registrar":    w.registrar,
                "created":      normalize_date(w.creation_date),
                "updated":      normalize_date(w.updated_date),
                "expires":      normalize_date(w.expiration_date),
                "nameservers":  nameservers,
                "status":       status,
                "emails":       w.emails if isinstance(w.emails, list)
                                else [w.emails] if w.emails else [],
                "org":          w.org,
                "country":      w.country,
            }

        except whois.parser.PywhoisError:
            return {
                "success": False,
                "error":   f"Brak danych WHOIS dla domeny {domain}",
                "code":    "NOT_FOUND",
            }
        except Exception as e:
            return {
                "success": False,
                "error":   f"Błąd WHOIS: {str(e)}",
                "code":    "ERROR",
            }

    def get_ip_whois(self, ip: str) -> dict:
        """
        Pobiera dane RDAP dla adresu IP.
        Zwraca: ASN, właściciel, kraj, prefix.
        """
        try:
            obj    = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)

            # Wyciągnij dane sieci
            network = result.get("network", {})

            return {
                "success":      True,
                "found":        True,
                "type":         "ip",
                "ip":           ip,
                "asn":          result.get("asn"),
                "asn_cidr":     result.get("asn_cidr"),
                "asn_name":     result.get("asn_description"),
                "asn_country":  result.get("asn_country_code"),
                "network_name": network.get("name"),
                "network_cidr": network.get("cidr"),
                "start_address": network.get("start_address"),
                "end_address":   network.get("end_address"),
                "country":      network.get("country"),
                "org":          result.get("asn_description"),
            }

        except Exception as e:
            return {
                "success": False,
                "error":   f"Błąd RDAP dla IP {ip}: {str(e)}",
                "code":    "ERROR",
            }

    def lookup(self, query: str) -> dict:
        """
        Automatycznie wykrywa typ zapytania i wywołuje
        odpowiednią metodę.
        """
        try:
            ipaddress.ip_address(query)
            return self.get_ip_whois(query)
        except ValueError:
            return self.get_domain_whois(query)