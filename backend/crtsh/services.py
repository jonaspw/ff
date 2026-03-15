# backend/crtsh/services.py

import requests
import sqlite3
import json
from datetime import datetime, timedelta
from django.conf import settings


class CrtShService:
    """
    Pobiera dane z crt.sh — Certificate Transparency Logs.
    Nie wymaga klucza API ani rejestracji.
    Dokumentacja: https://crt.sh
    """

    BASE_URL   = "https://crt.sh/"
    CACHE_HOURS = 24

    def __init__(self):
        self.headers = {
            "User-Agent": "TAIT-Project/1.0",
            "Accept":     "application/json",
        }
        self._init_db()

    # ============================================================
    # CACHE — SQLite
    # ============================================================

    def _init_db(self):
        """Tworzy tabelę cache dla crt.sh jeśli nie istnieje."""
        conn = sqlite3.connect("cache.db")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS crtsh_cache (
                key        TEXT PRIMARY KEY,
                data       TEXT,
                cached_at  TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _cache_get(self, key: str) -> dict | None:
        """Pobierz z cache — zwróć None jeśli wygasł lub brak."""
        conn = sqlite3.connect("cache.db")
        row = conn.execute(
            "SELECT data, cached_at FROM crtsh_cache WHERE key = ?",
            (key,)
        ).fetchone()
        conn.close()

        if not row:
            return None

        cached_at = datetime.fromisoformat(row[1])
        if datetime.now() - cached_at > timedelta(hours=self.CACHE_HOURS):
            return None

        return json.loads(row[0])

    def _cache_set(self, key: str, data: dict):
        """Zapisz dane do cache."""
        conn = sqlite3.connect("cache.db")
        conn.execute("""
            INSERT OR REPLACE INTO crtsh_cache (key, data, cached_at)
            VALUES (?, ?, ?)
        """, (key, json.dumps(data), datetime.now().isoformat()))
        conn.commit()
        conn.close()

    # ============================================================
    # HTTP
    # ============================================================

    def _get(self, params: dict) -> dict:
        """Wykonaj GET do crt.sh z obsługą błędów."""
        try:
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=30,
            )
            response.raise_for_status()

            # crt.sh zwraca pustą odpowiedź jeśli brak wyników
            if not response.text.strip():
                return {"success": True, "data": []}

            return {"success": True, "data": response.json()}

        except requests.exceptions.Timeout:
            return {"success": False, "error": "Timeout — crt.sh nie odpowiada"}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Brak połączenia z internetem"}
        except requests.exceptions.JSONDecodeError:
            return {"success": False, "error": "Błąd parsowania odpowiedzi crt.sh"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ============================================================
    # GŁÓWNE METODY
    # ============================================================

    def get_domain_certs(self, domain: str) -> dict:
        """
        Pobiera wszystkie certyfikaty TLS dla domeny.
        Używa wildcarda % żeby znaleźć też subdomeny.

        Zwraca: certyfikaty, subdomeny, wystawcy, daty.
        """
        # Sprawdź cache
        cache_key = f"domain_{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return {"success": True, "from_cache": True, **cached}

        # Pobierz z crt.sh — wildcard % znajdzie subdomeny
        result = self._get({
            "q":      f"%.{domain}",
            "output": "json",
        })

        if not result["success"]:
            return result

        certs_raw = result["data"]

        if not certs_raw:
            return {
                "success":    True,
                "from_cache": False,
                "domain":     domain,
                "found":      False,
                "count":      0,
                "subdomeny":  [],
                "certyfikaty": [],
                "wystawcy":   [],
            }

        # Przetwórz certyfikaty
        certyfikaty = []
        subdomeny   = set()
        wystawcy    = set()
        widziane_id = set()

        for cert in certs_raw:
            cert_id = cert.get("id")

            # Pomiń duplikaty
            if cert_id in widziane_id:
                continue
            widziane_id.add(cert_id)

            # Wyciągnij subdomeny z pola name_value
            name_value = cert.get("name_value", "")
            for nazwa in name_value.split("\n"):
                nazwa = nazwa.strip().lower()
                # Pomiń wildcardy i puste
                if nazwa and not nazwa.startswith("*"):
                    subdomeny.add(nazwa)

            # Wystawca certyfikatu
            issuer = cert.get("issuer_name", "")
            if issuer:
                wystawcy.add(issuer)

            certyfikaty.append({
                "id":         cert_id,
                "common_name": cert.get("common_name", ""),
                "name_value": name_value,
                "issuer":     issuer,
                "not_before": cert.get("not_before", ""),
                "not_after":  cert.get("not_after", ""),
                "logged_at":  cert.get("entry_timestamp", ""),
            })

        # Posortuj certyfikaty od najnowszego
        certyfikaty.sort(
            key=lambda x: x.get("not_before", ""),
            reverse=True,
        )

        data = {
            "domain":     domain,
            "found":      True,
            "count":      len(certyfikaty),
            "subdomeny":  sorted(list(subdomeny)),
            "certyfikaty": certyfikaty[:50],  # max 50 najnowszych
            "wystawcy":   list(wystawcy),
        }

        # Zapisz do cache
        self._cache_set(cache_key, data)

        return {"success": True, "from_cache": False, **data}

    def get_ip_certs(self, ip: str) -> dict:
        """
        Pobiera certyfikaty dla adresu IP.
        Przydatne do wykrywania domen hostowanych na tym IP.
        """
        cache_key = f"ip_{ip}"
        cached = self._cache_get(cache_key)
        if cached:
            return {"success": True, "from_cache": True, **cached}

        result = self._get({
            "q":      ip,
            "output": "json",
        })

        if not result["success"]:
            return result

        certs_raw = result["data"]

        if not certs_raw:
            return {
                "success":    True,
                "from_cache": False,
                "ip":         ip,
                "found":      False,
                "count":      0,
                "domeny":     [],
                "certyfikaty": [],
            }

        domeny     = set()
        certyfikaty = []
        widziane_id = set()

        for cert in certs_raw:
            cert_id = cert.get("id")
            if cert_id in widziane_id:
                continue
            widziane_id.add(cert_id)

            # Wyciągnij domeny z certyfikatu
            name_value = cert.get("name_value", "")
            for nazwa in name_value.split("\n"):
                nazwa = nazwa.strip().lower()
                if nazwa and not nazwa.startswith("*"):
                    domeny.add(nazwa)

            certyfikaty.append({
                "id":          cert_id,
                "common_name": cert.get("common_name", ""),
                "issuer":      cert.get("issuer_name", ""),
                "not_before":  cert.get("not_before", ""),
                "not_after":   cert.get("not_after", ""),
            })

        certyfikaty.sort(
            key=lambda x: x.get("not_before", ""),
            reverse=True,
        )

        data = {
            "ip":         ip,
            "found":      True,
            "count":      len(certyfikaty),
            "domeny":     sorted(list(domeny)),
            "certyfikaty": certyfikaty[:50],
        }

        self._cache_set(cache_key, data)
        return {"success": True, "from_cache": False, **data}