import requests
import sqlite3
import json
from datetime import datetime, timedelta
from django.conf import settings


class CIRCLFeedService:

    FEED_URL           = "https://www.circl.lu/doc/misp/feed-osint/"
    MANIFEST_TTL_HOURS = 24

    def __init__(self):
        self.headers = {"User-Agent": "TAIT-Project/1.0"}
        self._init_db()

    def _init_db(self):
        """Tworzy tabele w SQLite jeśli nie istnieją."""
        conn = sqlite3.connect("cache.db")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS circl_manifest (
                uuid     TEXT PRIMARY KEY,
                info     TEXT,
                date     TEXT,
                org      TEXT,
                added_at TEXT
            );
            CREATE TABLE IF NOT EXISTS circl_events (
                uuid       TEXT PRIMARY KEY,
                data       TEXT,
                fetched_at TEXT
            );
            CREATE TABLE IF NOT EXISTS circl_meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
        """)
        conn.commit()
        conn.close()

    def _get_meta(self, key: str):
        """Pobierz wartość metadanych z bazy."""
        conn = sqlite3.connect("cache.db")
        row = conn.execute(
            "SELECT value FROM circl_meta WHERE key = ?", (key,)
        ).fetchone()
        conn.close()
        return row[0] if row else None

    def _set_meta(self, key: str, value: str):
        """Zapisz wartość metadanych do bazy."""
        conn = sqlite3.connect("cache.db")
        conn.execute(
            "INSERT OR REPLACE INTO circl_meta (key, value) VALUES (?, ?)",
            (key, value)
        )
        conn.commit()
        conn.close()

    def _manifest_is_fresh(self) -> bool:
        """Sprawdź czy manifest był pobrany w ciągu ostatnich 24h."""
        last = self._get_meta("manifest_last_checked")
        if not last:
            return False
        return datetime.now() - datetime.fromisoformat(last) \
               < timedelta(hours=self.MANIFEST_TTL_HOURS)

    def _get(self, url: str) -> dict:
        """Wykonaj GET request z obsługą błędów."""
        try:
            r = requests.get(url, headers=self.headers, timeout=30)
            r.raise_for_status()
            return {"success": True, "data": r.json()}
        except requests.exceptions.Timeout:
            return {"success": False, "error": "Timeout"}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Brak połączenia"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def sync_manifest(self) -> dict:
        """
        Synchronizuje manifest z CIRCL.
        Pobiera tylko nowe eventy — nie nadpisuje istniejących.
        Wykonuje maksymalnie jedno zapytanie HTTP na 24h.
        """
        if self._manifest_is_fresh():
            return {
                "success":    True,
                "synced":     False,
                "new_events": 0,
                "message":    "Manifest aktualny — następne odświeżenie za < 24h",
            }

        # Pobierz aktualny manifest z CIRCL
        result = self._get(f"{self.FEED_URL}manifest.json")
        if not result["success"]:
            return result

        remote = result["data"]

        # Sprawdź które UUID już mamy w bazie
        conn = sqlite3.connect("cache.db")
        existing = set(
            r[0] for r in
            conn.execute("SELECT uuid FROM circl_manifest").fetchall()
        )

        # Zapisz tylko NOWE UUID
        new_uuids = set(remote.keys()) - existing
        now = datetime.now().isoformat()

        for uuid in new_uuids:
            meta = remote[uuid]
            conn.execute("""
                INSERT OR IGNORE INTO circl_manifest
                (uuid, info, date, org, added_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                uuid,
                meta.get("info", ""),
                meta.get("date", ""),
                meta.get("Orgc", {}).get("name", ""),
                now,
            ))

        conn.commit()
        conn.close()
        self._set_meta("manifest_last_checked", now)

        return {
            "success":    True,
            "synced":     True,
            "total":      len(remote),
            "new_events": len(new_uuids),
            "message":    f"Znaleziono {len(new_uuids)} nowych eventów",
        }

    def get_event(self, uuid: str) -> dict:
        """
        Pobiera konkretny event.
        Najpierw sprawdza cache — jeśli jest, zwraca od razu.
        Jeśli nie ma — pobiera z CIRCL i zapisuje do cache.
        """
        conn = sqlite3.connect("cache.db")
        row = conn.execute(
            "SELECT data FROM circl_events WHERE uuid = ?", (uuid,)
        ).fetchone()
        conn.close()

        if row:
            return {
                "success":    True,
                "from_cache": True,
                **json.loads(row[0])
            }

        # Nie ma w cache — pobierz z CIRCL
        result = self._get(f"{self.FEED_URL}{uuid}.json")
        if not result["success"]:
            return result

        event_data = result["data"].get("Event", {})

        # Wyciągnij IOC z atrybutów
        iocs = []
        for attr in event_data.get("Attribute", []):
            if attr.get("type") in [
                "ip-dst", "ip-src", "domain", "hostname",
                "url", "md5", "sha256", "x509-fingerprint-sha1"
            ]:
                iocs.append({
                    "type":    attr.get("type"),
                    "value":   attr.get("value"),
                    "comment": attr.get("comment", ""),
                    "to_ids":  attr.get("to_ids", False),
                    "tags": [
                        t.get("name") for t in attr.get("Tag", [])
                    ],
                })

        data = {
            "event_id":  uuid,
            "info":      event_data.get("info", ""),
            "date":      event_data.get("date", ""),
            "ioc_count": len(iocs),
            "iocs":      iocs,
        }

        # Zapisz do cache bezterminowo
        conn = sqlite3.connect("cache.db")
        conn.execute("""
            INSERT OR REPLACE INTO circl_events (uuid, data, fetched_at)
            VALUES (?, ?, ?)
        """, (uuid, json.dumps(data), datetime.now().isoformat()))
        conn.commit()
        conn.close()

        return {"success": True, "from_cache": False, **data}

    def get_manifest_local(self) -> dict:
        """
        Zwraca manifest z lokalnej bazy SQLite.
        Zero requestów HTTP do CIRCL.
        """
        conn = sqlite3.connect("cache.db")
        rows = conn.execute(
            "SELECT uuid, info, date, org FROM circl_manifest"
            " ORDER BY date DESC"
        ).fetchall()
        conn.close()

        return {
            "success": True,
            "count":   len(rows),
            "events":  [
                {"uuid": r[0], "info": r[1],
                 "date": r[2], "org":  r[3]}
                for r in rows
            ],
        }

    def search_by_actor(self, actor: str) -> dict:
        """
        Szukaj eventów po nazwie grupy APT w lokalnej bazie.
        Zero requestów HTTP do CIRCL.
        """
        conn = sqlite3.connect("cache.db")
        rows = conn.execute("""
            SELECT uuid, info, date, org FROM circl_manifest
            WHERE LOWER(info) LIKE ?
            ORDER BY date DESC
        """, (f"%{actor.lower()}%",)).fetchall()
        conn.close()

        return {
            "success":     True,
            "actor":       actor,
            "found_count": len(rows),
            "events": [
                {"uuid": r[0], "info": r[1],
                 "date": r[2], "org":  r[3]}
                for r in rows
            ],
        }
    
    def full_sync(self) -> dict:
        """
        Pobiera WSZYSTKIE eventy z CIRCL i zapisuje do bazy.
        Wywołaj tylko raz — przy pierwszym uruchomieniu.
        Kolejne aktualizacje obsługuje sync_manifest().

        Pomija eventy które już są w cache — bezpieczne do
        wielokrotnego wywołania jeśli przerwiemy w połowie.
        """
        # Najpierw pobierz/zaktualizuj manifest
        manifest_result = self._get(f"{self.FEED_URL}manifest.json")
        if not manifest_result["success"]:
            return manifest_result

        remote = manifest_result["data"]
        all_uuids = list(remote.keys())

        # Sprawdź które eventy już mamy w cache
        conn = sqlite3.connect("cache.db")

        # Zapisz nowe UUID do manifestu
        existing_manifest = set(
            r[0] for r in
            conn.execute(
                "SELECT uuid FROM circl_manifest"
            ).fetchall()
        )

        now = datetime.now().isoformat()
        for uuid in all_uuids:
            if uuid not in existing_manifest:
                meta = remote[uuid]
                conn.execute("""
                    INSERT OR IGNORE INTO circl_manifest
                    (uuid, info, date, org, added_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    uuid,
                    meta.get("info", ""),
                    meta.get("date", ""),
                    meta.get("Orgc", {}).get("name", ""),
                    now,
                ))
        conn.commit()

        # Sprawdź które eventy już mamy pobrane
        existing_events = set(
            r[0] for r in
            conn.execute(
                "SELECT uuid FROM circl_events"
            ).fetchall()
        )
        conn.close()

        # Pobierz tylko brakujące eventy
        to_fetch = [
            uuid for uuid in all_uuids
            if uuid not in existing_events
        ]

        total     = len(all_uuids)
        already   = len(existing_events)
        to_fetch_count = len(to_fetch)

        fetched   = 0
        failed    = 0
        failed_uuids = []

        for i, uuid in enumerate(to_fetch):
            result = self.get_event(uuid)

            if result["success"]:
                fetched += 1
            else:
                failed += 1
                failed_uuids.append(uuid)

            # Log postępu co 50 eventów
            if (i + 1) % 50 == 0:
                print(
                    f"Postęp: {i+1}/{to_fetch_count} "
                    f"({fetched} ok, {failed} błędów)"
                )

        # Zaktualizuj znacznik czasu manifestu
        self._set_meta("manifest_last_checked", now)

        return {
            "success":       True,
            "total_in_feed": total,
            "already_cached": already,
            "fetched_now":   fetched,
            "failed":        failed,
            "failed_uuids":  failed_uuids[:10],  # pierwsze 10 błędów
            "message": (
                f"Pobrano {fetched} nowych eventów. "
                f"{already} było już w cache. "
                f"{failed} błędów."
            ),
        }
    