# Apt Tracker — Dokumentacja projektu

## Krótkie podsumowanie

Apt Tracker to aplikacja do agregacji i analizy informacji o zagrożeniach (Threat Intelligence) skoncentrowana na śledzeniu aktywności APT (Advanced Persistent Threat). Projekt składa się z backendu w Django, który integruje wiele źródeł wywiadu (CIRCL, CRt.sh, Shodan, VirusTotal, ThreatFox, AbuseIPDB, Whois itd.), oraz frontendowego interfejsu w Vue.js (Vite), który umożliwia wyszukiwanie, wizualizację i ocenę IOC (Indicators of Compromise) oraz profili APT.

## Cel aplikacji

- Zbieranie i konsolidacja danych z różnych serwisów wywiadowczych.
- Umożliwienie szybkiego sprawdzenia wskaźników (domen, certyfikatów, adresów IP, IOC) pod kątem powiązań z APT.
- Dostosowywalne reguły punktacji (scoring) i możliwość analizowania profili APT.

## Architektura

- Backend: Django (projekt w katalogu `backend/`). Główne komponenty to zestaw aplikacji Django każda odpowiedzialna za integrację z jednym źródłem oraz moduł `analyzer` wykonujący agregację i scoring.
- Frontend: Vue 3 + Vite (katalog `frontend/`), aplikacja SPA z komponentami do wyświetlania wyników i konfiguracji.
- Dane MITRE ATT&CK znajdują się w `backend/mitre_data/enterprise-attack.json`.

## Najważniejsze pliki i lokalizacje

- **Backend główny URL**: [backend/core/urls.py](backend/core/urls.py#L1)
- **Lista aplikacji analizujących i endpointów**: [backend/analyzer/urls.py](backend/analyzer/urls.py#L1)
- **Frontend - wywołania API**: [frontend/src/api/analyze.js](frontend/src/api/analyze.js#L1)

## Aplikacje backendowe — krótki opis

- `analyzer` — koordynuje analizę zapytań i profili APT; udostępnia endpointy analizy i konfiguracji punktacji. Pliki: [backend/analyzer/](backend/analyzer/urls.py#L1)
- `circl` — integracja z CIRCL (manifesty, eventy, przeszukiwanie aktorów).
- `crtsh` — zapytania o certyfikaty z crt.sh.
- `shodanapp` — zapytania do Shodan (host/domain).
- `whois_lookup` — zapytania WHOIS dla domen.
- `abuseipdb` — sprawdzanie reputacji adresów IP w AbuseIPDB.
- `virustotal` — integracja z VirusTotal.
- `threatfox` — pobieranie i przeszukiwanie IOC z ThreatFox.

Pliki konfiguracyjne i implementacje usług znajdują się w katalogach odpowiadających aplikacjom (np. `backend/crtsh/services.py`, `backend/shodanapp/services.py`).

## Główne endpointy API

Ścieżki opisane w `backend/core/urls.py` (prefiks `/api/`):

- `/api/analyze/` — analiza pojedynczego zapytania (parametr `q`) oraz endpointy pomocnicze:
  - `/api/analyze/` → analizuje query — zmapowane do `analyzer.views.AnalyzeView` ([backend/analyzer/urls.py](backend/analyzer/urls.py#L1)).
  - `/api/analyze/apt/` → pobiera profil APT (`name`), `analyzer.views.APTProfileView`.
  - `/api/analyze/apt/technique/` → szczegóły technik MITRE.
  - `/api/analyze/config/` → analiza z użyciem konfigurowalnych reguł.
- `/api/threatfox/recent/` i `/api/threatfox/search/` — dostęp do ThreatFox.
- `/api/circl/sync/`, `/api/circl/full-sync/`, `/api/circl/manifest/`, `/api/circl/event/`, `/api/circl/search/` — integracja CIRCL.
- `/api/shodan/host/`, `/api/shodan/domain/` — zapytania Shodan.
- `/api/crtsh/lookup/` — wyszukiwanie certyfikatów w crt.sh.
- `/api/whois/` — wyszukiwanie WHOIS.
- `/api/abuseipdb/` — sprawdzanie reputacji IP.
- `/api/virustotal/` — wyszukiwanie w VirusTotal.

Przykład: front-end używa `frontend/src/api/analyze.js` i wywołuje `https://<backend>/analyze/?q=...` (w pliku ustawione jest `API_BASE`).

## Jak to działa (high-level)

1. Użytkownik wpisuje zapytanie (np. domenę, certyfikat, nazwę APT) we frontendzie.
2. Frontend wywołuje endpointy w `analyzer` lub bezpośrednio integracje (np. crtsh, shodan) w razie potrzeby.
3. `analyzer` korzysta z serwisów poszczególnych aplikacji (`services.py`) aby pobrać dodatkowe informacje i zbudować skonsolidowany raport.
4. Wynik jest wzbogacany o scoring zgodnie z regułami (możliwość nadpisania configu przez nagłówek `X-Scoring-Config`).
5. Frontend prezentuje zestaw powiązań, oceny i (opcjonalnie) modalne okienka z detalami (np. techniki MITRE, eventy CIRCL).

## Konfiguracja środowiska lokalnego

1. Backend (Python/Django):

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DJANGO_SECRET_KEY="zmienna_tutaj"
# Ustaw zmienne API dla poszczególnych serwisów (SHODAN_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_KEY itp.)
python manage.py migrate
python manage.py runserver
```

2. Frontend (Node.js / Vite):

```bash
cd frontend
npm install
npm run dev
```

Uwaga: domyślnie frontend oczekuje zewnętrznej zmiennej `API_BASE` w `frontend/src/api/analyze.js`. W środowisku deweloperskim można zmienić ją na lokalny backend.

## Testy

- Uruchom testy Django: `python manage.py test` w katalogu `backend/`.
- Pliki testów znajdują się wewnątrz każdej aplikacji, np. `backend/analyzer/tests.py`.

## Deployment

- W repozytorium jest plik `Procfile` (prawdopodobnie dla Heroku/Railway) oraz `vercel.json` i konfiguracja frontendu dla Vercel.
- Przy wdrożeniu ustaw zmienne środowiskowe: klucze API, `DJANGO_SECRET_KEY`, konfiguracja bazy danych.

## Gdzie szukać implementacji ważnych funkcji

- Punkt wejścia URL/API: [backend/core/urls.py](backend/core/urls.py#L1)
- Logika analizy i profile APT: [backend/analyzer/](backend/analyzer/urls.py#L1)
- Integracje z zewnętrznymi serwisami: katalogi aplikacji (np. [backend/crtsh/services.py](backend/crtsh/services.py#L1), [backend/shodanapp/services.py](backend/shodanapp/services.py#L1)).
- Frontend: komponenty w `frontend/src/components/` oraz widoki w `frontend/src/views/`.

## Szybkie wskazówki dla deweloperów

- Aby dodać nowe źródło wywiadu, dodaj aplikację Django z `services.py`, `views.py`, `urls.py` i zarejestruj ją w `core/urls.py`.
- Jeśli chcesz zmienić reguły scoringu, frontend zapisuje konfigurację w `localStorage` pod kluczem `scoring_config` i przekazuje ją nagłówkiem `X-Scoring-Config`.

## Kontakt i dalsze kroki

Jeśli chcesz, mogę:
- rozszerzyć dokumentację o szczegółowy opis modeli (`models.py`) i format zwracanych JSON-ów,
- wygenerować dokumentację API w formacie OpenAPI/Swagger,
- przygotować skrypt uruchomieniowy lub plik `docker-compose`.

---
Plik README zapisany w katalogu głównym projektu.
