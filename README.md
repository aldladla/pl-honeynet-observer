# PL Honeynet Observer

Projekt studencki do zbierania i analizy telemetrii honeypotów oraz nauki
utrzymania usług na Linuksie. Opublikowany kod obejmuje pipeline Cowrie SSH:
logi, korelację sesji, detekcje zachowań i metadane pozostawionych plików.

**Aktualizacja - 20 października 2026:** środowisko operatora zostało rozbudowane
o sensor HTTP, narzędzia analityka i dokładniejszą ocenę transferów SCP/SFTP.
Część zmian działa w prywatnym wdrożeniu, a część pozostaje w lokalnych labach.
Ten update publikuje dokumentację postępu; nie dodaje kodu tych rozszerzeń.
[Aktualny stan projektu i zakres publikacji](docs/project-status-2026-10.md).

**Technologie:** Python, FastAPI, SQLAlchemy, PostgreSQL / SQLite, Cowrie,
Docker, Linux, Grafana, JavaScript.

![Przegląd nowych sygnałów w zachowanej historii](docs/images/observer-overview-20260907.png)

*Panel operatora, 7 września 2026. Nowy hash oznacza nowość w zachowanej
historii, nie potwierdzenie nowego malware. Screeny przedstawiają wersję rozwojową.*

## Najważniejsze funkcje

- Rekonstrukcja sesji: logowanie, komendy, transfery i chronologiczna oś zdarzeń.
- Wyjaśnialne detekcje zachowań z dowodami z logów.
- Kolejka metadanych plików deduplikowana po SHA-256.
- Kontekst klientów SSH, HASSH i GeoIP/ASN.
- Izolacja sensora, monitoring, retencja i awaryjny kill switch.

Wersja rozwojowa dodaje przegląd nowych sygnałów, grupowanie powiązanych
sesji i karty analizy. Aktualny zakres wdrożeń i labów opisuje
[raport stanu](docs/project-status-2026-10.md). Pełna publikacja ich kodu
pozostaje osobnym etapem.

## Przepływ analizy

Logi Cowrie → normalizacja → baza danych → sesja i detekcje → triage pliku.

Projekt służy do ćwiczenia analizy logów, oceny podejrzanej aktywności
i dokumentowania ustaleń. Reguły wskazują zachowania; nie potwierdzają
automatycznie rodziny malware, wspólnego sprawcy ani skuteczności exploita.

<details>
<summary>Sesja: detekcje i dowody z poleceń</summary>

Reguły wskazują rozpoznanie hosta i przygotowanie wykonania; obok widać
polecenia stanowiące podstawę oceny. Źródła są pseudonimizowane.

![Detekcje zachowań wraz z poleceniami w sesji](docs/images/session-evidence-20260907.png)

</details>

<details>
<summary>Pliki: triage i powtarzające się obserwacje</summary>

Kolejka łączy identyczne SHA-256 i pokazuje rozmiary oraz liczbę powiązanych
sesji. Metadane transferu nie zastępują analizy zawartości pliku.

![Kolejka plików z liczbą obserwacji i powiązanych sesji](docs/images/artifact-triage-20260907.png)

</details>

## Bezpieczeństwo

Sensor działa na infrastrukturze operatora, z ograniczeniami ruchu wychodzącego.
Panel jest dostępny lokalnie lub przez tunel SSH. Pipeline nie wykonuje
przechwyconych plików; raporty publiczne stosują pseudonimizację.

Szczegóły: [bezpieczeństwo](docs/safety.md) ·
[obsługa próbek](docs/sample-handling.md).

<details>
<summary>Uruchomienie i testy</summary>

Wymagane: Python 3.12 oraz Docker Compose.

```powershell
Copy-Item .env.example .env
# Ustaw własne, losowe sekrety w .env.
docker compose up -d --build
Invoke-RestMethod http://127.0.0.1:8000/health
```

Panel: `http://127.0.0.1:8000`. Opcjonalny profil sensora lokalnego:

```powershell
docker compose --profile lab up -d --build
ssh -p 2222 demo@127.0.0.1
```

Testy:

```powershell
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\python.exe -m pytest
docker compose config --quiet
```

Fixture'y używają adresów dokumentacyjnych i domen `.invalid`.

</details>

Projekt rozwijany z pomocą narzędzi AI podczas implementacji i przeglądu.
Licencja [MIT](LICENSE).
