# PL Honeynet Observer

Projekt studencki do zbierania i analizy telemetrii honeypotów oraz nauki
utrzymania usług na Linuksie. Opublikowany kod obejmuje pipeline Cowrie SSH:
logi, korelację sesji, detekcje zachowań i metadane pozostawionych plików.

**Aktualizacja - 21 października 2026:** analiza 11 380 sesji i 165 534 zdarzeń,
kontrolowane testy SCP/SFTP oraz poprawki jakości danych wdrożone w środowisku
operatora na VPS. [Studium dochodzenia: równoległe sesje rozpoznania i transferu](docs/case-study-parallel-sessions-2026-10.md)
pokazuje metodę, wyniki i granice interpretacji.
Ta aktualizacja publikuje opis prac i zrzut panelu; kod rozszerzeń pozostaje
poza publiczną wersją. [Stan projektu i zakres publikacji](docs/project-status-2026-10.md).

**Technologie:** Python, FastAPI, SQLAlchemy, PostgreSQL / SQLite, Cowrie,
Docker, Linux, Grafana, JavaScript.

![Panel operatora: filtrowanie małych zapisów powłoki i jawny zakres odczytanych obserwacji](docs/images/artifact-provenance-20261021.png)

*Panel operatora, 21 października 2026. Filtr rozdziela sposób zapisu pliku,
a kolejka podaje zakres odczytanych obserwacji. Licznik hashy nie oznacza liczby
malware. Zrzut przedstawia prywatnie wdrożone rozszerzenie, którego kod nie
jest jeszcze częścią publicznego repozytorium.*

## Przykład analizy opartej na dowodach

W zamrożonym zbiorze znaleziono 2 132 pary równoległych sesji rozpoznania
i transferu, kończących się w odstępie do 25 ms. Sesje rozpoznania mają identyczny
prefiks 13 komend. Wynik wskazuje powtarzalny schemat automatyzacji; nie dowodzi
wspólnego sprawcy ani wykonania przesłanego pliku.

[Przeczytaj studium przypadku i opis testów kompletności transferu](docs/case-study-parallel-sessions-2026-10.md).

## Najważniejsze funkcje

- Rekonstrukcja sesji: logowanie, komendy, transfery i chronologiczna oś zdarzeń.
- Wyjaśnialne detekcje zachowań z dowodami z logów.
- Kolejka metadanych plików deduplikowana po SHA-256.
- Kontekst klientów SSH, HASSH i GeoIP/ASN.
- Izolacja sensora, monitoring, retencja i awaryjny kill switch.

Wersja operatora dodaje przegląd nowych sygnałów, grupowanie powiązanych
sesji, karty analizy i filtr sposobu zapisu pliku. Zakres wdrożeń i labów opisuje
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
Zrzut przedstawia wersję rozwojową z 7 września 2026.

![Detekcje zachowań wraz z poleceniami w sesji](docs/images/session-evidence-20260907.png)

</details>

<details>
<summary>Pliki: triage i powtarzające się obserwacje</summary>

Kolejka łączy identyczne SHA-256 i pokazuje rozmiary oraz liczbę powiązanych
sesji. Metadane transferu nie zastępują analizy zawartości pliku.
Zrzut przedstawia wersję rozwojową z 7 września 2026.

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
