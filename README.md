# PL Honeynet Observer

Projekt studencki do bezpiecznego zbierania i analizowania telemetrii z własnego
sensora SSH honeypot. System łączy pojedyncze zdarzenia Cowrie w sesje, wykrywa
obserwowane zachowania, pseudonimizuje źródła i pokazuje wyniki w autorskim panelu
oraz Grafanie.

Najważniejszym założeniem projektu jest izolacja. Sensor nie może służyć jako punkt
wyjścia do innych systemów, a przechwycone pliki są zapisywane w kwarantannie i
nigdy nie są wykonywane przez pipeline analityczny.

Projekt rozwijam jako praktyczne laboratorium pracy analityka SOC: od logu sensora,
przez triage i rekonstrukcję sesji, do zapisania ustaleń opartych na dowodach.

**Stack:** Python · FastAPI · Pydantic · SQLAlchemy · PostgreSQL / SQLite ·
Cowrie · Docker Compose · Linux · Grafana · JavaScript.

![Aktualny panel: przegląd nowych sygnałów na danych syntetycznych](docs/images/analyst-overview-demo.png)

*Podgląd lokalnej wersji rozwojowej z 7 września 2026. Dane są syntetyczne;
liczniki na nowych screenshotach nie przedstawiają wyników sensora. Opis i obrazy
wersji rozwojowej są publikowane przed pełną aktualizacją jej kodu na GitHub.*

## Jak wygląda praca analityka

1. Przegląd nowych sygnałów i odróżnienie ich od powtórzeń w zachowanej historii.
2. Otwarcie sesji i sprawdzenie logowania, poleceń, transferów oraz dowodów reguł.
3. Porównanie metadanych pliku po SHA-256 i przejście do powiązanych sesji.
4. Zapisanie ustaleń, kompletności próbki i pewności oceny w karcie analizy.

Kroki 1 i 4 oraz odświeżona nawigacja są częścią lokalnej wersji rozwojowej.
Panel wspiera ocenę analityka; klasyfikacja pliku w karcie jest oceną operatora.

## Podgląd aktualnej wersji rozwojowej

Panel ma trzy obszary pracy: **Przegląd**, **Sesje** i **Pliki**.
Nowość oznacza pierwszy ślad w zachowanej historii, a nie odkrycie nowego malware.
Grupowanie według hasha, adresu pobierania lub wzorca komend pomaga odnaleźć
powiązane sesje, ale samo nie potwierdza wspólnej kampanii ani sprawcy.

Karta analizy rozdziela status pracy, kompletność próbki, klasyfikację,
pewność oceny i zapisane dowody. Pozwala także pozostawić analizę częściową.

![Karta analizy artefaktu — formularz w demonstracyjnej wersji panelu](docs/images/analysis-card-demo.png)

<details>
<summary>Aktualna kolejka plików — dane demonstracyjne</summary>

Wyszukiwanie po nazwie i SHA-256, liczba obserwacji, archiwizacja oraz przejście
do karty analizy. Przechwycony artefakt i samo źródło pobierania są prezentowane
oddzielnie.

![Aktualna kolejka artefaktów na danych syntetycznych](docs/images/artifact-queue-demo.png)

</details>

## Kompetencje rozwijane w projekcie

- Analiza logów SSH i korelacja zdarzeń w ramach sesji.
- Triage poleceń oraz metadanych podejrzanych plików.
- Budowa wyjaśnialnych reguł wykrywania zachowań.
- Rozróżnianie próby wykonania, odpowiedzi emulatora i potwierdzonego zdarzenia.
- Dokumentowanie dowodów, hipotez i ograniczeń analizy.
- Obsługa izolowanego środowiska Linux / Docker oraz monitoringu sensora.

Praca z próbkami w osobnym laboratorium jest etapem ręcznym. Sam pipeline
nie wykonuje automatycznej analizy dynamicznej malware.

## Co udało się zbudować

- adapter i przyrostowy collector dla `cowrie.json`,
- walidację oraz idempotentny import JSONL,
- korelację zdarzeń po `session_id`,
- ocenę ryzyka i wyjaśnialne detekcje zachowań,
- rekonstrukcję osi czasu sesji,
- profile klientów SSH, HASSH oraz lokalny kontekst GeoIP/ASN,
- deduplikowaną kolejkę metadanych artefaktów po SHA-256,
- panel FastAPI i osobny dashboard Grafana,
- retencję danych, monitoring, kontrolę integralności i awaryjny kill switch,
- filtrowanie ruchu wychodzącego z izolowanej części sensora.

W pilotażowym uruchomieniu system zebrał kilka tysięcy sesji i zarejestrował między
innymi bezpośrednie transfery plików. Poniższy przykład pokazuje metadane pliku
`sshd` przesłanego w dwóch sesjach. Plik został zachowany, ale nie uruchomiony.

![Przechwycony artefakt w osi czasu sesji](docs/images/critical-session-upload.png)

## Architektura

```mermaid
flowchart LR
    Internet[Internet] --> Gate[Firewall gate]
    Gate --> Proxy[SSH gateway]
    Proxy --> Cowrie[Cowrie]
    Cowrie --> Collector[Collector]
    Collector --> DB[(PostgreSQL)]
    DB --> API[FastAPI / panel]
    DB --> Grafana[Grafana]
    Cowrie --> Quarantine[(Kwarantanna)]

    Monitor[Monitor systemd] -. kontrola .-> Gate
    Monitor -. health / integralność .-> API
    Egress[Blokada nowych połączeń wychodzących] -. izolacja .-> Cowrie
    Egress -. izolacja .-> Proxy
```

Panel aplikacji i Grafana są związane wyłącznie z `localhost` i na VPS są dostępne
przez tunel SSH. Publicznie wystawiany jest tylko emulowany sensor. PostgreSQL
pozostaje w wewnętrznej sieci Dockera.

## Widoki analityczne

Poniższe obrazy dokumentują wcześniejszą wersję panelu i pilotaż.
Aktualny wygląd wersji rozwojowej pokazano na początku README.

Autorski panel służy do czytania pojedynczych sesji: pokazuje logowanie, polecenia,
transfery, detekcje i chronologiczną rekonstrukcję. Widoki nie ujawniają surowych
adresów IP ani przechwyconych haseł.

![Kolejka metadanych artefaktów](docs/images/artifact-triage.png)

Grafana daje widok zagregowany: liczbę sesji i zdarzeń, aktywność w czasie,
strukturę zachowań i listę sesji wymagających uwagi.

![Dashboard Grafana](docs/images/grafana-overview.png)

## Bezpieczeństwo

Projekt jest defensywny i działa wyłącznie na infrastrukturze należącej do
operatora projektu. Nie zawiera aktywnego skanowania, odwetu ani eksploatacji
systemów zewnętrznych.

Najważniejsze zabezpieczenia:

- administracja SSH wyłącznie kluczem, bez logowania roota i bez haseł,
- osobna bramka sensora, domyślnie zamknięta,
- `DOCKER-USER` blokujący nowe połączenia wychodzące z sieci sensora,
- automatyczny kill switch uruchamiany po błędzie monitoringu,
- baseline integralności kodu, konfiguracji i obrazów,
- limity CPU, RAM, procesów, rozmiaru pojedynczego pliku i całej kwarantanny,
- panel, Grafana oraz baza niewystawione bezpośrednio do Internetu,
- eksporty publiczne oparte na allowliście i pseudonimizacji.

Pełna checklista znajduje się w [`docs/safety.md`](docs/safety.md), a model
obsługi próbek w [`docs/sample-handling.md`](docs/sample-handling.md).

## Uruchomienie lokalne

Wymagane są Python 3.12 oraz Docker z Compose.

```powershell
Copy-Item .env.example .env
# Ustaw własne, losowe sekrety w prywatnym pliku .env.
docker compose up -d --build
Invoke-RestMethod http://127.0.0.1:8000/health
```

Dashboard jest dostępny pod `http://127.0.0.1:8000`. Profil z Cowrie uruchamia
się osobno i domyślnie publikuje sensor tylko na loopback:

```powershell
docker compose --profile lab up -d --build
ssh -p 2222 demo@127.0.0.1
```

Zatrzymanie środowiska bez usuwania wolumenów:

```powershell
docker compose --profile lab down
```

## Testy

```powershell
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\python.exe -m pytest
docker compose config --quiet
```

Fixture'y używają wyłącznie adresów dokumentacyjnych RFC 5737 i domen `.invalid`.
Repozytorium nie zawiera danych z produkcyjnego sensora ani przechwyconych plików.

## Struktura projektu

```text
src/honeynet/          logika aplikacji, API, modele i detekcje
tests/                 testy jednostkowe i integracyjne
fixtures/              wyłącznie syntetyczne zdarzenia JSONL
deploy/pilot/          firewall gate, monitor, baseline i usługi systemd
deploy/grafana/        provisioning i dashboard Grafana
deploy/cowrie-persona/ bezpieczna persona emulowanego hosta
docs/                  metodologia, prywatność i instrukcje bezpieczeństwa
```

## Ograniczenia i dalszy rozwój

- Wynik ryzyka jest heurystyką, a nie dowodem przypisania konkretnej kampanii.
- Lokalizacja IP opisuje infrastrukturę źródłową, nie rzeczywistą lokalizację osoby.
- Projekt nie uruchamia przechwyconych plików; ewentualna analiza statyczna wymaga
  osobnego, odizolowanego laboratorium.
- Do badania ataków ukierunkowanych potrzebne byłyby dodatkowe sensory kontrolne i
  dłuższy okres obserwacji.

Najbliższe kroki to weryfikacja i publikacja aktualnej wersji panelu, opisanie
studium przypadku z dowodami oraz ocena jakości grupowania sesji. Kolejny etap
badawczy to wyróżnianie zmian w powracających schematach aktywności i sprawdzanie
reguł wykrywania na zachowanych logach oraz przykładach zwykłej administracji.

## Sposób pracy

Projekt powstał z wykorzystaniem narzędzi AI jako wsparcia podczas implementacji i
przeglądu. Decyzje dotyczące architektury, wdrożenia, zabezpieczeń, testów oraz
walidacji działania były podejmowane i sprawdzane przez autora projektu.

## Licencja

Kod jest udostępniany na licencji MIT. Zobacz [`LICENSE`](LICENSE).
