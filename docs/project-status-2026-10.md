# Stan projektu - 21 października 2026

PL Honeynet Observer jest projektem studenckim rozwijanym na własnej
infrastrukturze. Łączy zbieranie telemetrii, utrzymanie usług na Linuksie,
analizę sesji i dokumentowanie ustaleń. Implementacja i przegląd powstają
z pomocą narzędzi AI.

## Co znajduje się w publicznym repozytorium

Punktem odniesienia dla kodu jest rewizja
[`e483e76`](https://github.com/aldladla/pl-honeynet-observer/commit/e483e76f8ef184596f56a2276153d4a37a38f2b9)
z 7 września 2026. Publiczna wersja zawiera m.in. normalizację logów Cowrie,
korelację sesji, detekcje, kolejkę metadanych plików, panel FastAPI, konfigurację
Grafany oraz narzędzia izolacji i monitorowania sensora.

Ta aktualizacja dotyczy dokumentacji. Funkcje opisane poniżej jako rozwojowe
nie są przez nią dodawane do publicznego kodu. Polecenia uruchomienia
w głównym README dotyczą opublikowanej wersji. Zrzuty w README przedstawiają
wersję operatora: główny zrzut pochodzi z 21 października, a obrazy w sekcjach
rozwijanych z 7 września. Nie wszystkie widoczne funkcje są odtwarzalne
z publicznego kodu.

## Wyniki i wdrożenie z 21 października

- Przeanalizowano 11 380 sesji i 165 534 zdarzenia VPS, z odcięciem osi według
  `last_seen` każdej sesji. Spis zbierano między 14:05:01 a 14:06:44 UTC;
  nie jest to atomowy snapshot.
- Pogłębiono trzy dochodzenia: powtarzalny fragment transferu, materiał
  `authorized_keys` i zakończenia około 15 sekund po ostatnim wejściu klienta.
- W głównej sprawie znaleziono 2 132 pary równoległych sesji rozpoznania
  i transferu; sesje rozpoznania mają identyczny prefiks 13 komend.
- Wykonano 14 lokalnych transferów własnych danych przez SCP/SFTP i porównano
  zapisane bajty ze znanym wzorcem. Udokumentowano różnice przy limicie 16 MiB.
- Na VPS wdrożono filtr sposobu zapisu pliku, jawny zakres odczytu kolejki,
  poprawki walidacji metadanych HTTP i rozpoznawanie sondowania konfiguracji.
  Usunięto ciche ograniczenie kolejki do 10 000 obserwacji; obecny limit
  50 000 jest jawny, a ucięcie sygnalizowane.
- W środowisku operatora przeszło 425 testów Python i 58 testów interfejsu.
  Ten wynik dotyczy wersji roboczej, nie publicznego klonu repozytorium.
- Eksperyment A/B persony NAS przygotowano i sprawdzono lokalnie; nie został
  uruchomiony na VPS.

Podczas wdrożenia wystąpiła przerwa w zbieraniu ruchu trwająca około 54 minuty.
Sensory i kontrole zdrowia przywrócono; lukę trzeba wyłączać z czasu ekspozycji.
Zamrożony zbiór opisany powyżej kończy się przed tą przerwą.

[Studium przypadku, metoda i ograniczenia](case-study-parallel-sessions-2026-10.md).

## Aktualny stan prac poza publiczną wersją kodu

| Obszar | Wykonana praca | Zakres |
| --- | --- | --- |
| Sensory SSH i HTTP | Rozbudowa Cowrie oraz persony NAS przez HTTP; wspólne zbieranie metadanych | Wersja operatora; historia prac dokumentuje wdrożenia na VPS |
| Utrzymanie | Rozbudowa monitorów, kontroli bazowej konfiguracji, bramek firewalla i awaryjnego zamykania wejść sensorów | Wersja operatora |
| Panel analityczny | Przegląd nowych sygnałów, grupowanie technicznych powiązań sesji, karty plików, filtr sposobu zapisu i jawny zakres odczytu | Wersja operatora; poprawki kolejki wdrożone na VPS 21 października |
| Transfery plików | Odróżnianie SCP od SFTP, porównywanie rozmiarów i jawna ocena kompletności | Wersja rozwojowa; historyczne dane zachowują swoje ograniczenia |
| Rekonstrukcja sesji | Rozdzielenie komend odbioru SCP, prób poleceń powłoki i emulowanych odpowiedzi | Wersja operatora |
| Profile porównawcze | Przygotowanie profili H0neytr4p i ElasticPot oraz adapterów do lokalnych ćwiczeń | Lokalne laby; bez deklaracji publicznego wdrożenia |
| Analiza statyczna | Raporty z analizy wybranych przechwyconych plików w odłączonej VM | Osobny, odizolowany lab; bez uruchamiania próbek |

To podsumowanie dokumentacji, kodu roboczego i zapisanych wyników prac.
Nie jest bieżącym pomiarem dostępności VPS ani zapewnieniem o bezprzerwowej pracy.

## Jak przebiega analiza

```text
sensor SSH / HTTP
  -> logi i metadane
  -> normalizacja i baza danych
  -> sesje, detekcje i grupy technicznych powiązań
  -> karta analizy oraz udokumentowane ustalenia
```

Panel pomaga przejść od powtarzalnego sygnału do konkretnej sesji i materiału
źródłowego. Grupy powstają na podstawie m.in. identycznych SHA-256 i wzorców
poleceń. Podobieństwo sesji nie stanowi dowodu wspólnego sprawcy ani atrybucji.

Analiza transferów rozdziela zapis pliku, zamknięcie transferu i potwierdzenie
kompletności. W rekonstrukcji odróżniane są także polecenia techniczne transportu
od prób uruchomienia programu. Emulowany kod odpowiedzi honeypota nie dowodzi
wykonania przesłanej zawartości.

## Rozszerzenie dochodzenia około 15 sekund

W analizie zapisanej 19 października jeden hash występował w 31 sesjach jednego
pseudonimizowanego źródła. Powtarzała się sekwencja rozpoznania hosta,
transferu, próby nadania uprawnień, próby uruchomienia ścieżki i sprzątania.
Po ostatnim znaczniku połączenia kończyły się po 14,90-15,05 sekundy.

To obserwacja z określonego wycinka historii, a nie aktualny licznik ruchu.
Zapis nie rozstrzygał, która strona zamykała połączenie. Kompletność transferów
pozostawała niepotwierdzona, a odpowiedzi na próby uruchomienia były emulowane.
Pogłębienie z 21 października objęło 89 sesji tego hasha i jednego źródła.
86 z 89 kończyło się po 14,90–15,05 s od ostatniej komendy; mediana wyniosła
14,991596 s. Od odpowiedzi `safe-exec` do zamknięcia mediana wynosiła
15,929668 s, a od przechwycenia 16,197640 s. To różne punkty odniesienia.

Własne lokalne połączenie pozostało aktywne po 18 sekundach bezczynności.
Ten test dotyczy sprawdzonej lokalnej konfiguracji, nie ustala historycznego
inicjatora zamknięć VPS. Hipoteza oczekiwania na odpowiedź wymaga kolejnego
kontrolowanego testu. Nie potwierdzono wykonania malware ani doręczenia
wyniku końcowej komendy klientowi.

## Umiejętności rozwijane w projekcie

- Utrzymanie usług Linux i kontenerów Docker na własnym VPS.
- Diagnostyka komunikacji, zbierania logów i jakości telemetrii.
- Kontrola konfiguracji, monitoring i dokumentowanie zmian.
- Izolacja środowisk oraz ograniczenia ruchu wychodzącego.
- Analiza chronologii sesji i rzetelne oddzielanie faktów od hipotez.
- Python, FastAPI, SQLAlchemy, PostgreSQL i praca z Git.

## Kolejny etap publikacji

Kod rozszerzeń wymaga osobnego przeglądu przed udostępnieniem: sprawdzenia
kompletności zależności, danych przykładowych, testów oraz dokumentacji
uruchomienia. Nowe funkcje nie są jeszcze odtwarzalne z samego publicznego
repozytorium. Aktualizacja dokumentacji nie zastępuje publikacji kodu.

Publiczny opis nie zawiera surowych logów, haseł, adresów sensorów ani próbek.
Zasady projektu opisują [bezpieczeństwo](safety.md),
[prywatność](privacy.md) i [obsługa próbek](sample-handling.md).

### Znane ograniczenie testów opublikowanej wersji

Przy sprawdzaniu świeżej kopii repozytorium dwa istniejące testy wskazują
na skrypty z ignorowanego katalogu `work/`: test wdrożenia Grafany i test
przygotowania VM do analizy statycznej. Te skrypty nie są częścią publicznej
wersji, więc pełny zestaw testów nie jest jeszcze odtwarzalny z samego klonu.
Włączenie odpowiednio przygotowanych skryptów do publicznej struktury
lub zmiana zakresu tych testów wymaga osobnej aktualizacji kodu.
