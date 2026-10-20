# Stan projektu - 20 października 2026

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
stan rozwojowego panelu z 7 września, a nie aktualny interfejs październikowy.

## Aktualny stan prac poza publiczną wersją kodu

| Obszar | Wykonana praca | Zakres |
| --- | --- | --- |
| Sensory SSH i HTTP | Rozbudowa Cowrie oraz persony NAS przez HTTP; wspólne zbieranie metadanych | Wersja operatora; historia prac dokumentuje wdrożenia na VPS |
| Utrzymanie | Rozbudowa monitorów, kontroli bazowej konfiguracji, bramek firewalla i awaryjnego zamykania wejść sensorów | Wersja operatora |
| Panel analityczny | Przegląd nowych sygnałów, grupowanie technicznych powiązań sesji, karty plików i notatki z analizy | Wersja rozwojowa; historia prac dokumentuje wdrożenia części zmian na VPS |
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

## Przykład udokumentowanego dochodzenia

W analizie zapisanej 19 października jeden hash występował w 31 sesjach jednego
pseudonimizowanego źródła. Powtarzała się sekwencja rozpoznania hosta,
transferu, próby nadania uprawnień, próby uruchomienia ścieżki i sprzątania.
Po ostatnim znaczniku połączenia kończyły się po 14,90-15,05 sekundy.

To obserwacja z określonego wycinka historii, a nie aktualny licznik ruchu.
Zapis nie rozstrzygał, która strona zamykała połączenie. Kompletność transferów
pozostawała niepotwierdzona, a odpowiedzi na próby uruchomienia były emulowane.
Hipoteza timeoutu wymaga odtworzenia w lokalnym labie; na tej podstawie
nie można deklarować wykonania malware ani reakcji klienta na odpowiedź sensora.

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
