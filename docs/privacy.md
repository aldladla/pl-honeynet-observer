# Prywatność, minimalizacja i retencja danych

## Założenie

Telemetria może zawierać adresy IP, znaczniki czasu, identyfikatory urządzeń, nazwy użytkowników, wpisane ciągi i treść poleceń. Adres IP lub połączenie kilku pól może w danym kontekście stanowić dane osobowe; takie podejście jest zgodne z materiałami UODO odwołującymi się do orzecznictwa TSUE. Traktujemy więc surowe logi jak dane chronione, nawet jeśli nie znamy konkretnej osoby.

To jest polityka techniczna projektu, a nie porada prawna. Przed publicznym zbieraniem danych właściciel wdrożenia powinien ustalić rolę administratora, cel, podstawę prawną, obowiązki informacyjne, transfery i procedurę praw osób z kompetentnym prawnikiem lub IOD/DPO.

## Cel i ograniczenie zakresu

Dozwolony cel: wykrywanie i opisywanie zautomatyzowanych prób naruszenia naszych sensorów, budowa zagregowanych statystyk oraz tworzenie defensywnych wskaźników i reguł.

Nie wykorzystujemy telemetrii do identyfikowania osób, profilowania niezwiązanego z bezpieczeństwem, publikowania list „atakujących” ani podejmowania odwetu. Geolokalizacja i ASN są przybliżonym kontekstem sieciowym, a nie dowodem pochodzenia sprawcy.

## Dane zbierane w MVP

| Pole | Po co | Forma domyślna |
| --- | --- | --- |
| czas UTC, typ zdarzenia, sensor i sesja | odtworzenie sekwencji | pełna |
| źródłowy IP i port | korelacja krótkoterminowa/abuse | surowe tylko w warstwie ograniczonej |
| docelowa usługa/port | klasyfikacja | pełna |
| wynik logowania | statystyka prób | pełna |
| nazwa użytkownika i sekret | analiza słowników | po ingest natychmiastowa redakcja lub keyed hash; nigdy w raporcie |
| polecenie/URL | analiza zachowania | wersja zredagowana; bez automatycznego odwiedzania |
| payload | poza zakresem MVP | nie pobieramy |

Nie zbieramy danych, których nie potrafimy powiązać z zapisanym celem. Debug logging jest domyślnie wyłączony w środowisku publicznym.

### Zabezpieczenia egzekwowane przez kod

- Adapter Cowrie redaguje znane pola sekretów przed utworzeniem zdarzenia.
- Repozytorium powtarza redakcję jako ostatnia granica przed zapisem, także dla
  danych importowanych inną ścieżką niż Cowrie.
- Maskowane są m.in. hasła, tokeny, nagłówki autoryzacyjne, dane logowania w URL
  oraz popularne flagi CLI zawierające sekrety.
- Raport Markdown nie eksportuje `source_event`, surowego IP, hasła ani nazwy
  użytkownika.
- Opcjonalne GeoIP i ASN są obliczane lokalnie z plików MMDB. Dashboard otrzymuje
  wyłącznie allowlistę pól kontekstu sieciowego, nigdy surowy rekord dostawcy
  bazy. Brak bazy nie uruchamia zapytania do zewnętrznego API.

Redakcja wzorcami nie daje matematycznej gwarancji rozpoznania dowolnego sekretu.
Dlatego dostęp do bazy pozostaje ograniczony, obowiązuje retencja, a publikowany
eksport nadal wymaga kontroli człowieka.

## Rozdzielenie i pseudonimizacja

- Surowe IP przechowujemy osobno od danych analitycznych, z dostępem tylko dla operatora incydentów.
- Pipeline nadaje rotowany identyfikator pseudonimowy przez HMAC z sekretem spoza bazy. Zwykły SHA-256 adresu IP nie wystarcza, ponieważ przestrzeń adresów jest łatwa do przeszukania.
- Raporty publiczne pokazują agregaty. Gdy adres jest niezbędnym IOC dla obrony, publikację zatwierdza człowiek po ocenie szkody, aktualności i fałszywych atrybucji.
- Nazwy użytkowników, hasła, tokeny, klucze i dane wyglądające na osobowe są maskowane przed indeksowaniem i raportowaniem.
- Dostęp jest nadawany według roli, rejestrowany i przeglądany co najmniej kwartalnie. Współdzielone konta są zabronione.

## Domyślna retencja

Poniższe wartości są technicznym maksimum startowym, nie automatycznym uzasadnieniem prawnym:

| Klasa | Retencja | Koniec okresu |
| --- | ---: | --- |
| surowe zdarzenia z pełnym IP | 30 dni | automatyczne, nieodwracalne usunięcie |
| znormalizowane zdarzenia z pseudonimem | 90 dni | anonimizacja do agregatu lub usunięcie |
| dane logowania i treści po redakcji | 30 dni | usunięcie; dłużej tylko udokumentowany przypadek |
| agregaty bez możliwości identyfikacji | 24 miesiące | przegląd przydatności i ponowna anonimizacja/usunięcie |
| próbki | zgodnie z `sample-handling.md`; domyślnie brak w MVP | — |

„Legal hold” lub zachowanie dowodów musi mieć właściciela, uzasadnienie, zakres i termin następnego przeglądu. Nie wolno bezterminowo wyłączać retencji.

## Publikacja i udostępnianie

Przed eksportem lub publikacją wykonujemy kontrolę: brak pełnych IP bez uzasadnienia IOC, brak sekretów, danych ofiar, identyfikatorów sesji możliwych do połączenia z surowymi logami i URL-i zawierających tokeny. Udostępniamy najmniejszy potrzebny fragment przez kanał uzgodniony z odbiorcą; nie wysyłamy surowych zbiorów jako publicznych załączników.

Każdy dostęp lub eksport danych do zewnętrznego procesora wymaga przeglądu umowy, lokalizacji przetwarzania, retencji i mechanizmu usunięcia.

## Obsługa żądań i naruszeń

Projekt powinien mieć kontakt privacy/security oraz rejestr: źródło danych, cel, odbiorców, terminy usuwania i operacje na danych. Żądania dotyczące danych przekazujemy administratorowi/koordynatorowi prywatności; nie odpowiadamy pochopnie na podstawie samego adresu IP.

Podejrzenie wycieku oznacza natychmiastowe wstrzymanie eksportów, ograniczenie dostępu, zachowanie osi czasu, rotację sekretów pseudonimizacji i ocenę obowiązków przez właściwą osobę. Nie obiecujemy ani nie wykluczamy zgłoszenia organowi bez analizy konkretnego przypadku.

## Punkty odniesienia

- [RODO, art. 5 — minimalizacja danych i ograniczenie przechowywania](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [UODO — informacje o adresach IP i danych o ruchu](https://uodo.gov.pl/pl/138/3850)
- [UODO — tekst RODO i akty towarzyszące](https://uodo.gov.pl/pl/404)
