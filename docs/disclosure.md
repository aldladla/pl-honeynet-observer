# Skoordynowane ujawnianie wyników

## Co podlega tej procedurze

Log honeypota może pokazać próbę użycia znanej techniki, błędną konfigurację, aktywną kampanię albo potencjalnie nieznaną podatność. Sam payload, banner, adres źródłowy czy udane zachowanie w emulacji **nie są jeszcze dowodem nowej podatności ani tożsamości atakującego**.

Nie testujemy hipotezy na cudzym systemie. Potwierdzenie wykonujemy wyłącznie w naszym laboratorium, na legalnie pozyskanej wersji oprogramowania i w zakresie niezbędnym do zrozumienia ryzyka.

## Triage przed kontaktem

1. Nadaj prywatny identyfikator sprawie i zapisz czas UTC, sensor oraz wersję środowiska.
2. Oddziel obserwacje od wniosków. Zaznacz poziom pewności i alternatywne wyjaśnienia.
3. Sprawdź, czy zachowanie wynika z emulacji honeypota, znanej podatności, błędu konfiguracji albo fałszywego pozytywu.
4. Usuń z materiału sekrety, dane ofiar, niepotrzebne IP i surowe próbki. Wymieniaj próbkę tylko po uzgodnieniu bezpiecznego kanału.
5. Oceń wpływ defensywnie: podatne wersje, warunki wstępne, skutek, oznaki aktywnego wykorzystania i możliwe obejście — bez publikowania gotowej instrukcji ataku.
6. Zapisz osobę prowadzącą, kanał kontaktu i każdą zmianę statusu.

## Kolejność kontaktu

1. Najpierw kontaktujemy właściciela systemu lub producenta przez opublikowany kanał security/CVD. Sprawdzamy jego `security.txt` i politykę disclosure.
2. Gdy kontaktu brakuje, jest utrudniony, sprawa obejmuje wiele podmiotów albo wymaga zaufanego pośrednika, zgłaszamy ją do właściwego CSIRT-u. Dla wielu polskich podmiotów i w razie wątpliwości punktem startowym może być [CVD CERT Polska / CSIRT NASK](https://cert.pl/cvd/).
3. Incydent lub aktywną kampanię zgłaszamy kanałem incydentowym, nie udajemy, że jest to podatność produktu. CERT Polska udostępnia formularz na [incydent.cert.pl](https://incydent.cert.pl/).
4. Jeżeli materiał dotyczy infrastruktury krytycznej, administracji lub obronności, dobór właściwego CSIRT-u konsultujemy zgodnie z zakresem opisanym przez CERT Polska.

## Minimalna treść zgłoszenia

- dane kontaktowe i preferowany bezpieczny kanał;
- krótkie podsumowanie oraz poziom pewności;
- produkt, wersja i konfiguracja laboratorium;
- kroki reprodukcji ograniczone do środowiska kontrolowanego;
- oczekiwany i zaobserwowany wynik;
- potencjalny wpływ i możliwe mitigacje;
- oś czasu, hashe artefaktów oraz zredagowane logi;
- informacja o aktywnym wykorzystaniu, jeśli potwierdzona;
- proponowany kolejny termin kontaktu i prośba o potwierdzenie odbioru.

Nie wysyłamy próbki jako zwykłego załącznika i nie umieszczamy jej w publicznym repozytorium.

## Koordynacja i publikacja

- Nie publikujemy szczegółów umożliwiających wykorzystanie przed zakończeniem uzgodnionego procesu. CERT Polska prosi o wcześniejszy kontakt z właścicielem/dostawcą oraz o niepublikowanie przed zakończeniem obsługi.
- Terminy ustalamy z odbiorcą lub koordynatorem, uwzględniając dostępność poprawki, dystrybucję i aktywne wykorzystanie. Nie przyjmujemy automatycznie jednego terminu dla wszystkich spraw.
- Co najmniej co 7–14 dni aktualizujemy prywatną oś czasu. Brak odpowiedzi eskalujemy do właściwego CSIRT-u zamiast samodzielnie ujawniać dane ofiar.
- Publiczny raport opisuje metodę, wpływ, wersje, mitigację, oś czasu i podziękowania uzgodnione ze stronami. Usuwa dane osobowe, infrastrukturę ofiar, działające sekrety i niepotrzebny kod eksploatujący.
- Przed publikacją dajemy producentowi/koordynatorowi możliwość sprawdzenia faktów, bez przekazywania mu prawa do ukrywania prawdziwych wyników.

## Sytuacje pilne

Przy wiarygodnym aktywnym wykorzystaniu lub bezpośrednim zagrożeniu ludzi i usług nie publikujemy pochopnie. Ograniczamy dystrybucję, zabezpieczamy materiał, oznaczamy sprawę jako pilną i kontaktujemy producenta oraz właściwy CSIRT. Priorytetem jest mitigacja i powiadomienie narażonych podmiotów bez ujawniania informacji, które zwiększą skalę szkody.

## Rejestr decyzji

Każda sprawa ma: status (`triage`, `zgłoszona`, `potwierdzona`, `naprawa`, `gotowa do publikacji`, `zamknięta`), właściciela, odbiorców, terminy, decyzje redakcyjne i podstawę zamknięcia. Publikację zatwierdzają dwie osoby: prowadzący techniczny i osoba odpowiedzialna za bezpieczeństwo/prywatność.
