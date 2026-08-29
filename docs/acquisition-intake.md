# Intake kandydatów do pozyskania

## Co działa 24/7

Collector zapisuje zdarzenia `file_download_requested`, gdy Cowrie widzi próbę
pobrania z zewnętrznej lokalizacji. Prywatny panel grupuje te obserwacje po
lokalizacji, ale zwraca jedynie kluczowany identyfikator kandydata. Dzięki temu
można zauważyć powtarzającą się kampanię bez ujawniania lub odwiedzania URL-a.

Intake jest projekcją istniejącej telemetrii. Nie wymaga osobnego procesu
sieciowego, działa tak długo jak collector i baza oraz podlega tej samej retencji.

## Stany, których nie wolno mylić

- `awaiting_manual_review` — zarejestrowano zamiar pobrania;
- `content_retrieved=false` — system nie ma bajtów wskazanego pliku;
- `fetcher_status=disabled` — żaden worker nie łączy się ze źródłem;
- `artifact_captured` — Cowrie ma metadane pliku przesłanego bezpośrednio albo
  utworzonego w emulowanym systemie; nadal nie oznacza to wykonania próbki.

API:

- `GET /api/dashboard/acquisition-candidates` — deduplikowana kolejka decyzji;
- `GET /api/dashboard/acquisition-candidates/{candidate_id}/manifest` —
  allowlistowany manifest obserwacji bez URL-a i zawartości.

Identyfikator jest HMAC-em lokalizacji z kluczem pseudonimizacji. Nie należy go
traktować jak hash próbki. Manifest nie zawiera surowego IP, sekretów,
`source_event` ani lokalizacji sieciowej.

## Docelowy fetcher — jeszcze niewłączony

Jeśli operator później zatwierdzi rozszerzenie polityki, część pracująca stale
powinna ograniczać się do kolejki. Worker pobierający powinien być jednorazowy:

1. powstaje dla pojedynczego, ręcznie zatwierdzonego zadania;
2. ma dostęp wyłącznie do jednego celu i jednego protokołu;
3. stosuje limity czasu, rozmiaru i przekierowań;
4. zapisuje strumień jako niewykonywalny blob, oblicza SHA-256 i niczego nie
   uruchamia ani nie rozpakowuje;
5. przekazuje blob do oddzielnej kwarantanny i zostaje zniszczony.

Fetcher nie może działać w sieci sensora, posiadać kluczy VPS, bazy lub panelu ani
mieć routingu do sieci prywatnych. Włączenie wymaga zmiany zasad projektu oraz
spełnienia całej listy w `sample-handling.md`. Pierwszy test musi używać
nieszkodliwego pliku z kontrolowanej domeny testowej, nigdy danych z aktywnej
kampanii.
