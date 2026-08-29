# Kolejka metadanych artefaktów

## Cel

Kolejka pozwala analitykowi zauważyć, że sensor zarejestrował artefakt, porównać
powtarzające się obserwacje i przygotować bezpieczny manifest do dalszego triage.
Nie jest magazynem próbek i nie udostępnia bajtów pliku.

Zdarzenia `artifact_captured` są grupowane po pełnym SHA-256. Jedna karta pokazuje
czas pierwszej i ostatniej obserwacji, liczbę sesji i sensorów, znormalizowane nazwy,
rozmiary, typy MIME oraz klasyfikację pochodzenia. Hash ani nazwa nie dowodzą, że
plik jest złośliwy.

## API prywatnego panelu

- `GET /api/dashboard/artifacts` — deduplikowana kolejka metadanych;
- `GET /api/dashboard/artifacts/{artifact_id}/manifest` — manifest pojedynczego
  skrótu SHA-256.

Manifest zawiera wyłącznie pola z jawnej allowlisty. Źródłowe IP jest
pseudonimizowane. Nie są zwracane: `source_event`, hasło, surowe IP, URL pobrania,
lokalizacja próbki ani zawartość pliku. Endpoint nie wykonuje połączenia sieciowego.

Przycisk **Eksportuj manifest** zapisuje odpowiedź JSON w przeglądarce operatora.
Nazwa pliku zawiera tylko skrócony SHA-256. Pole `content_included` zawsze ma wartość
`false`, a `safe_for_static_lab` — `false`, ponieważ sam manifest nie zastępuje
decyzji operatora i weryfikacji procedury.

## Retencja

Kolejka jest projekcją istniejących rekordów zdarzeń, a nie osobnym magazynem.
Obowiązuje ją ta sama maksymalna retencja 30 dni opisana w `privacy.md`. Gdy ostatnie
zdarzenie danego SHA-256 zostanie usunięte przez proces retencji, artefakt znika z
kolejki. Wyeksportowany manifest jest osobną kopią operatora i należy go usunąć lub
zarchiwizować zgodnie z regułami sprawy.

## Granica obecnego etapu

Ten etap nie dodaje pobierania, eksportu ani kwarantanny próbek. Jeśli kiedyś
zostanie zatwierdzone przechowywanie zawartości, wymaga ono oddzielnej implementacji
zgodnej z `sample-handling.md`: szyfrowanego magazynu, rejestru operacji, limitów,
retencji próbki oraz ręcznej autoryzacji transferu do izolowanego laboratorium.
