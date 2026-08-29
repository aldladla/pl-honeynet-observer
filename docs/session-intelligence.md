# Session Intelligence

Moduł rekonstruuje zachowanie wyłącznie ze zwalidowanych metadanych Cowrie.
Nie wykonuje poleceń, nie otwiera artefaktów i nie łączy się z adresami obecnymi
w telemetrii.

## Profil klienta SSH

Adapter normalizuje `cowrie.client.version` oraz `cowrie.client.kex`. Zapisuje
wersję klienta, HASSH i listy algorytmów negocjacji. Są to cechy sesji, a nie
tożsamość człowieka ani samodzielny dowód wspólnego operatora.

## Pochodzenie artefaktu

| Wartość | Znaczenie |
| --- | --- |
| `direct_upload` | Cowrie zarejestrowało upload SCP/SFTP |
| `remote_fetch` | artefakt wiąże się ze zdalnym URL-em |
| `shell_redirect` | plik powstał przez mechanizm emulowanej powłoki |
| `stdin_capture` | zawartość została przechwycona ze standardowego wejścia |
| `unknown` | telemetria nie pozwala rozstrzygnąć pochodzenia |

Klasyfikacja roli (`key`, `config`, `script`, `archive`, `executable`, `unknown`)
wynika wyłącznie z nazwy pliku. Nie oznacza analizy zawartości ani potwierdzenia,
że plik jest złośliwy.

## Stany łańcucha

| Stan | Znaczenie dowodowe |
| --- | --- |
| `observed` | sensor bezpośrednio zapisał dane działanie lub rezultat |
| `attempted` | komenda pokazuje zamiar, ale nie potwierdza skutku |
| `contained` | Cowrie jawnie zapisało niepowodzenie albo odrzucenie działania |
| `unknown` | istnieje kontekst etapu, lecz brakuje dowodu wyniku |

Łańcuch może zawierać dostęp, rozpoznanie, przygotowanie zasobów, transfer,
wykonanie, trwałość i czyszczenie. Brak etapu oznacza brak wystarczających danych,
a nie dowód, że działanie nie wystąpiło.

## Granice wnioskowania

- Wprowadzenie komendy do Cowrie nie dowodzi wykonania jej na prawdziwym hoście.
- `file_download.failed` potwierdza nieudaną próbę w emulatorze, niekoniecznie
  pakiet odrzucony przez hostowy firewall.
- Hash i nazwa pliku nie dowodzą złośliwości artefaktu.
- HASSH może grupować podobne klienty, ale nie powinien samodzielnie łączyć sesji
  w jedną kampanię.
