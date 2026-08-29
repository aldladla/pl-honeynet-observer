# Metodologia detekcji

Silnik analizuje wyłącznie zwalidowane metadane sesji. Nie wykonuje komend,
nie otwiera artefaktów i nie łączy się z adresami widocznymi w telemetrii.
Wyniki są obliczane deterministycznie podczas budowania widoku dashboardu.

## Pierwszy katalog zachowań

| Kategoria | Przykładowy sygnał | Interpretacja |
| --- | --- | --- |
| `system_discovery` | `uname`, `id`, `ps`, `/etc/os-release` | zwykły rekonesans systemu |
| `network_discovery` | `ip addr`, `netstat`, `route`, `resolv.conf` | rozpoznanie sieci i połączeń |
| `honeypot_probe` | `cowrie`, `kippo`, `/.dockerenv`, `/proc/1/cgroup`, `systemd-detect-virt` | próba znalezienia śladów emulacji lub konteneryzacji |
| `payload_delivery` | `curl`, `wget`, `tftp`, zdarzenie pobrania | próba dostarczenia zasobu |
| `execution_preparation` | `chmod +x`, `base64 -d`, `nohup`, `crontab` | przygotowanie wykonania lub trwałości |
| `credential_attack` | co najmniej cztery błędne logowania w sesji | lokalna seria prób uwierzytelnienia |
| `artifact_captured` | zdarzenie metadanych artefaktu | najsilniejszy sygnał w obecnym MVP |

Każda detekcja zawiera kategorię, poziom, pewność, opis i maksymalnie pięć
bezpiecznych elementów dowodowych. Hasła, surowe IP i pełny `source_event` nie są
częścią wyniku.

## Dlaczego osobna detekcja fingerprintingu

Cowrie emuluje system plików i część komend. Oficjalna dokumentacja zaznacza, że
nie wszystkie komendy są implementowane, a domyślne elementy systemu mogą ułatwić
identyfikację instalacji. Projekt Cowrie wcześniej poprawiał również zachowania
protokołu pozwalające narzędziom rozpoznać honeypot. Dlatego traktujemy próby
sprawdzania emulatora jako wartościową telemetrię, a nie tylko problem do ukrycia.

Źródła:

- [Cowrie FAQ](https://docs.cowrie.org/en/latest/FAQ.html)
- [Zmiana emulowanego systemu plików](https://docs.cowrie.org/en/stable/HONEYFS.html)
- [Historia zmian Cowrie](https://github.com/cowrie/cowrie/blob/main/CHANGELOG.rst)

## Ograniczenia

- Dopasowanie reguły nie dowodzi, że bot poprawnie rozpoznał honeypot.
- Brak dopasowania nie oznacza bezpiecznej sesji.
- Pojedyncze polecenie `uname` nie jest oznaczane jako fingerprinting honeypota.
- Obecny brute force działa wewnątrz sesji. Korelacja źródła między sesjami będzie
  kolejnym etapem.
- Reguły sygnaturowe mogą zostać ominięte przez kodowanie i nietypową składnię;
  później uzupełnimy je normalizacją poleceń i detekcją sekwencji.
