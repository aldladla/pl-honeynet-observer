# Prywatny panel Grafana

Grafana jest gotową warstwą obserwacyjną nad istniejącym pipeline'em. Nie
zastępuje collectora, bazy ani szczegółowego panelu sesji. Pokazuje przegląd
ostatnich kampanii i zachowań, a kliknięcie identyfikatora sesji prowadzi do
widoku dokładnych komend w aplikacji FastAPI.

## Granica prywatności

Grafana nie łączy się kontem aplikacji i nie ma dostępu do `public.events`.
Jednorazowy kontener `grafana-bootstrap` tworzy konto `grafana_reader` oraz dwa
widoki w schemacie `grafana_safe`:

- `event_stream` — czas, sensor, sesja i typ zdarzenia;
- `session_summary` — wyłącznie agregaty sesji i uproszczony poziom ryzyka.

Widoki nie zawierają surowego IP, portu źródłowego, hasła, URL-a, komendy,
`data` ani `source_event`. Konto ma wyłącznie `SELECT` do tych widoków. To
świadoma redukcja danych: pełny materiał dowodowy pozostaje w prywatnym panelu
śledczym.

## Uruchomienie

W `.env` ustaw niezależne losowe wartości:

```text
GRAFANA_DB_PASSWORD=<losowa wartość 24+ znaków>
GRAFANA_ADMIN_USER=honeynet-admin
GRAFANA_ADMIN_PASSWORD=<inna losowa wartość 24+ znaków>
GRAFANA_PORT=3000
GRAFANA_ROOT_URL=http://127.0.0.1:3000
```

Następnie:

```powershell
docker compose --profile lab up -d grafana-bootstrap grafana
docker compose --profile lab ps grafana
```

Lokalnie panel jest pod `http://127.0.0.1:3000`. Na VPS port jest związany
wyłącznie z loopbackiem. Uruchom na swoim komputerze osobny tunel:

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" -p <ADMIN_SSH_PORT> `
  -N -L 13000:127.0.0.1:3000 ubuntu@<VPS_PUBLIC_IP>
```

Po wpisaniu passphrase okno pozostaje bez komunikatu — to prawidłowe zachowanie.
Otwórz `http://127.0.0.1:13000/d/pl-honeynet-overview` i zaloguj się danymi
`GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD` z prywatnego `.env` na VPS.
Na VPS `GRAFANA_ROOT_URL` powinien mieć wartość `http://127.0.0.1:13000`, czyli
adres widziany przez przeglądarkę po zestawieniu tunelu.

Istniejący panel śledczy nadal korzysta z osobnego tunelu na port `18000`.
Grafana nie jest i nie powinna być dostępna przez publiczny port VPS.
