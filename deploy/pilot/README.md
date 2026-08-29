# Pakiet bezpiecznego pilota Ubuntu VPS

Ten katalog przygotowuje monitoring i odcięcie **własnego** sensora. Nie został
uruchomiony na żadnym serwerze i domyślnie nie publikuje portu. Najpierw obowiązuje
pełna bramka z `docs/safety.md`, regulamin dostawcy oraz oddzielny kanał zarządzania.

## Obsługiwany wariant

- dedykowany VPS z Ubuntu i bez innych aplikacji;
- Docker Engine z domyślnym backendem zapory `iptables`;
- publiczny wyłącznie sensor IPv4; panel nadal `127.0.0.1:8000`;
- administracja niezależnym SSH z kluczem i zaporą dostawcy;
- zewnętrzna zapora dostawcy jako dodatkowa warstwa.

Backend `nftables` Dockera nie jest jeszcze obsługiwany przez te skrypty. Nie ma w
nim łańcucha `DOCKER-USER`, a jego obsługa jest nadal eksperymentalna. Skrypt w
takim środowisku zakończy się błędem zamiast otworzyć sensor.

## Dlaczego nie samo UFW

Docker kieruje ruch do opublikowanych portów przed łańcuchami używanymi przez
UFW. Dlatego gate działa w oficjalnie przeznaczonym do reguł operatora łańcuchu
`DOCKER-USER` i dopasowuje oryginalny port przez conntrack. Nie modyfikujemy
łańcuchów tworzonych wewnętrznie przez Dockera.

Publiczna bramka korzysta z dedykowanej sieci `sensor-ingress`
(`172.30.255.0/28`). Pierwsza reguła operatora kieruje nowe połączenia
wychodzące z tej podsieci do `HONEYNET-EGRESS`, gdzie są bezwarunkowo odrzucane.
Odpowiedzi na połączenia rozpoczęte przez klientów sensora pozostają dozwolone.
Prywatne połączenie bramki z Cowrie odbywa się osobną siecią `sensor-lab`.

## Instalacja plików — nadal bez publikacji

Poniższe polecenia są przeznaczone dopiero dla dedykowanego VPS-a. Repozytorium
powinno znajdować się w `/opt/pl-honeynet-observer`, a prywatny `.env` mieć tryb
`0600` i początkowo zawierać:

```dotenv
SENSOR_BIND_IP=127.0.0.1
SENSOR_PUBLIC_PORT=2222
PUBLICATION_APPROVED=no
```

Instalacja jednostek nie otwiera portu — gate ustawia `DROP`:

```bash
sudo install -m 0750 deploy/pilot/honeynet-firewall-gate /usr/local/sbin/
sudo install -m 0750 deploy/pilot/honeynet-kill-switch /usr/local/sbin/
sudo install -m 0750 deploy/pilot/honeynet-monitor /usr/local/sbin/
sudo install -m 0750 deploy/pilot/honeynet-sensor-open /usr/local/sbin/
sudo install -m 0750 deploy/pilot/honeynet-preflight /usr/local/sbin/
sudo install -m 0750 deploy/pilot/honeynet-baseline /usr/local/sbin/
sudo install -m 0750 deploy/pilot/honeynet-update-geoip /usr/local/sbin/
sudo install -m 0644 deploy/pilot/systemd/*.service /etc/systemd/system/
sudo install -m 0644 deploy/pilot/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeynet-firewall.service
```

## Lokalny kontekst kraju i ASN

Aktualizacja pobiera wyłącznie ogólne bazy `server-country` i `origin-asn` wraz
z checksumami. Nie wysyła żadnych adresów z logów do zewnętrznego API:

```bash
sudo /usr/local/sbin/honeynet-update-geoip
docker compose --profile lab up -d --build app
```

Bazy pochodzą z projektu `sapics/ip-location-db`, są publikowane w PDDL i
montowane do kontenera aplikacji tylko do odczytu. Wynik opisuje infrastrukturę
sieciową, nie miejsce pobytu ani tożsamość operatora kampanii.

## Próba przed publikacją

1. Zostaw `SENSOR_BIND_IP=127.0.0.1` i `PUBLICATION_APPROVED=no`.
2. Uruchom stos: `docker compose --profile lab up -d --build`.
3. Sprawdź `docker compose --profile lab ps` i lokalny panel przez tunel SSH.
4. Potwierdź, że `honeynet-firewall-gate status` pokazuje `CLOSED`.
5. Uruchom kill switch i sprawdź, że logi oraz wolumeny nadal istnieją:

```bash
sudo systemctl start honeynet-kill-switch.service
docker compose --profile lab ps --all
docker volume ls --filter name=pl-honeynet-observer
```

Nie używamy `down -v`, `docker rm -v` ani `prune` w procedurze incydentowej.

## Jawne uruchomienie publicznego pilota

Dopiero po wpisaniu `PASS` dla każdego punktu w `docs/safety.md`:

1. ustaw w `.env` konkretny adres interfejsu VPS, port oraz
   `PUBLICATION_APPROVED=yes`;
2. potwierdź w zaporze dostawcy, że publiczny jest tylko wybrany port sensora;
3. uruchom pozostałe usługi przy zamkniętym gate;
4. zatwierdź aktualny kod, konfigurację i obrazy przez
   `sudo systemctl start honeynet-baseline-capture.service`;
5. wykonaj `sudo systemctl start honeynet-sensor-open.service`;
6. przetestuj port z innego, kontrolowanego hosta;
7. włącz timer: `sudo systemctl enable --now honeynet-monitor.timer`.

`honeynet-sensor-open` najpierw sprawdza bazę, aplikację, Cowrie, kolektor i
retencję. Osobny preflight odrzuca słabe/współdzielone sekrety, błędny adres,
port uprzywilejowany inny niż jawnie dopuszczony standardowy port SSH 22,
niedziałający Docker, brak aktywnego `DOCKER-USER` oraz niepoprawny Compose.
Następnie uruchamia bramkę, a gate otwiera jako ostatni krok.
Błąd na dowolnym etapie ponownie zamyka gate i zatrzymuje bramkę.

## Monitoring i automatyczne odcięcie

Co minutę kontrolowane są:

- wymagane kontenery;
- API i połączenie z bazą;
- heartbeat kolektora;
- prywatne powiązanie panelu z loopback;
- pojedyncza, wewnętrzna sieć Cowrie;
- stan hostowego gate;
- zajętość dysku, domyślnie z progiem 80%.
- rozmiar kwarantanny próbek: pojedynczy zapis do 16 MiB, ostrzeżenie przy 70%
  z 2 GiB oraz fail-closed po osiągnięciu limitu; monitor nie usuwa dowodów;
- tożsamości obrazów oraz sumy kodu i konfiguracji względem zatwierdzonego baseline;
- pomiar CPU i RAM, domyślnie z progami 95% oraz 90%; pojedynczy skok CPU
  generuje ostrzeżenie, a odcięcie następuje dopiero po trzech kolejnych
  przekroczeniach (`HONEYPOT_CPU_BREACH_COUNT_LIMIT`); prawidłowy pomiar zeruje
  licznik danego kontenera.

Każdy błąd powoduje `OnFailure=honeynet-kill-switch.service`. Wyniki pozostają w
journald:

```bash
journalctl -u honeynet-monitor.service -u honeynet-kill-switch.service
```

To zapewnia lokalną detekcję i automatyczne odcięcie. Przed publikacją nadal trzeba
podłączyć osobny kanał powiadomień operatora, zależny od wybranego dostawcy, oraz
przetestować go na kontrolowanym incydencie.

## Ręczny kill switch

Jedno polecenie:

```bash
sudo systemctl start honeynet-kill-switch.service
```

Najpierw ustawia hostowy `DROP`, następnie zatrzymuje wyłącznie `ssh-gateway`.
Nie usuwa bazy, kontenerów, sieci, logów ani wolumenów. Sensor nie uruchomi się
automatycznie ponownie; wznowienie wymaga ponownej oceny i jawnego uruchomienia
`honeynet-sensor-open.service`.
