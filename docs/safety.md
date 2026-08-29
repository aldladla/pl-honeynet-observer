# Zasady bezpiecznego uruchamiania honeynetu

## Cel i granice

Projekt służy wyłącznie do defensywnego zbierania telemetrii z systemów, które kontrolujemy. Pierwszy etap działa lokalnie: usługi nasłuchują tylko na `127.0.0.1` albo w odizolowanej sieci laboratoryjnej. Nie skanujemy cudzych systemów, nie odpowiadamy odwetowo i nie próbujemy przejmować infrastruktury źródłowej.

Domyślna zasada: **jeżeli środowisko nie przeszło listy kontrolnej publikacji, nie może być dostępne z Internetu**.

## Nienegocjowalne zabezpieczenia

- Próbki i polecenia pochodzące z honeypota nigdy nie są wykonywane na hoście, laptopie operatora ani w środowisku produkcyjnym.
- Kontener honeypota nie ma dostępu do sieci domowej, panelu administracyjnego, bazy telemetrycznej ani sekretów operatora.
- Ruch wychodzący z segmentu sensorów jest domyślnie blokowany. Nie zapewniamy routingu, proxy, tunelowania, relay SMTP ani możliwości atakowania innych hostów.
- Kontener publikujący port sensora ma osobną podsieć wejściową. Host blokuje w
  `DOCKER-USER` wszystkie nowe połączenia wychodzące z tej podsieci, pozostawiając
  wyłącznie odpowiedzi na połączenia zainicjowane z Internetu.
- Pobieranie wskazanych plików jest w MVP wyłączone. Rejestrujemy URL, nazwę i metadane żądania, ale nie pobieramy zawartości automatycznie.
- Panel, API, baza danych, metryki i SSH administratora nie są wystawiane publicznie. Dostęp administracyjny odbywa się przez osobny kanał, z MFA tam, gdzie jest dostępne.
- Procesy działają bez uprawnień `root`, z minimalnymi capabilities, tylko niezbędnymi montowaniami i limitami CPU, RAM, miejsca oraz liczby procesów.
- Pojedyncza próbka ma limit zapisu, a łączny rozmiar kwarantanny jest liczony co
  minutę. Osiągnięcie limitu odcina publiczny sensor bez automatycznego kasowania
  dowodów.
- Logi nie mogą zawierać sekretów infrastruktury. Sekrety są przekazywane poza repozytorium i regularnie rotowane.

## Minimalna architektura

1. **Sensor** — odizolowany kontener/VM, który udaje usługę i zapisuje zdarzenia do kolejki lub katalogu tylko-do-dopisywania.
2. **Warstwa odbiorcza** — przyjmuje zdarzenia jednym, uwierzytelnionym kanałem; sensor nie ma dostępu zwrotnego do bazy ani API administracyjnego.
3. **Magazyn** — prywatna sieć, szyfrowanie w tranzycie i w spoczynku, oddzielne konto z minimalnymi uprawnieniami.
4. **Analiza i raporty** — operują przede wszystkim na danych znormalizowanych i zanonimizowanych. Surowe dane są dostępne tylko wyznaczonym operatorom.

Nie traktujemy kontenera jako pełnej granicy bezpieczeństwa. Publiczny sensor powinien działać na osobnym VPS/VM bez peeringu z innymi zasobami projektu.

## Bramka przed publicznym wdrożeniem

Każdy punkt musi mieć udokumentowane `PASS` i osobę zatwierdzającą:

- [ ] właściciel infrastruktury i zakres eksperymentu są jednoznaczne;
- [ ] dostawca VPS potwierdza zgodność z AUP/ToS, w tym honeypot, rejestrację ruchu i ewentualne przechowywanie próbek;
- [ ] publiczne są tylko celowo wybrane porty sensora;
- [ ] egress jest zablokowany i zweryfikowany testem z wnętrza sensora;
- [ ] panel, API, baza i port zarządzania nie odpowiadają z Internetu;
- [ ] gotowe są limity zasobów, rotacja logów, alerty i automatyczny kill switch;
- [ ] kopia zapasowa konfiguracji nie zawiera danych atakujących ani próbek;
- [ ] zasady prywatności, retencji i dostępu z `privacy.md` są wdrożone;
- [ ] procedura obsługi próbek z `sample-handling.md` została przećwiczona na nieszkodliwym pliku EICAR lub własnej atrapie — bez uruchamiania;
- [ ] wykonano próbny incydent i potwierdzono możliwość całkowitego odłączenia sensora;
- [ ] wskazano kontakt abuse i osobę dyżurną.

Brak choć jednego `PASS` oznacza pozostawienie środowiska na localhost/lab.

## Monitorowanie i kill switch

Alarmujemy co najmniej o: nieoczekiwanym ruchu wychodzącym, wzroście użycia CPU/RAM/dysku, zmianie obrazu lub konfiguracji, procesie spoza listy dozwolonej, próbie dostępu do sieci zarządzającej oraz utracie telemetrii.

Kill switch musi jednym działaniem odciąć publiczny interfejs lub regułę zapory, bez kasowania dowodów. Po jego użyciu nie restartujemy sensora automatycznie.

Referencyjna implementacja dla dedykowanego Ubuntu VPS znajduje się w
`deploy/pilot/`. Działa wyłącznie z backendem zapory Dockera `iptables`, zaczyna
od zamkniętego gate w `DOCKER-USER`, monitoruje heartbeat kolektora i przy błędzie
najpierw ustawia `DROP`, a następnie zatrzymuje tylko `ssh-gateway`. Nie uruchamiać
jej przed przejściem całej bramki publikacyjnej.

## Procedura podejrzenia przełamania

1. Odłącz sensor od Internetu i wszystkich sieci prywatnych; nie loguj się interaktywnie do podejrzanego kontenera, jeśli można zebrać dane z hypervisora.
2. Zapisz czas UTC, identyfikator sensora, ostatnią znaną dobrą konfigurację i osobę podejmującą decyzję.
3. Zabezpiecz logi, metadane i snapshot tylko wtedy, gdy nie zwiększa to ryzyka. Oblicz sumy SHA-256; pracuj na kopii.
4. Zrotuj wszystkie sekrety, do których sensor mógł mieć dostęp. Sprawdź płaszczyznę zarządzającą, odbiornik i sąsiednie zasoby.
5. Powiadom dostawcę przez jego kanał abuse/security, jeśli mogło dojść do ruchu wychodzącego albo naruszenia AUP.
6. Oceń obowiązki zgłoszeniowe i ochronę danych z właściwą osobą prawną/DPO; niniejszy dokument nie zastępuje porady prawnej.
7. Odtwórz sensor z czystego, przypiętego obrazu. Nie przywracaj podejrzanego systemu do sieci.
8. Zapisz przyczynę, zakres, oś czasu, działania naprawcze oraz test zapobiegający powtórzeniu.

## Kryteria natychmiastowego zatrzymania

Eksperyment zatrzymujemy, gdy sensor generuje ruch do cudzych hostów, przechowuje próbkę poza kwarantanną, traci izolację, zapełnia zasoby, ujawnia dane lub sekrety, otrzymujemy zgłoszenie abuse albo nie potrafimy wyjaśnić zachowania procesu. Wznowienie wymaga analizy przyczyny i ponownego przejścia bramki publikacji.
