# Lokalny kontekst GeoIP i ASN

Dashboard może opcjonalnie wzbogacać pseudonimizowane źródło o przybliżony kraj,
ASN i nazwę operatora. Zapytania nie opuszczają hosta aplikacji:
odczyt odbywa się wyłącznie z lokalnych, zgodnych z formatem MaxMind plików MMDB.

## Konfiguracja

1. Zainstaluj skrypt zgodnie z `deploy/pilot/README.md`.
2. Na pilocie uruchom `sudo /usr/local/sbin/honeynet-update-geoip`. Skrypt pobiera
   bazy PDDL `server-country` i `origin-asn`, weryfikuje ich SHA-256 i umieszcza
   w prywatnym katalogu `data/geoip/`:

   - `server-country-ipv4.mmdb`
   - `origin-asn-ipv4.mmdb`

3. Uruchom ponownie kontener aplikacji:

```powershell
docker compose up -d --build app
```

Compose montuje katalog jako `/geoip` tylko do odczytu. Ścieżki można zmienić
przez `GEOIP_COUNTRY_DB_PATH` i `GEOIP_ASN_DB_PATH`. Pliki baz danych są ignorowane
przez Git i nie powinny trafiać do repozytorium ani obrazu aplikacji.

Brak pliku, brak dopasowania lub uszkodzona baza nie zatrzymują API. Panel pokaże
wtedy, że lokalny kontekst GeoIP jest niedostępny.

## Granice interpretacji

- GeoIP opisuje przybliżoną lokalizację infrastruktury sieciowej, nie człowieka.
- VPN, proxy, Tor, serwer chmurowy albo przejęty host mogą wskazywać inny kraj niż
  miejsce pobytu operatora kampanii.
- ASN i organizacja są zwykle stabilniejszym kontekstem niż miasto.
- Sam kraj źródłowego IP nie dowodzi, że kampania pochodzi z tego kraju ani że
  była wymierzona w Polskę.
- Publiczny raport Markdown nadal nie zawiera surowego IP ani GeoIP. Ewentualna
  publikacja zagregowanych statystyk geograficznych wymaga osobnego przeglądu.

Źródło i licencja baz: [sapics/ip-location-db](https://github.com/sapics/ip-location-db).
