# Obsługa potencjalnie złośliwych próbek

## Stan domyślny: brak pobierania

W MVP zapisujemy tylko fakt próby pobrania, zredagowany URL, czas, sensor i kontekst sesji. Sensor nie odwiedza URL-a i nie pobiera pliku. Automatyczne wykonanie jest zabronione na każdym etapie.

Włączenie przechowywania próbek wymaga oddzielnej decyzji, uzasadnionego celu, akceptacji AUP dostawcy, przejścia listy kontrolnej poniżej i wyznaczenia operatora. Bez tego payload zostaje pominięty.

## Lista kontrolna przed włączeniem zbierania

- [ ] kwarantanna działa na osobnym hoście/VM bez routingu do Internetu i sieci prywatnych;
- [ ] sensor może tylko wysłać strumień do jednokierunkowego odbiornika; nie ma dostępu do repozytorium próbek;
- [ ] magazyn nie jest montowany z opcją wykonywania (`noexec`) i nie jest synchronizowany z chmurą, backupem użytkownika ani indekserem;
- [ ] pliki są szyfrowane, dostęp wymaga indywidualnego konta i MFA, a każda operacja jest logowana;
- [ ] antywirus/EDR administratora nie ma wyjątków obejmujących szerokie katalogi; uzgodniono bezpieczną kwarantannę z zespołem bezpieczeństwa;
- [ ] retencja i automatyczne usuwanie zostały przetestowane nieszkodliwą atrapą;
- [ ] istnieje procedura odłączenia, incydentu i bezpiecznego zniszczenia danych;
- [ ] dostawca i właściciel środowiska pisemnie zaakceptowali zakres.

## Przyjęcie próbki bez uruchamiania

1. Odbierz bajty jako nieufny blob; nie otwieraj, nie rozpakowuj i nie wyświetlaj podglądu.
2. Ogranicz rozmiar oraz czas transferu. Odrzuć archiwa-zagnieżdżenia i formaty przekraczające politykę.
3. Oblicz SHA-256 strumieniowo i nadaj losowy identyfikator. Oryginalna nazwa jest wyłącznie zredagowaną metadaną.
4. Zapisz próbkę w szyfrowanej kwarantannie jako dane bez bitu wykonywalnego. Nie używaj rozszerzenia kojarzonego z uruchamianiem.
5. Utwórz rekord: czas UTC, identyfikator sensora/sesji, rozmiar, SHA-256, metoda pozyskania, operator i stan (`quarantine`).
6. Potwierdź brak ruchu wychodzącego z kwarantanny i integralność pliku. Nie przesyłaj automatycznie do publicznych sandboxów ani serwisów reputacyjnych — może to ujawnić badanie lub dane stron trzecich.

## Dozwolona analiza w tej fazie projektu

Dozwolone są wyłącznie operacje statyczne zatwierdzone przez operatora, na kopii i w dedykowanej odłączonej VM: hashowanie, identyfikacja typu na podstawie nagłówka, bezpieczne wyodrębnienie ciągów narzędziami nieuruchamiającymi kodu i porównanie z lokalną bazą IOC.

Zabronione są: uruchamianie binarki lub skryptu, ładowanie dokumentu w aplikacji, makra, emulacja nieznanego kodu, `curl`/`wget` do URL-i z próbki, kontakt z C2, przesłanie do niezaufanej usługi oraz rozpakowywanie na komputerze operatora. Dynamiczna analiza wymaga osobnego, zaprojektowanego sandboxa i nie wchodzi w MVP.

## Dostęp i łańcuch odpowiedzialności

Każde pobranie, kopia, eksport, zmiana stanu i usunięcie zapisują: kto, kiedy, dlaczego, skąd i dokąd. Próbka nie trafia do Git, komunikatora, poczty, systemu ticketowego ani publicznego storage. Udostępnienie zaufanemu CSIRT-owi lub producentowi następuje dopiero po uzgodnieniu celu, bezpiecznego kanału, szyfrowania, odbiorcy i retencji.

Domyślna retencja próbki po ewentualnym włączeniu zbierania wynosi **14 dni**. Przedłużenie wymaga numeru sprawy, właściciela, uzasadnienia i daty ponownego przeglądu. Metadane bez próbki podlegają zasadom `privacy.md`.

## Incydent z próbką

Za incydent uznajemy m.in.: wykonanie lub podgląd przez niewłaściwą aplikację, zapis poza kwarantanną, ruch sieciowy, utratę kontroli dostępu, błędny eksport, zmianę hashy albo brak możliwości usunięcia.

1. Odłącz dotkniętą VM/host od wszystkich sieci; nie wyłączaj go pochopnie, jeśli zespół IR potrzebuje stanu ulotnego.
2. Zatrzymaj ingest i zablokuj poświadczenia do magazynu.
3. Zapisz czas, użytkownika, próbkę/hash, wykonane operacje, hosty i potencjalnych odbiorców.
4. Powiadom właściciela bezpieczeństwa; uruchom procedurę z `safety.md` oraz ocenę prywatności z `privacy.md`.
5. Nie kopiuj próbki „dla pewności”. Zabezpieczenie materiału prowadzi wyznaczony operator na uzgodnionym nośniku.
6. Przywróć środowisko z czystego obrazu, zrotuj sekrety, zweryfikuj sąsiednie systemy i udokumentuj działania naprawcze.

## Usunięcie

Po końcu retencji usuwamy klucz szyfrujący próbkę lub stosujemy zatwierdzony mechanizm bezpiecznego usunięcia adekwatny do użytego storage. Zapisujemy identyfikator, SHA-256, datę, metodę i osobę zatwierdzającą, ale nie zachowujemy zawartości. Snapshoty i repliki muszą podlegać temu samemu terminowi.
