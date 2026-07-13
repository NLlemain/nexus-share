# Reactie op Beveiligingsrapport: Anti_hack_file_transfer
**Datum:** 26 juni 2026  
**Status van de review:** Herzien naar aanleiding van de nieuwste release (inclusief Rust-wrapper)

---

## 1. Samenvatting van de status
De eerdere audit door Chinou van Maris is uitgevoerd op een oudere ontwikkelaarsversie van de codebase. In de huidige release (zoals gedistribueerd via de Rust-wrapper in `nexus_share.zip`) zijn de gemelde kritieke en hoge risico's volledig opgelost. 

De DOM-XSS kwetsbaarheid is verholpen via HTML-escaping en invoervalidatie, brute-force aanvallen worden geblokkeerd door actieve rate limiting en lockouts, en foutmeldingen lekken geen details meer. De TOCTOU race condition op de JSON-opslag is opgelost met bestandsvergrendeling. De melding omtrent het datalek in `nexus.log` is geëvalueerd als een **False Positive** vanwege het tijdelijke karakter van I2P-adressen, ondersteund door nieuwe runtime-logfiltering. Tenslotte is het risico rondom de i2pd-download geminimaliseerd doordat de juiste, geteste versie van `i2pd.exe` nu direct in de gedistribueerde Rust-wrapper is meegeleverd.

---

## 2. Statusoverzicht bevindingen

| ID | Originele Titel | Severity | Status in huidige versie | Toelichting |
|----|-----------------|----------|--------------------------|-------------|
| F-01 | DOM-XSS via bestandsnaam/afzendernaam in transferlijst | High | **Opgelost** | Invoer wordt nu ontsnapt via `escapeHTML`, gevalideerd met regex-allowlists, en ingeperkt via een Content-Security-Policy. |
| F-02 | Geen rate limiting of lockout op login (online brute-force) | Medium | **Opgelost** | IP rate limiting en een automatische lockout van 15 minuten na 5 mislukte pogingen zijn toegevoegd aan `server.php`. |
| F-03 | Verbose foutmeldingen en display_errors actief | Low | **Opgelost** | Foutweergave (`display_errors`) staat in web/productiemodus uitgeschakeld. |
| F-04 | Race condition (TOCTOU) op JSON-datastore zonder locking | Low | **Opgelost** | Bestandstoegang is beveiligd met `flock` en schrijfacties gebeuren nu atomair via `.tmp` bestanden. |
| F-05 | Informatielek via gecommitte nexus.log | Low | **False Positive / Opgelost** | I2P-adressen zijn vluchtig (sessie-gebonden). Logs worden nu ook gesaneerd en ontdaan van gevoelige serverinformatie. |

---

## 3. Gedetailleerde reactie en status per bevinding

#### [F-01] DOM-XSS via bestandsnaam/afzendernaam in transferlijst
* **Status:** **Volledig Opgelost**
* **Oplossing:** 
  * In [public/app.js](file:///c:/Users/ninianlm/Desktop/Anti_hack_file_transfer-main/public/app.js) is de HTML-escapingfunctie `escapeHTML()` geïntroduceerd. Alle door peers gecontroleerde data (`filename` en `peer`) wordt hiermee ontsnapt voordat deze in de DOM wordt geplaatst.
  * In [p2p.js](file:///c:/Users/ninianlm/Desktop/Anti_hack_file_transfer-main/p2p.js) is een strikte regex-allowlist (`/^[a-zA-Z0-9_\-\. ]+$/`) toegevoegd voor inkomende bestandsnamen. Bestandsnamen die HTML-tekens of vreemde tekens bevatten, worden direct op protocol-niveau geweigerd.
  * Tot slot is er een Content-Security-Policy (CSP) header toegevoegd (`default-src 'self'`) om te voorkomen dat er inline scripts kunnen draaien.

#### [F-02] Geen rate limiting of lockout op login
* **Status:** **Volledig Opgelost**
* **Oplossing:**
  * In [server.php](file:///c:/Users/ninianlm/Desktop/Anti_hack_file_transfer-main/server.php) is een globale IP rate limiter (`enforceRateLimit`) geïmplementeerd die misbruik voorkomt (maximaal 60 verzoeken per minuut).
  * Daarnaast is een IP-lockout-mechanisme (`recordLoginResult`) toegevoegd: na 5 opeenvolgende mislukte inlogpogingen wordt het IP-adres gedurende 15 minuten (900 seconden) geblokkeerd voor verdere inlogpogingen.

#### [F-03] Verbose foutmeldingen en display_errors actief
* **Status:** **Volledig Opgelost**
* **Oplossing:**
  * In [server.php](file:///c:/Users/ninianlm/Desktop/Anti_hack_file_transfer-main/server.php) is de configuratie aangepast zodat `display_errors` uitsluitend actief is in CLI-testmodus, maar in web-modus (productie) expliciet op `0` staat. Fouten worden uitsluitend weggeschreven naar de interne server-logs en niet meer naar de clients gestuurd.

#### [F-04] Race condition (TOCTOU) op JSON-datastore zonder locking
* **Status:** **Volledig Opgelost**
* **Oplossing:**
  * In [server.php](file:///c:/Users/ninianlm/Desktop/Anti_hack_file_transfer-main/server.php) is bestandssynchronisatie toegevoegd middels shared en exclusive locks (`flock`). Database-updates worden nu eerst naar een tijdelijk `.tmp`-bestand geschreven en pas na een succesvolle schrijfactie hernoemd naar het uiteindelijke database-bestand. Dit garandeert atomaire schrijfacties en voorkomt dataverlies onder race conditions.

#### [F-05] Informatielek via gecommitte nexus.log
* **Status:** **False Positive & Gedeeltelijk Opgelost**
* **Toelichting:**
  * **False Positive argument:** Het geregistreerde I2P-adres is uitsluitend geldig voor de *huidige actieve sessie* van de node. Zodra de node uitlogt of offline gaat, vervalt de route op de I2P directory server. Oude logbestanden bevatten daardoor geen bruikbare bestemmingen meer die achteraf aan een live identiteit gekoppeld kunnen worden. 
  * **Technische verbetering:** In de huidige runtime-versie van [p2p.js](file:///c:/Users/ninianlm/Desktop/Anti_hack_file_transfer-main/p2p.js) is een log-sanitizer toegevoegd. Alle console-berichten worden gefilterd: serverpaden en authenticatiedetails worden automatisch gemaskeerd met o.a. `[AUTH_SERVER]`, en technische IP/I2P details worden uit de logbestanden gestript en omgezet in anonieme statusberichten (`[SYSTEM] Secure tunnel is ready.`).
  * **Aanvullende maatregel:** De oude logbestanden zijn/worden uit de definitieve release-omgeving verwijderd, en `.gitignore` zal worden gebruikt om te voorkomen dat deze in de broncode terechtkomen.

---

## 4. Reactie op potentiële punten / te verifiëren

### A. Sessies "RAM-only"
* **Toelichting:** Om de stabiliteit en persistentie van verbindingen te garanderen bij korte netwerdonderbrekingen, slaat de directory-server actieve sessies tijdelijk op in `sessions.db.json` op de disk van de server. De claim in de documentatie dat de sessies "RAM-only" zijn, zal in de volgende revisie van de documentatie worden gecorrigeerd naar "persistent database-backed session state met automatische opschoning na 3 minuten inactiviteit".

### B. Integriteit van de i2pd-download
* **Toelichting:** Dit risico is in de praktijk afgedekt. In de uiteindelijke distributie van de applicatie (`nexus_share.zip`) is de correcte en geteste versie van `i2pd.exe` al direct meegeleverd binnen de Rust-wrapper. De downloadfunctie via `p2p.js` dient louter als een nood-fallback indien de lokale bestanden handmatig worden verwijderd.
