# Auswertung der DIDSSO-Benchmarkdaten

Diese Anleitung beschreibt, wie die vom DIDSSO-Benchmark erzeugten Daten
geprüft, in OpenOffice Calc importiert und für die Evaluation der Bachelorarbeit
ausgewertet werden. Die Auswertung verwendet primär deskriptive Statistik. Ein
einzelner Testlauf dient ausschließlich der Funktionsprüfung; die finalen
Ergebnistabellen müssen auf den vorgesehenen 100 Messläufen je Szenario
basieren.

## 1. Erzeugte Dateien

Der Protokollbenchmark erzeugt im Ordner `benchmark-results/` drei zusammengehörige
Dateien:

- `protocol-<timestamp>.json`: Metadaten, Browser- und Backendversionen,
  Rohwerte, Fehler und aggregierte Werte;
- `protocol-<timestamp>-raw.csv`: eine Zeile je gemessenem Durchlauf;
- `protocol-<timestamp>-summary.csv`: aggregierte Statistik je Szenario und
  Metrik.

Der Proof-Benchmark erzeugt einen JSON-Bericht. Er enthält für RISC Zero die
einzelnen Proof-Läufe und deren aggregierte Werte. STWO ist nicht Bestandteil
der quantitativen Auswertung.

### Raw CSV

Die Raw CSV wird benötigt für:

- die Kontrolle jedes einzelnen Laufs;
- Verlaufsgrafiken über die Laufnummer;
- Ausreißer- und Driftanalysen;
- die getrennte Betrachtung verschiedener Navigationsquellen;
- die Prüfung, ob tatsächlich der erwartete Tokenpfad ausgeführt wurde.

### Summary CSV

Die Summary CSV wird benötigt für:

- Ergebnistabellen;
- Diagramme der Mittelwerte;
- Median, Stichprobenstandardabweichung, Minimum und Maximum;
- den Vergleich der drei Protokollszenarien.

Jede Zeile identifiziert genau eine Kombination aus `scenario` und `metric`.
Deshalb darf nicht die gesamte Summary CSV ungefiltert als ein gemeinsames
Diagramm dargestellt werden.

## 2. Gültigkeit eines Berichts prüfen

Vor jeder statistischen Auswertung muss die zugehörige JSON-Datei kontrolliert
werden. Ein Bericht darf für die finalen Ergebnisse nur verwendet werden, wenn:

1. `status` den Wert `completed` besitzt;
2. `errors` leer ist;
3. jede vorgesehene Messreihe genau 100 abgeschlossene Läufe enthält;
4. `proof_backend` den Wert `risc0` besitzt;
5. der Browser nicht im Headless-Modus ausgeführt wurde;
6. Browser-, geckodriver-, Selenium- und Python-Version dokumentiert sind.

Bei der Summary CSV muss für jede ausgewertete Zeile gelten:

```text
count = 100
```

Berichte mit `running`, `failed` oder `cancelled` sind Teilberichte. Sie dürfen
zur Fehlersuche, aber nicht für die finale Aggregation verwendet werden.

Warm-up-Läufe und ungemessene Vorbereitungsläufe sind bereits aus den CSV-Daten
ausgeschlossen.

## 3. CSV in OpenOffice Calc importieren

Die CSV-Datei wird über **Datei -> Öffnen** geladen. Im Textimportdialog werden
folgende Einstellungen verwendet:

- Zeichensatz: `Unicode (UTF-8)`;
- Sprache: `Englisch (USA)`;
- Trennoption: `Getrennt`;
- Trennzeichen: ausschließlich `Komma`;
- Texttrenner: `"`;
- `Leerzeichen`, `Semikolon` und `Tabulator` sind deaktiviert.

Das englische Gebietsschema ist erforderlich, weil die Messwerte einen
Dezimalpunkt verwenden. Nach dem Import sollten numerische Werte in Calc
standardmäßig rechtsbündig dargestellt werden. Linksbündige Zahlen wurden
möglicherweise als Text importiert und dürfen nicht direkt für Berechnungen
verwendet werden.

In der Summary CSV müssen die folgenden Spalten erkennbar sein:

```text
scenario
metric
count
mean
median
sample_standard_deviation
minimum
maximum
```

Anschließend empfiehlt es sich, über **Daten -> Filter -> AutoFilter** Filter
für die Kopfzeile zu aktivieren.

## 4. Bedeutung der statistischen Größen

### Arithmetisches Mittel

Das Mittel beschreibt die durchschnittliche gemessene Dauer. Es wird durch
besonders langsame oder schnelle Ausreißer beeinflusst.

### Median

Der Median teilt die sortierten Messungen in zwei Hälften. Er ist robuster
gegenüber einzelnen Ausreißern. Ein deutlicher Abstand zwischen Mittelwert und
Median weist häufig auf eine schiefe Verteilung oder einzelne langsame Läufe
hin.

### Stichprobenstandardabweichung

Die Stichprobenstandardabweichung beschreibt die Streuung der Messwerte um den
Mittelwert. Sie ist bei einem einzelnen Lauf nicht definiert und bleibt deshalb
bei diagnostischen Einzelläufen leer.

### Minimum und Maximum

Minimum und Maximum zeigen die beobachtete Spannweite. Sie sollten gemeinsam
mit einer Verlaufsgrafik kontrolliert werden, da ein einzelner Extremwert das
Maximum stark verändern kann.

Ausreißer werden nicht allein deshalb gelöscht, weil sie groß oder klein sind.
Ein Ausschluss ist nur zulässig, wenn ein dokumentierter technischer Fehler
vorlag und die Ausschlussregel vor der Ergebnisinterpretation festgelegt wurde.
Die betroffenen Laufnummern müssen dann angegeben werden.

## 5. End-to-End-Vergleich der Protokollflüsse

Für die zentrale Ergebnistabelle wird die Summary CSV in der Spalte `metric`
nach folgendem Wert gefiltert:

```text
end_to_end_seconds
```

Es verbleiben normalerweise drei Szenarien:

- `privacy_enhanced_sso`;
- `direct_login_access_token`;
- `direct_login_refresh_token`.

Auf einem neuen Tabellenblatt wird daraus eine Hilfstabelle erstellt:

| Scenario | Mean [s] | Median [s] | SD [s] | Min. [s] | Max. [s] |
|---|---:|---:|---:|---:|---:|
| Privacy-enhanced SSO | | | | | |
| Direct Login -- Access Token | | | | | |
| Direct Login -- Refresh Token | | | | | |

Die Werte werden aus den entsprechenden Summary-Zeilen übernommen. Für die
Bachelorarbeit sollten alle Zeitwerte konsistent auf beispielsweise drei
Dezimalstellen gerundet werden. Berechnungen erfolgen immer mit den ungerundeten
Originalwerten; gerundet wird erst für die Darstellung.

### Diagramm in Calc

1. Die Spalten `Scenario` und `Mean [s]` der Hilfstabelle markieren.
2. **Einfügen -> Diagramm** auswählen.
3. `Säule` oder `Balken` verwenden.
4. Datenreihen in Spalten anordnen.
5. Erste Zeile und erste Spalte als Beschriftung verwenden.
6. Die Y-Achse als `Execution time [s]` beschriften.

Da die SSO-Zeit wesentlich größer als die Direct-Login-Zeiten sein kann, sind
die kleinen Balken auf einer linearen Achse möglicherweise kaum sichtbar. In
diesem Fall werden entweder zwei getrennte Diagramme oder eine ausdrücklich als
logarithmisch gekennzeichnete Y-Achse verwendet. Eine abgeschnittene Achse ohne
deutliche Kennzeichnung ist zu vermeiden.

Nach 100 Läufen kann die Spalte `SD [s]` als Y-Fehlerbalken verwendet werden.
Fehlerbalken müssen in Bildunterschrift oder Fließtext als
Stichprobenstandardabweichung bezeichnet werden.

## 6. SSO-Latenz aufteilen

Für die SSO-Aufteilung wird zusätzlich nach folgendem Szenario gefiltert:

```text
scenario = privacy_enhanced_sso
```

Für eine additive Aufteilung der End-to-End-Zeit werden nur diese Metriken
verwendet:

- `proof_generation_seconds`;
- `proof_verification_seconds`;
- `token_issuance_seconds`;
- `result_delivery_seconds`;
- `browser_processing_seconds`;
- `unattributed_seconds`.

Diese Werte können als Balkendiagramm oder als gestapelte Säule dargestellt
werden. Ihre Mittelwerte ergeben bis auf Rundungsabweichungen die mittlere
End-to-End-Latenz.

Die folgenden diagnostischen Metriken dürfen nicht zusätzlich in dieselbe
gestapelte Säule aufgenommen werden:

- `wallet_result_validation_latency_seconds`;
- `extension_poll_delay_seconds`;
- `extension_detection_latency_seconds`.

Diese Intervalle überlappen sich teilweise mit dem Ergebniszustellungs- und
Navigationsablauf. Eine Addition würde Zeitabschnitte doppelt zählen. Sie können
in einem separaten Diagnosediagramm dargestellt werden.

Ein sinnvoller zusätzlicher Kennwert ist der Anteil der Proof-Erzeugung an der
Gesamtlatenz:

```text
proof share [%] = proof generation mean / SSO end-to-end mean * 100
```

## 7. Access- und Refresh-Pfad vergleichen

Für den Vergleich werden zunächst die End-to-End-Zeilen der Szenarien
`direct_login_access_token` und `direct_login_refresh_token` verwendet.

Zusätzlich kann die Metrik

```text
token_claims_round_trip_seconds
```

für beide Szenarien verglichen werden. Dadurch wird sichtbar, welcher Anteil
der Direct-Login-Latenz auf die Kommunikation mit dem IdP und die
Claims-Aktualisierung entfällt.

Sinnvolle abgeleitete Werte sind:

```text
absolute refresh overhead [s] = refresh mean - access mean
relative refresh overhead [%] = (refresh mean / access mean - 1) * 100
```

Diese Werte werden erst nach 100 Läufen interpretiert. Ein Unterschied aus nur
einem Lauf kann durch normale Laufzeitschwankungen entstehen.

## 8. Verlauf und Performance-Drift untersuchen

Für eine Verlaufsgrafik wird die Raw CSV verwendet. Relevant sind:

```text
scenario
run
end_to_end_seconds
```

Auf einem neuen Tabellenblatt wird eine Hilfstabelle aufgebaut:

| Run | SSO [s] | Access [s] | Refresh [s] |
|---:|---:|---:|---:|
| 1 | | | |
| 2 | | | |
| ... | | | |
| 100 | | | |

Aus dieser Tabelle wird ein XY-Punkt- oder Liniendiagramm erstellt. Die
Laufnummer bildet die X-Achse, die Dauer in Sekunden die Y-Achse. Wegen der
unterschiedlichen Größenordnungen können getrennte Diagramme für SSO und Direct
Login übersichtlicher sein.

Die Verlaufsgrafik dient der Kontrolle auf:

- besonders langsame oder schnelle Ausreißer;
- systematische Zunahme der Laufzeit;
- Aufwärm- oder Cacheeffekte;
- thermische Effekte;
- möglichen zusätzlichen Aufwand durch wachsende JSON-Zustandsdateien.

Eine erkennbare zeitliche Drift muss als Einschränkung diskutiert werden, weil
die Läufe dann nicht vollständig unabhängig und identisch verteilt sind.

## 9. Korrekte Ausführung der Szenarien kontrollieren

In der Raw CSV werden vor der statistischen Interpretation die kategorialen
Spalten geprüft.

### Tokenmodus

Für alle Access-Läufe muss gelten:

```text
token_mode = access
```

Für alle Refresh-Läufe muss gelten:

```text
token_mode = refresh
```

Abweichungen bedeuten, dass nicht das vorgesehene Szenario gemessen wurde.

### Navigationsquelle

Die Spalte `navigation_source` enthält typischerweise:

- `extension` oder
- `rp_session_poll`.

Für jede SSO-Serie sollte ausgezählt werden, wie häufig welcher Pfad die
Navigation ausgelöst hat. Wenn beide Pfade vorkommen, kann zusätzlich geprüft
werden, ob ihre End-to-End-Verteilungen unterschiedlich sind. Die
Navigationsquelle ist Teil des evaluierten Prototyps und kein Grund für einen
automatischen Ausschluss.

## 10. RISC-Zero-Proofzeiten und -größen auswerten

Der Proof-Benchmark erfasst ausschließlich die Erzeugungs- und
Verifikationszeiten des in der quantitativen Evaluation verwendeten
RISC-Zero-Backends. STWO-Ergebnisse werden weder mit diesen Werten
zusammengeführt noch als Vergleichsreihe ausgewertet.

Zusätzlich werden zwei Größenmetriken erhoben:

- `receipt_size_bytes` ist die Größe des Base64-dekodierten, serialisierten
  RISC-Zero-Receipts und damit die eigentliche Proof-Artefaktgröße;
- `proof_envelope_size_bytes` ist die UTF-8-Größe des deterministisch kompakt
  serialisierten JSON-Proof-Objekts einschließlich Metadaten und
  Base64-Overhead.

Keine dieser Größen entspricht der Größe einer verschlüsselten
DIDComm-Nachricht. Die beiden Metriken dürfen daher nicht als vollständiger
Kommunikationsaufwand des Protokolls interpretiert werden.

Die gemessenen Proof-Zeiten sind integrierte Backendzeiten. Sie enthalten unter
anderem Python-, JSON-, Datei-, WSL- und Prozess-Overhead und dürfen daher nicht
als reine kryptografische Kernlaufzeiten bezeichnet werden. Der Start des
persistenten RISC-Zero-Verifiers ist als Setup ausgeschlossen. Für die
Ergebnistabelle werden Proof-Erzeugung und Proof-Verifikation jeweils mit
Mittelwert, Median, Stichprobenstandardabweichung, Minimum und Maximum
angegeben. Dieselben deskriptiven Kennwerte werden für beide Größenmetriken in
Byte angegeben.

Direct Access und Direct Refresh erzeugen keinen neuen ZK-Proof. Die
RISC-Zero-Proofzeiten werden deshalb nur für den Privacy-enhanced SSO-Flow und
den separaten Proof-Benchmark ausgewertet.

## 11. Optionales Konfidenzintervall

Zusätzlich zur geforderten deskriptiven Statistik kann ein 95-%-Konfidenzintervall
für den Mittelwert angegeben werden:

```text
mean +/- t(0.975, n - 1) * SD / sqrt(n)
```

Bei `n = 100` liegt der verwendete t-Faktor ungefähr bei 1,984. Ein solches
Intervall setzt jedoch hinreichend unabhängige, gleichartig erzeugte Messungen
voraus. Bei sichtbarer Drift oder starkem zustandsabhängigem Verhalten muss
diese Annahme eingeschränkt und das Intervall entsprechend vorsichtig
interpretiert werden. Für die im Methodology-Kapitel bereits vorgesehenen
Kennwerte ist das Konfidenzintervall nicht zwingend erforderlich.

## 12. Empfohlene Tabellen und Abbildungen

Für den Evaluationsteil bieten sich mindestens folgende Ergebnisse an:

1. Tabelle der End-to-End-Latenz aller drei Protokollflüsse mit Mittelwert,
   Median, Stichprobenstandardabweichung, Minimum und Maximum;
2. Diagramm der mittleren End-to-End-Latenz mit SD-Fehlerbalken;
3. Tabelle oder Diagramm der additiven SSO-Latenzbestandteile;
4. Tabelle der separat erhobenen RISC-Zero-Proofzeiten und -größen;
5. Verlaufsgrafik der Laufzeiten über alle 100 Durchläufe;
6. kurze Angabe zur Häufigkeit der tatsächlichen Navigationsquellen.

In jeder Tabelle oder Abbildung werden Einheit, Stichprobengröße, Browsermodus,
Proof-Backend und Bedeutung der Fehlerbalken angegeben.

## 13. Typische Fehler vermeiden

- Keine Statistik aus einem diagnostischen Einzellauf als finales Ergebnis
  verwenden.
- Headless- und headed Messungen nicht zusammenführen.
- Fehlgeschlagene und vollständige Berichte nicht vermischen.
- Sekunden und Millisekunden nicht verwechseln; die CSV-Zeitmetriken sind in
  Sekunden angegeben.
- Überlappende Zeitintervalle nicht addieren.
- STWO-Messungen nicht in die quantitative RISC-Zero-Auswertung aufnehmen.
- Mittelwerte nicht ohne Median und Streuung interpretieren.
- Ausreißer nicht ohne technische Begründung entfernen.
- Keine übermäßige Genauigkeit darstellen; für Tabellen sind meist drei
  Dezimalstellen ausreichend.
- Die feste Ausführungsreihenfolge und mögliche Zustandsdrift als Limitation
  benennen.

## 14. Reproduzierbare Ablage

Für jede finale Messung sollten gemeinsam archiviert werden:

- JSON-Bericht;
- Raw CSV;
- Summary CSV;
- verwendeter Git-Commit;
- Proof-Backend und Backendversion;
- Browser-, geckodriver- und Selenium-Version;
- Hardware- und Betriebssysteminformationen;
- Datum und Startbefehl der Messung.

Dadurch bleiben die Tabellen und Abbildungen auf die ursprünglichen Rohdaten
zurückführbar.
