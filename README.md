# seclume

JDBC-Treiber und Connection-Pool für PostgreSQL, MySQL/MariaDB, Microsoft SQL Server und
Oracle, deren Kerneigenschaft ist: **Datenbank-Passwörter erscheinen zu keinem Zeitpunkt
als `String` oder `char[]` auf dem Java-Heap und sind daher in einem hprof-Heapdump nicht
auffindbar.**

Java 25, Spring Boot 4.x / Spring Framework 7.x. Keine Fremdabhängigkeiten zur Laufzeit
außer JDK und Spring. Kein Hersteller-Treiber wird verwendet, gewrappt oder delegiert.

---

## Bedrohungsmodell

**IN SCOPE** — dagegen schützt die Bibliothek:

- Ein hprof-Heapdump (`jmap`, `-XX:+HeapDumpOnOutOfMemoryError`, JFR, Actuator-`/heapdump`,
  Support-Upload) fällt einem Angreifer in die Hände, Minuten bis Jahre nach dem Connect.
- Der Dump wird sowohl über den Objektgraphen (MAT/OQL) als auch roh (`strings | grep`)
  durchsucht — beides muss ergebnislos bleiben.

**OUT OF SCOPE** — das löst seclume nicht und versucht es auch nicht:

- Angreifer mit Live-Prozesszugriff (ptrace, gcore, Debugger). Der benutzt ohnehin die
  offenen Connections des Pools.
- Kernel-/Hypervisor-Kompromittierung.
- Das Zeitfenster von wenigen Mikrosekunden während des Handshakes selbst.

Daraus folgt eine Empfehlung, die den ganzen Aufwand überflüssig macht, wo sie umsetzbar
ist: **betriebssystemintegrierte Authentifizierung** (SSPI/Kerberos, PostgreSQL `gss`/`sspi`,
SQL Server Integrated Security, Oracle NTS). Dort gibt es kein Geheimnis im Prozess, das man
verlieren könnte — nicht einmal für die Mikrosekunden des Handshakes. Passwort-Auth ist der
Notnagel für alles, was nicht in einer Domäne steht.

`/heapdump` darf übrigens exponiert bleiben. Das ist der Punkt.

---

## Weitere Datenbanken

Zwei Punkte stehen über den Auftrag hinaus auf dem Plan, in dieser Reihenfolge:

**CockroachDB und YugabyteDB** sprechen das PostgreSQL-Wireprotokoll. Hier ist
wahrscheinlich **kein neuer Treiber nötig** — nur der Nachweis, dass der vorhandene sie
bedient. Das kostet einen CI-Lauf, und genau dort ist es eingetragen. Ein Beleg ist es
allerdings erst, wenn er grün ist; bis dahin ist es eine Vermutung.

**DB2 / IBM i** ist der einzige Kandidat, für den sich ein *neuer* Treiber lohnt — und
zwar erst, wenn die vier bestehenden fertig sind. Die Begründung ist nicht technisch,
sondern liegt im Umfeld: Banken, Versicherungen und Behörden, also genau die Stellen mit
statischen Datenbankpasswörtern per Vorgabe und mit Speicherauszügen, die an Hersteller
gehen. Das Protokoll (DRDA) ist offen dokumentiert, es wäre also TDS-Klasse an Aufwand,
nicht Oracle-Klasse.

Bewusst **nicht** auf dem Plan: H2 und HSQLDB (eingebettet — die Datenbank liegt selbst im
Heap, die Kerneigenschaft trägt dort nicht), SAP HANA (proprietäres Protokoll ohne
Spezifikation, Oracle-Klasse an Aufwand bei kleinerem Nutzen), und alles ohne JDBC.

## Verhältnis zu Vault, IAM und Rotation

Die naheliegende Frage: macht seclume einen Tresor überflüssig — oder ist es umgekehrt
der Tresor, der seclume überflüssig macht? Weder noch, und die Unterscheidung lohnt sich.

**Gegen einen Tresor mit statischem Passwort** — also den Fall, der in der Praxis
überwiegt: ein Secret-Store, dessen Inhalt jährlich rotiert wird, wenn überhaupt — ist
„gemountete Datei + seclume" nicht schlechter, sondern in einem Punkt besser:

| | Vault mit statischem Passwort | Datei + seclume |
|---|---|---|
| Nicht in Image, Env, Properties | ✅ | ✅ (`/run/secrets/...`) |
| Nicht im JVM-Heap | ❌ | ✅ |
| Prüfprotokoll, zentrale Richtlinie | ✅ | ❌ |
| Zusätzliche Komponente im Startpfad | ja (Sidecar, Token-Renewal, Unsealing) | nein |

Der Tresor verliert die zweite Zeile, und zwar unvermeidlich: sobald die Java-Anwendung
das Geheimnis abruft, ist es ein `String` im Heap und bleibt dort, bis der GC ihn zufällig
überschreibt. Vault schützt den Weg *zum* Prozess, nicht den Zustand *im* Prozess.

**Gegen kurzlebige Anmeldedaten** — Vaults Datenbank-Engine, IAM-Auth bei RDS oder
Cloud SQL — verliert seclume dagegen klar. Wer Anmeldedaten benutzt, die nach Minuten
verfallen, begrenzt das *Zeitfenster* und nicht nur die Angriffsfläche. Das ist stärker
als jeder Schutz im Ruhezustand, und wer es haben kann, sollte es nehmen.

**Beides zusammen ist das Beste.** `secret.provider: bean` ist genau dafür da: der Tresor
liefert, seclume sorgt dafür, dass das Gelieferte den Heap nicht sieht.

**Und die Grenze:** seclume verschiebt den schwachen Punkt auf die Quelle. Wer den
Dateibaum des Containers lesen kann oder einen Core-Dump zieht, hat das Geheimnis — das
steht oben im Bedrohungsmodell ausdrücklich als *out of scope*. Geschlossen wird der eine
Weg, der heute offen ist und den kein Tresor schließt: der Heapdump.

## Nicht darstellbare Geheimnisquellen

Diese Quellen sind mit seclume **nicht** unterstützbar, und zwar grundsätzlich, nicht aus
Bequemlichkeit:

- **Umgebungsvariablen.** `ProcessEnvironment` wird beim JVM-Start als `Map<String,String>`
  befüllt und nie freigegeben; der String existiert, bevor Bibliothekscode läuft.
  `DB_PASSWORD=…` ist damit nicht absicherbar.
- **Kommandozeilen-Argumente.** Zusätzlich prozessextern lesbar über `/proc/<pid>/cmdline`
  bzw. `Win32_Process.CommandLine`.
- **HTTP-Secret-Endpunkte über `java.net.http.HttpClient`** — dessen Response-Handler liefern
  Strings. Ein solcher Provider setzt einen eigenen Off-Heap-HTTP-Parser voraus und ist
  deshalb nicht Teil des Lieferumfangs.
- **Binding als `char[]` durch Spring Boot.** Siehe `docs/spring-binding.md` (folgt mit dem
  Starter): das `char[]` entsteht am Ende einer reinen String-Kette und ist selbst Heap.

---

## Stand

Der Aufbau folgt den Meilensteinen aus dem Auftrag; jede Stufe wird lauffähig und getestet
abgeschlossen, bevor die nächste beginnt.

| Stufe | Inhalt | Stand |
|-------|--------|-------|
| 1 | `seclume-core`: `SecretProvider`, `SecretScope`, Off-Heap-Krypto | **fertig** |
| 2 | hprof-Parser und Heapdump-Test-Harness inkl. Negativkontrolle | **fertig** |
| 3 | PostgreSQL-Treiber | **fertig** (Protokoll, SCRAM, erweitertes Protokoll, JDBC-Oberfläche, Blockcursor, generierte Schlüssel) |
| 4 | MySQL/MariaDB | **fertig** (Protokoll, Anmeldung, JDBC-Oberfläche; Integrationssuite gegen MySQL 8.4 grün) |
| 5 | Microsoft SQL Server | **fertig** (Anmeldung, Abfragen, JDBC-Oberfläche; Integrationslauf gegen SQL Server 2022 grün) |
| 6 | Oracle | **fertig** (Anmeldung, Abfragen, Bindevariablen, DDL/DML, **Transaktionen**, **Array-Stapel**, Cursor-Wiederverwendung, JDBC-Oberfläche; Integrationslauf gegen Oracle Free 23ai grün; **LOBs** vollständig: lesen und schreiben, `Clob`/`Blob`, Ströme, Ausschnitt in einer Rundreise, `createClob`/`createBlob` — offen: server-seitige temporäre LOBs) |
| 7 | Connection-Pool | **fertig** — inkl. Micrometer, Health-Indicator, Statement-Cache, Leckerkennung und einer Timeout-Meldung, die die ältesten Halter nennt |
| 8 | Spring-Boot-Starter | **fertig** |
| 9 | README, Threat-Model, Migrationsleitfaden | teilweise (dieses Dokument) |
| — | **Verteilte Transaktionen (XA)** in allen vier Treibern, standardmäßig aus | **fertig** — gegen echte Server geprüft, siehe [`docs/xa.md`](docs/xa.md) |
| — | **Cursor in Blöcken** (`setFetchSize`) | **fertig** in allen vier (SQL Server ohne Bindewerte) |
| — | **Ausfallsicherheit Stufe 1**: Hostliste und Failover beim Verbinden | **fertig**, siehe [`docs/resilience.md`](docs/resilience.md) |
| — | **Pipeline-Block**: ein Roundtrip für einen ganzen Arbeitsschritt | **fertig** (PostgreSQL und MySQL bündeln) |
| — | **NS-Mitschnitt** (`-Dseclume.oracle.trace=true`): jedes Oracle-Paket in beiden Richtungen, **nur Rahmen, nie Inhalte** | **fertig** — das Werkzeug, mit dem drei Protokollfehler gefunden wurden |
| — | **`seclume-verify`**: Vorflug-Bericht über Server, Geheimnisquelle, Fähigkeiten und Roundtrips | **fertig** |
| — | **`seclume-heapcheck`**: beweist für *jeden* laufenden Java-Prozess, ob ein Geheimnis im Heap steht | **fertig** |
| — | **`RdsIamSecretProvider`**: AWS-RDS-IAM-Token signiert statt geholt, nie ein `String` | **fertig** |
| — | **`seclume-spring-test`**: Spring Data, Hibernate und Flyway auf seclume | **fertig** gegen PostgreSQL, MySQL/Oracle vorbereitet |
| 10 | PostgreSQL-Familie belegen: CockroachDB, YugabyteDB | offen (nur CI, kein Treiber) |
| — | `seclume-bench`: JMH gegen die Herstellertreiber und HikariCP | **steht** — und liefert den ersten klaren Vorsprung: **Faktor 15 gegen MySQL Connector/J** bei einem Stapel über echte Netzstrecke. Zahlen und Herleitung in `docs/performance.md` |
| 11 | DB2 / IBM i (DRDA) | offen, nach den vier bestehenden |
| **Z** | **`seclume-tcp-core`** — portabler Transportkern im Userspace (TUN/utun/Wintun), damit eine laufende Verbindung zwischen **Linux, Windows und macOS** umziehen kann; JDBC ist der erste Adapter, nicht der Zweck | **erklärtes Ziel**, eigenes Projekt, noch nicht begonnen — Architektur und Reihenfolge in [`docs/mobility.md`](docs/mobility.md) |

### Was von Stufe 3 steht

Modul `seclume-postgresql` - Protokoll 3.0, eigener Wire-Code, kein `org.postgresql`:

- `WireBuffer`/`PgChannel` — Sende- und Empfangspuffer im nativen Speicher, blockweises
  Lesen, Nachrichten werden **an Ort und Stelle** ausgewertet.
- `ScramSha256` — SCRAM-SHA-256 vollständig off-heap, geprüft gegen den Vektor aus RFC 7677
  und gegen eine unabhängige Nachrechnung mit der JCA für den Fall, den PostgreSQL wirklich
  geht (leeres `n=`, UTF-8-Passwort).
- `Md5Password` — das alte Verfahren, für Bestandsserver, ebenfalls off-heap.
- `PgSession` — Startup, Auth-Verzweigung, Simple Query, `ErrorResponse` mit SQLState,
  `ParameterStatus`, `BackendKeyData`.
- `Row` — Fenster auf den Empfangspuffer statt Kopie; `getLong` kommt ohne `String` aus.
- Erweitertes Protokoll — `Parse`/`Bind`/`Describe`/`Execute`/`Sync`; ein benannter Plan
  bleibt bis zum Schließen der Anweisung im Server stehen.
- `PgParameters` — Parameter gehen im Textformat als **Parameter** über die Leitung, nie
  als Text im SQL. SQL-Injektion ist damit keine abgewehrte Gefahr, sondern eine, die es
  in dieser Bauart nicht gibt.
- JDBC-Oberfläche — `SeclumeDriver` (über `META-INF/services` und `provides` gefunden),
  `PgConnection`, `PgStatement`, `PgPreparedStatement`, `PgResultSet`,
  `PgResultSetMetaData`, `PgDatabaseMetaData`, `SeclumeDataSource`.
- `ResultBlock` — die Zeilen eines Ergebnisses liegen in **einem** nativen Block plus einem
  `int[]` mit Anfang und Länge je Zelle. Ein Java-Objekt entsteht erst bei `getString`,
  bei `getLong` gar keines. Übliche Treiber legen hier ein `Object[]` je Zeile und einen
  `String` je Zelle an.
- `PgSqlRewriter` — `?` wird zu `$1`, `$2`, … und zwar durch echtes Lesen: Textliterale,
  Bezeichner, Dollarzitate, geschachtelte Blockkommentare und die `jsonb`-Operatoren
  `?|`, `?&`, `??` bleiben unangetastet.

Nachgewiesen gegen einen **echten Server** (lokale PostgreSQL 15.1, Rolle mit
`scram-sha-256`): Anmeldung, `select`, 1.000 Zeilen, NULL und Umlaute, DDL/DML,
Serverfehler mit SQLState `42P01`, falsches Passwort mit `28P01`. Und der Heapdump-Test
mit echter Verbindung: sechs Anmeldungen, eine offene Verbindung, Dump — **kein Treffer**.

Auf JDBC-Ebene geprüft, ebenfalls gegen den echten Server: `DriverManager.getConnection`
mit der seclume-URL, `PreparedStatement` mit `uuid`/`numeric`/`bytea`/`timestamp`,
Batch, Rollback, `DatabaseMetaData.getTables`/`getColumns`/`getPrimaryKeys`,
`ResultSetMetaData` mit Präzision und Skalierung, Serverfehler mit SQLState. Ein
`password=` in der URL wird mit Begründung abgelehnt statt heimlich benutzt. Und der
Heapdump-Test **über den JDBC-Weg** — sechs Verbindungen über den `DriverManager`, eine
offen gehalten, Dump — **kein Treffer**.

Es fehlt noch: Binärformate und Typdekodierung, TLS mit Kanalbindung (`SSLRequest`,
SCRAM-SHA-256-PLUS), `COPY`, `CancelRequest` (und damit `setQueryTimeout`), Portale in
Häppchen (`setFetchSize` wird gemerkt, wirkt aber nicht), generierte Schlüssel,
Savepoints, `NOTIFY` und die Testcontainers-Suite gegen zwei Serverstände.

### Was von Stufe 4 steht

Modul `seclume-mysql` — Protokoll 4.1, eigener Wire-Code, kein `com.mysql`:

- `MyChannel` — Paketrahmen mit Folgenummern. Die Folgenummer ist der Unterschied zu
  PostgreSQL: der Server prüft sie, und sie wird an genau einer Stelle geführt.
- `NativePassword` — `mysql_native_password`, drei SHA-1-Runden und ein XOR, vollständig
  off-heap. Ein `byte[20]` mit `SHA1(passwort)` wäre so gut wie das Passwort selbst.
- `CachingSha2Password` — der Standard seit MySQL 8: schneller Weg (SHA-256), voller Weg
  über RSA-OAEP mit dem Serverschlüssel, Klartext-Weg für TLS. Die Exponentiation läuft
  auf einem nativen Wortarray, nicht auf `BigInteger`.
- `ServerPublicKey` — PEM aus dem Serverpaket, off-heap dekodiert.
- `MySession` — Handshake v10, Capability-Aushandlung, Auth-Plugin-Switch, `COM_QUERY`,
  `COM_STMT_PREPARE`/`EXECUTE`/`CLOSE`/`RESET`, `COM_PING`, `COM_RESET_CONNECTION`,
  Fehlerpakete mit Nummer und SQLState.
- `MyRow`/`BinaryValues` — Text- **und** Binärzeilen, letztere mit der Nullbitmaske und
  ihren zwei Bit Vorlauf und den längenvariablen Zeitstrukturen.
- JDBC-Oberfläche — `MyDriver`, `MyConnection` (inklusive Savepoints und
  `getGeneratedKeys`, beides kann MySQL im Gegensatz zu PostgreSQL ohne Zusatzabfrage),
  `MyStatement`, `MyPreparedStatement`, `MyResultSet`, `MyDatabaseMetaData`,
  `MyDataSource`.

Bewusst **nicht** gesetzte Fähigkeitsbits: `CLIENT_LOCAL_FILES` — damit dürfte der
*Server* den Client auffordern, eine beliebige lokale Datei zu schicken — und
`CLIENT_MULTI_STATEMENTS`, der Weg, auf dem aus einer SQL-Injektion ein zweiter Befehl
wird. `caching_sha2_password` über eine unverschlüsselte Verbindung verlangt
`allowPublicKeyRetrieval=true`, weil ein Mann in der Mitte die Frage nach dem
öffentlichen Schlüssel ebenso beantworten würde.

Geprüft ist das gegen einen **Testserver, der echte MySQL-Pakete spricht** und die
Anmeldeantwort selbst mit der JCA nachrechnet — Handshake, Rahmen, Text- und
Binärergebnisse, Fehlerpakete, die JDBC-Schicht. Dazu der Heapdump-Test: sechs
Anmeldungen aus einer eigenen JVM, Dump — **kein Treffer**, während die Gegenprobe (ein
Nutzdatenwert aus derselben Abfrage) im selben Dump **gefunden** wird; ohne diese
Gegenprobe wäre das leere Ergebnis wertlos.

Es fehlt: die Integrationssuite gegen einen echten MySQL- und MariaDB-Server (auf diesem
Rechner läuft keiner, und Docker ist aus), TLS, die Plugins `sha256_password` (der
RSA-Teil steht, der Ablauf ist ungetestet), `mysql_clear_password`, MariaDB `ed25519` und
`parsec`, `LOAD DATA LOCAL`, Multi-Resultset, Cursor in Häppchen und das
Zusammensetzen von Nutzlasten über 16 MB.

### Was Stufe 8 enthält — das Zielbild ist erreicht

Modul `seclume-spring-boot-starter`. Abhängigkeit einbinden, `application.properties`
ausfüllen, fertig — in den Tests steht keine einzige `@Bean`-Methode für eine
`DataSource` und kein Aufruf eines Treibers:

```yaml
seclume:
  datasources:
    main:
      url: jdbc:seclume:postgresql://db:5432/app
      username: app
      secret:
        provider: file
        path: /run/secrets/db-password
      pool:
        maximum-pool-size: 20
        warmup: true
```

Daraus entsteht je Eintrag eine gepoolte `DataSource`-Bean (`dataSource` bei einer,
`<name>DataSource` bei mehreren, `seclume.primary` entscheidet). Alles, was Spring an
eine `DataSource` hängt — `JdbcClient`, `JdbcTemplate`, `DataSourceTransactionManager`,
JPA, Actuator — findet sie wie jede andere.

- `provider: bean` löst eine eigene `SecretProvider`-Bean auf (Vault, KMS, HSM).
- `provider: dpapi` und `credential-manager` brechen auf Nicht-Windows mit klarer Meldung
  ab, statt still auf etwas anderes auszuweichen.
- `provider: integrated` wird erkannt und lehnt vorerst ehrlich ab — Kerberos/SSPI gehört
  zum SQL-Server-Treiber, der noch offen ist.
- Die Treibermodule sind **optionale** Abhängigkeiten; jeder liegt hinter einer eigenen
  inneren Klasse, damit die JVM den nicht eingebundenen nie lädt. Fehlt er, sagt die
  Meldung, welches Artefakt nachzutragen ist.

**`spring.datasource.password` bricht den Start ab** — ebenso ein `password` unter
`seclume.datasources.*`. Das ist der Kern: ein Passwort in der Konfiguration ist ein
`String` im `Environment`, für die Lebensdauer der Anwendung, sichtbar in jedem Heapdump
und im `/env`-Endpunkt des Actuators. Still darüber hinwegzugehen hieße, die
Kerneigenschaft unbemerkt auszuhebeln.

Geprüft mit 11 Tests gegen die echte lokale PostgreSQL: eine und mehrere Datenquellen,
Pool-Einstellungen inklusive Warmup, eigene `SecretProvider`-Bean, der Eintrag in
`AutoConfiguration.imports`, und fünf Fälle, die laut scheitern sollen.

### Wo Stufe 5 (SQL Server) steht

Modul `seclume-sqlserver`. Der Gegensatz zu Oracle ist auffällig: TDS ist als `MS-TDS`
**offen spezifiziert**, und der erste Austausch lief auf Anhieb — bei Oracle brauchte es
vier Anläufe und einen Mitschnitt.

Fertig und gegen SQL Server 2022 geprüft (`version=16.0.4265`):

- `TdsChannel` — Paketschicht mit Zusammensetzen mehrteiliger Nachrichten. Die Falle: die
  Länge im Paketkopf ist **big-endian**, als einziges Feld in ganz TDS.
- `PreLogin` — Optionstabelle aus Kennung, Versatz und Länge; der Server meldet Version
  und Verschlüsselungswunsch.
- `TdsPassword` — UTF-16LE, Halbbytes tauschen, XOR `0xA5`, **vollständig off-heap**. Der
  naheliegende Einzeiler `getBytes(UTF_16LE)` würde das Passwort auf den Heap legen; dafür
  hat der Kern eine eigene UTF-16-Umkodierung.

**Ein Befund, der im Code steht und dort hingehört:** diese Kodierung ist keine
Verschlüsselung, sondern ohne Schlüssel umkehrbar — ein Test führt das ausdrücklich vor.
Deshalb ist TLS bei SQL Server nicht optional, und der Server sagt das auch: seine Antwort
`ENCRYPT_OFF` heißt in TDS nicht „unverschlüsselt", sondern *„Verschlüsselung nur für die
Anmeldung"*. Der Treiber verlangt deshalb `ENCRYPT_ON`.

Die **Anmeldung ist vollständig** und gegen SQL Server 2022 geprüft: PRELOGIN,
TLS-Handshake **innerhalb** von TDS-Paketen, LOGIN7 mit off-heap verschleiertem Passwort,
Tokenstrom mit `LOGINACK`/`ENVCHANGE`/`ERROR`. Ergebnis:
`TLSv1.2 / TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `server=Microsoft SQL Server,
database=master, packetSize=4096`; ein falsches Passwort wird mit 18456/28000 abgelehnt.

Zwei Fallen, die erst der echte Server gezeigt hat: **TLS 1.2, nicht neuer** (1.3 sprengt
die Verschachtelung), und **eine TLS-Flugstrecke gehört in ein TDS-Paket** — einzeln
verpackt legt der Server wortlos auf. Dazu eine aus der Spezifikation: die Feldlängen in
LOGIN7 zählen **Zeichen**, die Versätze daneben **Bytes** — auch beim Passwort. Wer das
verwechselt, bekommt „Login failed for user", was wie ein falsches Passwort aussieht.

Die **Abfrageschicht steht** — bisher gegen synthetische Tokenströme geprüft, nicht gegen
einen Server, weil der Testcontainer abgebaut ist:

- `ColumnMetadata`, `TdsRow`, `TdsValues` — Spaltenbeschreibung, Zeilen (auch `NBCROW`
  mit NULL-Bitmaske und `MAX` in Blöcken), Werte einschließlich `decimal` **ohne
  `BigInteger`**.
- `TokenStream` — der Tokenstrom. Ein Fehler beendet ihn nicht: er wird gemerkt, der Rest
  zu Ende gelesen, erst danach geworfen — sonst blieben ungelesene Bytes auf der
  Verbindung.
- `TdsSession` — `SQL_BATCH` mit den 22 Byte `ALL_HEADERS` und `sp_executesql` als RPC.

Darauf die **JDBC-Oberfläche**: `TdsConnection`, `TdsStatement`, `TdsPreparedStatement`,
`TdsResultSet` (Zeilen off-heap, kein Objekt pro Zelle), `TdsDatabaseMetaData`,
`TdsDriver`, `TdsDataSource`. `?` wird zu `@P0` — gelesen, nicht ersetzt, denn in T-SQL
schachteln Blockkommentare.

Offen: ein Lauf gegen einen echten Server, Cursor in Blöcken, mehrere Ergebnisse aus einem
Batch, `ATTENTION` für `cancel()`.

### Was von Stufe 6 (Oracle) steht

Oracle ist das einzige der vier Protokolle **ohne öffentliche Spezifikation**. Deshalb
liegt hier neben dem Modul ein Dokument: `docs/protocol/oracle.md` hält fest, was belegt
ist, aus welcher Quelle (mit Lizenz, wie die Aufgabe es verlangt) und was offen ist.

Es läuft gegen einen echten Server (Oracle Free 23ai):

- **Anmeldung** über den 12c-Pfad: PBKDF2-SHA512, AES-256-CBC, der 32-Byte-Sitzungs-
  schlüssel aus beiden Hälften als Hextext. Nicht geraten, sondern **gemessen** — an
  einem aufgezeichneten Handschlag, dessen Passwort lokal bekannt war, ließ sich die
  richtige Ableitung identifizieren statt vermuten. Alles off-heap.
- **Abfragen** über TTC-Funktion 94: Spaltenbeschreibung, Zeilenblöcke, Bitvektor,
  Fetch-Schleife, Fehlerbehandlung.
- **Bindevariablen** und **DDL/DML** mit der Zahl der geänderten Zeilen.
- **Typen**: `NUMBER` (eigenes Basis-100-Format, ohne `BigDecimal` auf dem Weg),
  `VARCHAR2`, `CHAR`, `DATE`, `TIMESTAMP`, `RAW`, `LONG`.
- **JDBC-Oberfläche**: `Driver`, `DataSource`, `Connection`, `Statement`,
  `PreparedStatement` mit Stapel, `ResultSet`, `DatabaseMetaData`.

Wie das gefunden wurde, ist der interessantere Teil und steht ausführlich in
`docs/protocol/oracle.md`: nicht durch Raten, sondern durch Aufnahmen. Die
lehrreichste Regel daraus — **eine Aufnahme, in der jedes Feld null und einbytig ist,
belegt gar nichts**: drei verschiedene falsche Lesarten der Spaltenbeschreibung passten
gleich gut auf dieselben Bytes, und erst eine Abfrage über `NUMBER(9,2)`, `VARCHAR2(40)`
und `DATE` nebeneinander hat entschieden.

Offen und ausdrücklich **nicht** geraten: LOBs (`CLOB`/`BLOB`), Array-Binds als eine
Nachricht, NTS/Kerberos.

### Was Stufe 7 enthält

Modul `seclume-pool` — hängt nur an `javax.sql.DataSource`, nicht an einem Treiber, und
hat keine Fremdabhängigkeit:

- `SeclumePool` — min/max, Connection-, Idle-, Lifetime- und Keepalive-Timeout, Warmup,
  Leck-Erkennung mit dem Stacktrace der Ausleihe.
- **Der Ausleihpfad fasst kein Schloss und keinen gemeinsamen Zähler an.** Die freien
  Verbindungen liegen als Slots in einem Array, jeder Thread startet an seinem eigenen
  Slot (Hash der Thread-ID, ausdrücklich **kein `ThreadLocal`** — das taugt bei
  Millionen virtueller Threads nichts). Gemessen: von 64 µs auf **0,27 µs** je
  Ausleihe. HikariCP liegt bei 0,10 µs und damit weiter vorn — sein schneller Pfad ist ein
  `ThreadLocal`, was bei acht Plattform-Threads unschlagbar und bei einer Million
  virtueller Threads unbrauchbar ist. Sobald eine Abfrage dazwischenliegt, ist der
  Unterschied Rauschen.
- **Validierung nur nach Ruhezeit.** Eine Verbindung, die gerade zurückkam, wird ohne
  Nachfrage beim Server wieder ausgegeben; erst nach `validation-bypass-window`
  (Vorgabe 500 ms Ruhe) wird geprüft. Der Unterschied ist keine Feinheit: eine Prüfung je
  Ausleihe ist ein **kompletter Roundtrip**, und genau daran hing der Pool in der ersten
  Messung — 64 µs je Ausleihe gegen 0,4 µs bei HikariCP. Wer die paranoide Variante will,
  setzt das Fenster auf null.
- `PooledConnection` — `close()` gibt zurück statt zu schließen; davor wird eine offene
  Transaktion zurückgerollt und `autoCommit`/`readOnly`/Isolationsstufe auf den
  Ausgangswert gesetzt. Sonst erbt der nächste Anwender einen Zustand, den er nie gesetzt
  hat. Scheitert das Aufräumen, wird die Verbindung geschlossen statt zurückgelegt.
- Ein Fehler aus dem SQLState-Bereich `08` (Verbindung) wirft die Verbindung weg, ein
  Syntaxfehler nicht.

**Der Pool hält kein Geheimnis** — er sieht keines. Ein Neuaufbau ist schlicht ein
weiterer `getConnection()` an der darunterliegenden `DataSource`, und die fragt den
`SecretProvider` erneut. Scheitert der, scheitert der Aufbau; einen gecachten Ausweg gibt
es nicht, denn das wäre ein Passwort im Heap. `getConnection(user, password)` wirft mit
Begründung, und `toString()`/`PoolStatistics` enthalten ausschließlich Zahlen.

**Virtual-Thread-tauglich**, und das ist kein Etikett:

- kein `synchronized` um blockierende Aufrufe (ein virtueller Thread, der in einem Monitor
  blockiert, nimmt seinen Trägerthread mit),
- kein `ThreadLocal`-Zwischenspeicher für zuletzt benutzte Verbindungen — bei Millionen
  virtueller Threads ist das ein Speicherleck mit Trefferquote nahe null,
- Vergabe über `Semaphore` und `ConcurrentLinkedDeque`, beide ohne Monitor.

Geprüft mit 13 Tests ohne Datenbank (Stub-`DataSource`: Größe, Wiederverwendung, Timeout,
Zustandsrücksetzung, kaputte Verbindungen, doppeltes `close()`, 500 virtuelle Threads) und
6 Tests gegen die echte lokale PostgreSQL — dort unter anderem: 200 virtuelle Threads
teilen sich nachweislich höchstens acht `pg_backend_pid()`, und nach `close()` steht keine
der Sitzungen mehr in `pg_stat_activity`.

Dieser Test hat einen **echten Fehler im Treiber** gefunden: `WireBuffer` benutzte
`Arena.ofConfined()`, also einen Speicherbereich, der an den erzeugenden Thread gebunden
ist. Eine Verbindung, die auf einem anderen virtuellen Thread zurückgegeben wird, ließ sich
damit nicht schließen (`WrongThreadException`) — genau der Fall, für den es einen Pool
gibt. Jetzt ist es eine geteilte Arena; das kostet beim Schließen etwas, einmal je
Verbindung.

Offen: die Micrometer-Anbindung (optional, nur wenn im Classpath) und ein JMH-Vergleich
gegen HikariCP.

### Gemeinsames Geschirr

Mit dem zweiten Treiber ist zusammengezogen, was beide brauchen — sonst stünde es
spätestens beim vierten viermal da:

- `internal.WireBuffer` — der native Puffer, jetzt mit beiden Byteordnungen.
- `internal.JdbcUrl` — das Zerlegen der URLs, damit `provider=file` überall dasselbe
  heißt und ein `password=` überall gleich abgelehnt wird.
- `internal.jdbc.ReadOnlyResultSet` — das Gerüst eines vorwärtsgerichteten, nur lesenden
  `ResultSet`: die knapp 190 Methoden, die es nicht gibt, stehen einmal da. `PgResultSet`
  ist dadurch von 1246 auf 165 Zeilen geschrumpft.
- `internal.jdbc.ParameterSetters` — die vierzig `set...`-Methoden als Schnittstelle mit
  Standardmethoden (keine Oberklasse: ein `PreparedStatement` ist immer auch das
  `Statement` seines Treibers, und Java kennt nur eine Oberklasse).

### Was Stufe 2 enthält

`seclume-tck` — der Beweismechanismus, gebaut **vor** dem ersten Treiber:

- `HprofParser` — liest einen Heapdump und meldet jedes `byte[]` und `char[]`. Unbekannte
  Satzarten führen zum Abbruch statt zum Weiterraten: ein stiller Fehltritt hieße, dass der
  Test nichts findet und grün wird — der schlimmste denkbare Ausgang.
- `HeapDumpScanner` — sucht roh über die ganze Datei (`strings | grep`) **und** strukturiert
  über alle primitiven Arrays (MAT/OQL), jeweils in UTF-8, UTF-16BE, UTF-16LE und Base64.
  Ein Fund nennt Art, Ort und Länge, nie den Inhalt.
- `SecretHolderProbe` — eine eigene JVM, die ein Zufallspasswort so benutzt wie ein Treiber
  und danach ihren Heap ausschreibt (`live=false`, also inklusive toter Objekte). Das Passwort
  kommt über eine Datei herein, nie über ein Argument.
- `StaticSecretProvider` — die Negativkontrolle: hält das Passwort absichtlich als `String`
  und `byte[]`.

Gemessen auf diesem Rechner, 5 Zyklen je Lauf:

| Lauf | Dump | geparste Arrays | roher Scan | strukturierter Scan |
|------|------|-----------------|-----------|---------------------|
| off-heap | 5,1 MB | 9.897 | 0 Treffer | 0 Treffer |
| off-heap, Scope **offen** während des Dumps | 5,1 MB | ~9.900 | 0 Treffer | 0 Treffer |
| leckend (Kontrolle) | 5,0 MB | 9.894 | **2 Treffer** | **2 Treffer** |

### Was Stufe 1 enthält

**Geheimnisquellen** (`space.seclume.secret`)

| Provider | Quelle | Plattform |
|----------|--------|-----------|
| `FileSecretProvider` | Datei, gelesen per `FileChannel` in einen direkten Puffer | alle |
| `EnvFileSecretProvider` | `.env`-Datei, Schlüsselsuche off-heap | alle |
| `UnixSocketSecretProvider` | AF_UNIX-Socket (Vault-Agent, Sidecar) | Unix |
| `ProcessSecretProvider` | Helfer schreibt in eine FIFO | Unix |
| `CallbackSecretProvider` | eigene Lambda (Vault, KMS, HSM) | alle |
| `DpapiSecretProvider` | DPAPI-Blob als Datei, `crypt32!CryptUnprotectData` | Windows |
| `CredentialManagerSecretProvider` | `advapi32!CredReadW`, Generic Credential | Windows |

**Off-Heap-Krypto** (`space.seclume.crypto`) — MD5, SHA-1, SHA-256, SHA-512, HMAC
darüber, PBKDF2-HMAC, AES-128/192/256 in CBC und CFB, RSA (PKCS#1 v1.5 und OAEP) mit
eigener Langzahlarithmetik, Konstantzeit-Vergleich. Alles auf `MemorySegment`, alle
Zwischenzustände off-heap und genullt.

Nachgewiesen durch 107 Tests: die offiziellen Vektoren (RFC 1321, FIPS 180-4, RFC 2202,
RFC 4231, RFC 6070, FIPS 197, NIST SP 800-38A) **und** Kreuzvergleiche gegen die JCA über
viele zufällige Längen — die Vektoren zeigen, dass das Verfahren stimmt, die Kreuzvergleiche
finden die Fehler in Puffergrenzen und Padding.

---

## Zielbild

Am Ende soll das hier reichen - Abhängigkeit einbinden, `application.properties` ausfüllen,
fertig. Kein Treiber-Setup, kein Pool-Setup, keine Extraklasse:

```properties
seclume.datasources.main.url=jdbc:seclume:postgresql://db:5432/app
seclume.datasources.main.username=app
seclume.datasources.main.secret.provider=file
seclume.datasources.main.secret.path=/run/secrets/db-password
seclume.datasources.main.pool.maximum-pool-size=20
```

Der einzige Unterschied zu `spring.datasource.*` ist die eine Zeile, die es nicht gibt:
**das Passwort steht nicht in der Konfiguration**, sondern nur, woher es kommt. Alles
andere - `DataSource`, `JdbcClient`, `DataSourceTransactionManager`, JPA,
`SQLExceptionTranslator`, Actuator-Health - richtet der Starter selbst ein.

Wer `spring.datasource.password` setzt, bekommt beim Start einen Abbruch mit klarer
Meldung statt einer stillen Aushebelung der Kerneigenschaft.

### Was davon heute schon geht

**Das oben, und zwar für alle vier Datenbanken.** Der Starter kennt jedes Präfix und lädt
den passenden Treiber - und nur den, denn die vier Module sind optionale Abhängigkeiten:

```properties
seclume.datasources.main.url=jdbc:seclume:postgresql://db:5432/app
seclume.datasources.main.url=jdbc:seclume:mysql://db:3306/app
seclume.datasources.main.url=jdbc:seclume:mariadb://db:3306/app
seclume.datasources.main.url=jdbc:seclume:sqlserver://db:1433/app
seclume.datasources.main.url=jdbc:seclume:oracle://db:1521/FREEPDB1
```

Bei Oracle steht an der Stelle der Datenbank der **Service**; sonst ist nichts anders.
Steht ein Präfix ohne das zugehörige Modul in der Konfiguration, nennt der Abbruch die
fehlende Abhängigkeit statt einen `NoClassDefFoundError` zu werfen.

Ohne Spring geht dasselbe über `DriverManager`:

```java
String url = "jdbc:seclume:postgresql://db:5432/app"
           + "?user=app&provider=file&path=/run/secrets/db-password";
try (Connection connection = DriverManager.getConnection(url)) {
    ...
}
```

Oder über eine `DataSource`:

```java
SeclumeDataSource dataSource = new SeclumeDataSource();
dataSource.setHost("db");
dataSource.setDatabase("app");
dataSource.setUser("app");
dataSource.setProperty("provider", "file");
dataSource.setProperty("path", "/run/secrets/db-password");
```

Die Schlüssel hinter `provider` sind dieselben, die später in
`seclume.datasources.*.secret.*` stehen - `SecretProviders` ist die eine Stelle, an der
aus einem Namen eine Quelle wird, für URL und Starter gleichermaßen.

`getConnection(user, password)` gibt es nicht: der Aufruf nimmt das Passwort als `String`,
und damit wäre es für die Lebensdauer der Anwendung im Heap. Er wirft mit dieser
Begründung.

---

## Prüfen gegen echte Datenbanken (CI)

`.github/workflows/ci.yml` startet die Datenbanken als Service-Container und lässt die
Tests dagegen laufen — PostgreSQL 15 **und** 18, MySQL 8.4 **und** MariaDB 11.4,
Oracle Free 23ai, dazu ein bereitstehender SQL Server 2022.

Das ist nicht Kosmetik, sondern der fehlende Baustein. Auf einem Entwicklungsrechner
steht selten mehr als eine Datenbank, und ein selbstgebauter Testserver bestätigt nur die
eigenen Annahmen. Erst hier wird aus „compiliert und wirkt plausibel" ein Nachweis — und
zwei Serverstände je Produkt zeigen Protokollunterschiede, bevor ein Anwender sie findet.

Das Passwort geht auch in der CI über eine **Datei** herein, also über den Weg, den die
Bibliothek anbietet: kein `echo`, keine Umgebungsvariable im Log.

**Ehrlich dazu:** die Jobs für MySQL und Oracle laufen heute nur gegen die vorhandenen
Tests — Protokoll- und Krypto-Tests. Die eigentlichen Integrationssuiten gegen diese
Server sind noch zu schreiben; sie stehen in der Liste der offenen Punkte. Der Job für
SQL Server hält nur den Platz frei, weil Stufe 5 nicht begonnen ist.

### Warum sich das Projekt für Mitarbeit eignet

Der Kern dieser Bibliothek ist eine Zusage, die man versehentlich zerstören kann: eine
einzige `new String(...)` an der falschen Stelle, und das Passwort steht wieder im Heap.
Bei den meisten Sicherheitsbibliotheken müsste man darauf vertrauen, dass ein Beitrag das
nicht tut. Hier nicht:

- `ForbiddenApiTest` liest den eigenen Quelltext und schlägt an, wenn jemand `new String`,
  `getBytes`, `BigInteger`, `javax.crypto` oder `char[]` einführt, ohne es mit
  `// seclume-allow: <grund>` zu begründen.
- Der Heapdump-Test schreibt aus einer zweiten JVM einen echten Dump und durchsucht ihn —
  **mit Gegenprobe**: ein Nutzdatenwert derselben Abfrage *muss* gefunden werden, sonst
  wäre das leere Ergebnis fürs Passwort wertlos.

Ein Beitrag, der die Kerneigenschaft bricht, wird also rot, ohne dass jemand ihn dafür
lesen muss. Das ist für ein offenes Projekt mehr wert als jede Richtlinie im Wiki.

## Bauen

```
./mvnw clean test
```

Der Windows-Plattformtest (DPAPI, Credential Manager) läuft automatisch mit, wenn er auf
Windows ausgeführt wird, und wird sonst übersprungen.

---

## Provisionierung unter Windows

Ohne Vault-Infrastruktur ist der eingebaute Schlüsselspeicher der richtige Weg:

```powershell
# DPAPI, an den ausführenden Benutzer gebunden - für einen Dienst als das Dienstkonto ausführen
Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File -Encoding ascii C:\ProgramData\app\db.dpapi
```

```powershell
# Credential Manager, generische Anmeldeinformation
cmdkey /generic:seclume/reporting /user:app /pass
```

---

## Geschwindigkeit

Ziel ist nicht nur „schnell genug", sondern schneller als die etablierten Java-Treiber.
Der Off-Heap-Aufbau hilft dabei; was das im Einzelnen bedeutet und wo es Grenzen hat, steht
in [`docs/performance.md`](docs/performance.md).

Die Kopfzahlen, alle nachgerechnet und mit Herleitung dort:

| Messung | seclume | Herstellertreiber |
|---|---|---|
| Stapel von 500 Zeilen, MySQL über LAN (604 µs RTT) | 18,7 ms | 278,6 ms (Connector/J) |
| Ausleihen, Abfrage, Zurückgeben (8 Threads, lokal) | 62,4 µs | 70,9 µs (HikariCP + pgjdbc) |
| dieselbe Form mit `PreparedStatement` und Statement-Cache | **58,9 µs** | — (111,4 µs ohne Cache) |
| `@Transactional`-Methode mit einer Abfrage | **2 Rundreisen** | 7 |
| Stapel von 200 Zeilen, SQL Server | **1 Rundreise** | 200 (vorher, eigener Treiber) |

Zwei Befunde, die dabei herauskamen und mehr wert sind als die Zahlen selbst: das Schließen
einer **shared Arena** kostete die Hälfte der Laufzeit unter Last (jetzt behoben), und
Oracle brauchte für die zweite Ausführung eines Prepared Statements eine Rundreise zu viel,
weil ein Feld im Aufruf auf null stand.

---

## Ehrlichkeitsregeln

- Kein Platzhalter, der so tut, als funktioniere er. Nicht Implementiertes wirft.
- Keine „vorläufige" Delegation an einen Herstellertreiber, auch nicht auskommentiert.
- Ist ein Protokolldetail nicht sicher rekonstruierbar, steht das in `docs/protocol/<db>.md`
  und das Feature gilt als nicht unterstützt, statt geraten zu werden.
- Testergebnisse werden mit Ausgabe berichtet. „Sollte funktionieren" zählt nicht.
