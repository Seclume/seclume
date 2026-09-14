# seclume

JDBC drivers and a connection pool for PostgreSQL, MySQL/MariaDB, Microsoft SQL Server and
Oracle, whose core property is: **database passwords never appear as a `String` or `char[]` on
the Java heap and are therefore not findable in an hprof heap dump.**

Java 25, Spring Boot 4.x / Spring Framework 7.x. No runtime dependencies beyond the JDK and
Spring. No vendor driver is used, wrapped or delegated to.

---

## Threat model

**IN SCOPE** — what the library protects against:

- An hprof heap dump (`jmap`, `-XX:+HeapDumpOnOutOfMemoryError`, JFR, the Actuator's
  `/heapdump`, a support upload) falls into an attacker's hands, minutes or years after the
  connect.
- The dump is searched both through the object graph (MAT/OQL) and raw (`strings | grep`) —
  both have to come up empty.

**OUT OF SCOPE** — what seclume does not solve and does not try to:

- An attacker with live process access (ptrace, gcore, a debugger). They will use the pool's
  open connections anyway.
- A compromised kernel or hypervisor.
- The window of a few microseconds during the handshake itself.

From which follows a recommendation that makes the whole effort unnecessary wherever it can be
followed: **operating-system integrated authentication** (SSPI/Kerberos, PostgreSQL `gss`/`sspi`,
SQL Server Integrated Security, Oracle NTS). There is no secret in the process there that could
be lost — not even for the microseconds of the handshake. Password authentication is the
fallback for everything that is not in a domain.

`/heapdump` may stay exposed, by the way. That is the point.

---

## Further databases

Two items beyond the brief are on the plan, in this order:

**CockroachDB and YugabyteDB** speak the PostgreSQL wire protocol. Probably **no new driver is
needed** here — only proof that the existing one serves them. That costs a CI run, and that is
exactly where it is entered. It is evidence only once it is green, though; until then it is a
guess.

**DB2 / IBM i** is the only candidate worth a *new* driver — and only once the four existing
ones are finished. The reason is not technical but environmental: banks, insurers and public
authorities, that is, exactly the places with static database passwords by policy and with
memory dumps that go to vendors. The protocol (DRDA) is openly documented, so it would be
TDS-class effort, not Oracle-class.

Deliberately **not** on the plan: H2 and HSQLDB (embedded — the database itself sits in the
heap, where the core property does not carry), SAP HANA (proprietary protocol without a
specification, Oracle-class effort for a smaller benefit), and anything without JDBC.

## Relationship to Vault, IAM and rotation

The obvious question: does seclume make a vault unnecessary — or is it the vault that makes
seclume unnecessary? Neither, and the distinction is worth drawing.

**Against a vault holding a static password** — the case that dominates in practice: a secret
store whose content is rotated yearly, if at all — „mounted file + seclume" is not worse but
better in one respect:

| | Vault with a static password | File + seclume |
|---|---|---|
| Not in image, env, properties | ✅ | ✅ (`/run/secrets/...`) |
| Not in the JVM heap | ❌ | ✅ |
| Audit trail, central policy | ✅ | ❌ |
| Extra component in the startup path | yes (sidecar, token renewal, unsealing) | no |

The vault loses the second row, and unavoidably so: the moment the Java application fetches the
secret, it is a `String` in the heap and stays there until the GC happens to overwrite it. Vault
protects the road *to* the process, not the state *inside* it.

**Against short-lived credentials** — Vault's database engine, IAM auth on RDS or Cloud SQL —
seclume clearly loses. Whoever uses credentials that expire after minutes limits the *window*
and not merely the attack surface. That is stronger than any protection at rest, and whoever can
have it should take it.

**Both together is best.** `secret.provider: bean` exists for exactly that: the vault delivers,
seclume makes sure what was delivered never sees the heap.

**And the limit:** seclume moves the weak point to the source. Whoever can read the container's
file tree or take a core dump has the secret — which the threat model above names explicitly as
*out of scope*. What is closed is the one road that is open today and that no vault closes: the
heap dump.

## Secret sources that cannot be supported

These sources are **not** supportable with seclume, and fundamentally so, not out of
convenience:

- **Environment variables.** `ProcessEnvironment` is filled as a `Map<String,String>` at JVM
  startup and never released; the string exists before library code runs. `DB_PASSWORD=…` is
  therefore not securable.
- **Command line arguments.** Readable from outside the process as well, through
  `/proc/<pid>/cmdline` or `Win32_Process.CommandLine`.
- **HTTP secret endpoints through `java.net.http.HttpClient`** — its response handlers return
  strings. Such a provider presupposes an off-heap HTTP parser of its own and is therefore not
  part of what ships.
- **Binding as `char[]` by Spring Boot.** Still to be written:
  the `char[]` arrives at the end of a pure string chain and is itself heap.

---

## State

The build follows the milestones of the brief; every stage is finished, running and tested,
before the next one starts.

| Stage | Content | State |
|-------|---------|-------|
| 1 | `seclume-core`: `SecretProvider`, `SecretScope`, off-heap crypto | **done** |
| 2 | hprof parser and heap dump test harness including the negative control | **done** |
| 3 | PostgreSQL driver | **done** (protocol, SCRAM, extended protocol, JDBC surface, block cursors, generated keys) |
| 4 | MySQL/MariaDB | **done** (protocol, login, JDBC surface; integration suite against MySQL 8.4 green) |
| 5 | Microsoft SQL Server | **done** (login, queries, JDBC surface; integration run against SQL Server 2022 green) |
| 6 | Oracle | **done** (login, queries, bind variables, DDL/DML, **transactions**, **array batches**, cursor reuse, JDBC surface; integration run against Oracle Free 23ai green; **LOBs** complete: read and write, `Clob`/`Blob`, streams, a slice in one round trip, `createClob`/`createBlob` — open: server-side temporary LOBs) |
| 7 | Connection pool | **done** — including Micrometer, health indicator, statement cache, leak detection and a timeout message that names the oldest holders |
| 8 | Spring Boot starter | **done** |
| 9 | README, threat model, migration guide | partly (this document) |
| — | **Distributed transactions (XA)** in all four drivers, off by default | **done** — checked against real servers, see [`docs/xa.md`](docs/xa.md) |
| — | **Cursors in blocks** (`setFetchSize`) | **done** in all four (SQL Server without bind values) |
| — | **Resilience stage 1**: host list and failover on connect | **done**, see [`docs/resilience.md`](docs/resilience.md) |
| — | **Pipelined block**: one round trip for a whole unit of work | **done** (PostgreSQL and MySQL bundle) |
| — | **NS trace** (`-Dseclume.oracle.trace=true`): every Oracle packet in both directions, **framing only, never contents** | **done** — the tool that found three protocol faults |
| — | **`seclume-verify`**: preflight report on server, secret source, capabilities and round trips | **done** |
| — | **`seclume-heapcheck`**: proves for *any* running Java process whether a secret is in its heap | **done** |
| — | **`RdsIamSecretProvider`**: AWS RDS IAM token signed rather than fetched, never a `String` | **done** |
| — | **`seclume-spring-test`**: Spring Data, Hibernate and Flyway on seclume | **done** against PostgreSQL and Oracle, MySQL prepared |
| 10 | Prove the PostgreSQL family: CockroachDB, YugabyteDB | open (CI only, no driver) |
| — | `seclume-bench`: JMH against the vendor drivers and HikariCP | **standing** — and it delivers the first clear lead: **a factor of 15 against MySQL Connector/J** on a batch over a real network. Numbers and reasoning in `docs/performance.md` |
| 11 | DB2 / IBM i (DRDA) | open, after the four existing ones |
| **Z** | **`seclume-tcp-core`** — a portable userspace transport core (TUN/utun/Wintun) so a live connection can move between **Linux, Windows and macOS**; JDBC is the first adapter, not the purpose | **a declared goal**, own project, packet I/O on Windows proven — architecture and order in [`docs/mobility.md`](docs/mobility.md) |

### What stage 3 consists of

Module `seclume-postgresql` — protocol 3.0, wire code of its own, no `org.postgresql`:

- `WireBuffer`/`PgChannel` — send and receive buffers in native memory, block-wise reading,
  messages evaluated **in place**.
- `ScramSha256` — SCRAM-SHA-256 entirely off-heap, checked against the vector from RFC 7677 and
  against an independent recomputation with the JCA for the case PostgreSQL actually takes
  (empty `n=`, UTF-8 password).
- `Md5Password` — the old method, for legacy servers, also off-heap.
- `PgSession` — startup, auth branching, simple query, `ErrorResponse` with SQLState,
  `ParameterStatus`, `BackendKeyData`.
- `Row` — a window onto the receive buffer instead of a copy; `getLong` manages without a
  `String`.
- Extended protocol — `Parse`/`Bind`/`Describe`/`Execute`/`Sync`; a named plan stays in the
  server until the statement is closed.
- `PgParameters` — parameters travel in text format as **parameters**, never as text inside the
  SQL. SQL injection is therefore not a danger that is fended off but one that does not exist in
  this construction.
- JDBC surface — `SeclumeDriver` (found through `META-INF/services` and `provides`),
  `PgConnection`, `PgStatement`, `PgPreparedStatement`, `PgResultSet`, `PgResultSetMetaData`,
  `PgDatabaseMetaData`, `SeclumeDataSource`.
- `ResultBlock` — the rows of a result live in **one** native block plus an `int[]` with start
  and length per cell. A Java object appears only at `getString`, and at `getLong` none at all.
  Usual drivers put an `Object[]` per row and a `String` per cell here.
- `PgSqlRewriter` — `?` becomes `$1`, `$2`, … and by actually reading: text literals,
  identifiers, dollar quoting, nested block comments and the `jsonb` operators `?|`, `?&`, `??`
  are left untouched.

Proven against a **real server** (a local PostgreSQL 15.1, role with `scram-sha-256`): login,
`select`, 1,000 rows, NULL and umlauts, DDL/DML, a server error with SQLState `42P01`, a wrong
password with `28P01`. And the heap dump test with a real connection: six logins, one open
connection, dump — **no hit**.

Checked at the JDBC level, again against the real server: `DriverManager.getConnection` with
the seclume URL, `PreparedStatement` with `uuid`/`numeric`/`bytea`/`timestamp`, batch,
rollback, `DatabaseMetaData.getTables`/`getColumns`/`getPrimaryKeys`, `ResultSetMetaData` with
precision and scale, server errors with SQLState. A `password=` in the URL is rejected with a
reason rather than quietly used. And the heap dump test **through the JDBC route** — six
connections through `DriverManager`, one held open, dump — **no hit**.

Still missing: binary formats and type decoding, TLS with channel binding (`SSLRequest`,
SCRAM-SHA-256-PLUS), `COPY`, `CancelRequest` (and with it `setQueryTimeout`), portals in
portions (`setFetchSize` is remembered but has no effect), generated keys, savepoints, `NOTIFY`
and the Testcontainers suite against two server versions.

### What stage 4 consists of

Module `seclume-mysql` — protocol 4.1, wire code of its own, no `com.mysql`:

- `MyChannel` — packet framing with sequence numbers. The sequence number is the difference to
  PostgreSQL: the server checks it, and it is kept in exactly one place.
- `NativePassword` — `mysql_native_password`, three SHA-1 rounds and an XOR, entirely off-heap.
  A `byte[20]` holding `SHA1(password)` would be as good as the password itself.
- `CachingSha2Password` — the default since MySQL 8: the fast path (SHA-256), the full path
  through RSA-OAEP with the server key, the cleartext path for TLS. The exponentiation runs on a
  native word array, not on `BigInteger`.
- `ServerPublicKey` — PEM out of the server packet, decoded off-heap.
- `MySession` — handshake v10, capability negotiation, auth plugin switch, `COM_QUERY`,
  `COM_STMT_PREPARE`/`EXECUTE`/`CLOSE`/`RESET`, `COM_PING`, `COM_RESET_CONNECTION`, error
  packets with number and SQLState.
- `MyRow`/`BinaryValues` — text **and** binary rows, the latter with the null bitmap and its two
  bits of lead-in and the length-variable time structures.
- JDBC surface — `MyDriver`, `MyConnection` (including savepoints and `getGeneratedKeys`, both
  of which MySQL can do without an extra query, unlike PostgreSQL), `MyStatement`,
  `MyPreparedStatement`, `MyResultSet`, `MyDatabaseMetaData`, `MyDataSource`.

Capability bits deliberately **not** set: `CLIENT_LOCAL_FILES` — with it the *server* could ask
the client to send an arbitrary local file — and `CLIENT_MULTI_STATEMENTS`, the road on which an
SQL injection becomes a second command. `caching_sha2_password` over an unencrypted connection
requires `allowPublicKeyRetrieval=true`, because a man in the middle would answer the question
for the public key just as readily.

That is checked against a **test server that speaks real MySQL packets** and recomputes the
login answer itself with the JCA — handshake, framing, text and binary results, error packets,
the JDBC layer. Plus the heap dump test: six logins from a JVM of its own, dump — **no hit**,
while the counter-check (a payload value from the same query) **is found** in the same dump;
without that counter-check the empty result would be worthless.

Missing: TLS, the plugins `sha256_password` (the RSA part stands, the flow is untested),
`mysql_clear_password`, MariaDB `ed25519` and `parsec`, `LOAD DATA LOCAL`, multi-resultset,
cursors in portions and the reassembly of payloads over 16 MB.

### What stage 8 contains — the target picture is reached

Module `seclume-spring-boot-starter`. Add the dependency, fill in `application.properties`,
done — the tests contain not a single `@Bean` method for a `DataSource` and no call into a
driver:

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

Out of that comes one pooled `DataSource` bean per entry (`dataSource` for one,
`<name>DataSource` for several, `seclume.primary` decides). Everything Spring hangs on a
`DataSource` — `JdbcClient`, `JdbcTemplate`, `DataSourceTransactionManager`, JPA, Actuator —
finds it like any other.

- `provider: bean` resolves a `SecretProvider` bean of your own (Vault, KMS, HSM).
- `provider: dpapi` and `credential-manager` abort on non-Windows with a clear message instead
  of quietly falling back to something else.
- `provider: integrated` is recognised and honestly declined for now — Kerberos/SSPI belongs to
  the SQL Server driver.
- The driver modules are **optional** dependencies; each sits behind an inner class of its own
  so the JVM never loads one that is not on the classpath. If it is missing, the message says
  which artefact to add.

**`spring.datasource.password` aborts the startup** — and so does a `password` under
`seclume.datasources.*`. That is the crux: a password in the configuration is a `String` in the
`Environment`, for the lifetime of the application, visible in every heap dump and in the
Actuator's `/env` endpoint. Passing over it quietly would mean disabling the core property
unnoticed.

Checked with 11 tests against the real local PostgreSQL: one and several data sources, pool
settings including warmup, a `SecretProvider` bean of your own, the entry in
`AutoConfiguration.imports`, and five cases that are supposed to fail loudly.

### Where stage 5 (SQL Server) stands

Module `seclume-sqlserver`. The contrast with Oracle is striking: TDS is **openly specified**
as `MS-TDS`, and the first exchange worked straight away — with Oracle it took four attempts and
a packet capture.

Done and checked against SQL Server 2022 (`version=16.0.4265`):

- `TdsChannel` — the packet layer with reassembly of multi-part messages. The trap: the length
  in the packet header is **big-endian**, the only field in all of TDS that is.
- `PreLogin` — an option table of token, offset and length; the server reports version and its
  encryption wish.
- `TdsPassword` — UTF-16LE, swap nibbles, XOR `0xA5`, **entirely off-heap**. The obvious
  one-liner `getBytes(UTF_16LE)` would put the password on the heap; for that the core has a
  UTF-16 transcoding of its own.

**A finding that is in the code and belongs there:** this encoding is not encryption but
reversible without a key — a test demonstrates it explicitly. That is why TLS is not optional
with SQL Server, and the server says so too: its answer `ENCRYPT_OFF` does not mean
„unencrypted" in TDS but *„encryption for the login only"*. The driver therefore insists on
`ENCRYPT_ON`.

The **login is complete** and checked against SQL Server 2022: PRELOGIN, the TLS handshake
**inside** TDS packets, LOGIN7 with an off-heap obfuscated password, a token stream of
`LOGINACK`/`ENVCHANGE`/`ERROR`. Result: `TLSv1.2 /
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `server=Microsoft SQL Server, database=master,
packetSize=4096`; a wrong password is refused with 18456/28000.

Two traps only the real server revealed: **TLS 1.2, not newer** (1.3 breaks the nesting), and **a
TLS flight belongs in one TDS packet** — wrapped individually, the server hangs up without a
word. Plus one from the specification: the field lengths in LOGIN7 count **characters**, the
offsets next to them **bytes** — for the password too. Confusing the two yields „Login failed for
user", which looks like a wrong password.

The **query layer stands**:

- `ColumnMetadata`, `TdsRow`, `TdsValues` — column description, rows (including `NBCROW` with a
  null bitmap and `MAX` in chunks), values including `decimal` **without `BigInteger`**.
- `TokenStream` — the token stream. An error does not end it: it is remembered, the rest is read
  to the end, and only then is it thrown — otherwise unread bytes would be left on the
  connection.
- `TdsSession` — `SQL_BATCH` with the 22 bytes of `ALL_HEADERS` and `sp_executesql` as an RPC.

On top of it the **JDBC surface**: `TdsConnection`, `TdsStatement`, `TdsPreparedStatement`,
`TdsResultSet` (rows off-heap, no object per cell), `TdsDatabaseMetaData`, `TdsDriver`,
`TdsDataSource`. `?` becomes `@P0` — by reading, not by replacing, because block comments nest in
T-SQL.

Open: cursors in blocks, several results out of one batch, `ATTENTION` for `cancel()`.

### What stage 6 (Oracle) consists of

Oracle is the only one of the four protocols **without a public specification**. That is why a
document sits next to the module: `docs/protocol/oracle.md` records what is established, from
which source (with its licence, as the brief demands) and what is open.

It runs against a real server (Oracle Free 23ai):

- **Login** through the 12c path: PBKDF2-SHA512, AES-256-CBC, the 32-byte session key from both
  halves as hex text. Not guessed but **measured** — against a recorded handshake whose password
  was known locally, the right derivation could be identified rather than assumed. All off-heap.
- **Queries** through TTC function 94: column description, row blocks, bit vector, fetch loop,
  error handling.
- **Bind variables** and **DDL/DML** with the number of changed rows.
- **Types**: `NUMBER` (a base-100 format of its own, with no `BigDecimal` on the way),
  `VARCHAR2`, `CHAR`, `DATE`, `TIMESTAMP`, `RAW`, `LONG`.
- **LOBs**: read and write, `Clob`/`Blob`, streams, `createClob`/`createBlob`. A slice costs one
  round trip and brings the slice — 4096 characters out of 200,000, the rest stays on the
  server. Details in [`docs/protocol/oracle-lob.md`](docs/protocol/oracle-lob.md).
- **JDBC surface**: `Driver`, `DataSource`, `Connection`, `Statement`, `PreparedStatement` with
  batches, `ResultSet`, `DatabaseMetaData`.

How that was found is the more interesting part and is written out in
`docs/protocol/oracle.md`: not by guessing but from recordings. The most instructive
rule out of it — **a recording in which every field is zero and one byte wide establishes
nothing**: three different wrong readings of the column description fitted the same bytes
equally well, and only a query over `NUMBER(9,2)`, `VARCHAR2(40)` and `DATE` side by side
decided it.

Open and explicitly **not** guessed: server-side temporary LOBs, NTS/Kerberos.

### What stage 7 contains

Module `seclume-pool` — depends only on `javax.sql.DataSource`, not on a driver, and has no
third-party dependency:

- `SeclumePool` — min/max, connection, idle, lifetime and keepalive timeouts, warmup, leak
  detection with the stack trace of the checkout.
- **The checkout path touches no lock and no shared counter.** The free connections lie as slots
  in an array, each thread starts at its own slot (hash of the thread id, explicitly **not a
  `ThreadLocal`** — that is useless with millions of virtual threads). Measured: from 64 µs down
  to **0.27 µs** per checkout. HikariCP is at 0.10 µs and thus still ahead — its fast path is a
  `ThreadLocal`, which is unbeatable with eight platform threads and unusable with a million
  virtual ones. As soon as a query sits in between, the difference is noise.
- **Validation only after an idle period.** A connection that just came back is handed out again
  without asking the server; only after `validation-bypass-window` (500 ms of quiet by default)
  is it checked. The difference is not a nicety: a check per checkout is a **whole round trip**,
  and that is exactly what the pool hung on in the first measurement — 64 µs per checkout against
  0.4 µs for HikariCP. Whoever wants the paranoid variant sets the window to zero.
- `PooledConnection` — `close()` returns instead of closing; before that an open transaction is
  rolled back and `autoCommit`/`readOnly`/isolation level are set back to their starting values.
  Otherwise the next user inherits a state they never set. If the cleanup fails, the connection
  is closed rather than put back.
- An error from SQLState class `08` (connection) discards the connection, a syntax error does
  not.

**The pool holds no secret** — it never sees one. A rebuild is simply another `getConnection()`
on the underlying `DataSource`, and that asks the `SecretProvider` again. If that fails, the
build fails; there is no cached way around it, because that would be a password in the heap.
`getConnection(user, password)` throws with a reason, and `toString()`/`PoolStatistics` contain
numbers only.

**Fit for virtual threads**, and that is not a label:

- no `synchronized` around blocking calls (a virtual thread that blocks in a monitor takes its
  carrier thread with it),
- no `ThreadLocal` cache of recently used connections — with millions of virtual threads that is
  a memory leak with a hit rate near zero,
- handing out through `Semaphore` and `ConcurrentLinkedDeque`, both without a monitor.

Checked with 13 tests without a database (a stub `DataSource`: size, reuse, timeout, state
reset, broken connections, double `close()`, 500 virtual threads) and 6 tests against the real
local PostgreSQL — among them: 200 virtual threads demonstrably share at most eight
`pg_backend_pid()`, and after `close()` none of the sessions is left in `pg_stat_activity`.

That test found a **real fault in the driver**: `WireBuffer` used `Arena.ofConfined()`, a memory
region bound to the creating thread. A connection returned on a different virtual thread could
then not be closed (`WrongThreadException`) — exactly the case a pool exists for. It is a shared
arena now; that costs a little on close, once per connection.

### Shared plumbing

With the second driver, what both need was pulled together — otherwise it would stand there four
times by the fourth:

- `internal.WireBuffer` — the native buffer, now with both byte orders.
- `internal.JdbcUrl` — the URL parsing, so that `provider=file` means the same everywhere and a
  `password=` is refused the same way everywhere.
- `internal.jdbc.ReadOnlyResultSet` — the skeleton of a forward-only, read-only `ResultSet`: the
  nearly 190 methods that do not exist stand there once. `PgResultSet` shrank from 1246 to 165
  lines because of it.
- `internal.jdbc.ParameterSetters` — the forty `set...` methods as an interface with default
  methods (not a superclass: a `PreparedStatement` is always also its driver's `Statement`, and
  Java has only one superclass).

### What stage 2 contains

`seclume-tck` — the proof mechanism, built **before** the first driver:

- `HprofParser` — reads a heap dump and reports every `byte[]` and `char[]`. Unknown record types
  abort rather than guess on: a silent misstep would mean the test finds nothing and turns green
  — the worst conceivable outcome.
- `HeapDumpScanner` — searches raw across the whole file (`strings | grep`) **and** structurally
  across all primitive arrays (MAT/OQL), each in UTF-8, UTF-16BE, UTF-16LE and Base64. A hit
  names kind, place and length, never the content.
- `SecretHolderProbe` — a JVM of its own that uses a random password the way a driver would and
  then writes out its heap (`live=false`, so including dead objects). The password comes in
  through a file, never through an argument.
- `StaticSecretProvider` — the negative control: deliberately holds the password as a `String`
  and a `byte[]`.

Measured on this machine, 5 cycles per run:

| Run | Dump | Arrays parsed | Raw scan | Structural scan |
|------|------|-----------------|-----------|---------------------|
| off-heap | 5.1 MB | 9,897 | 0 hits | 0 hits |
| off-heap, scope **open** during the dump | 5.1 MB | ~9,900 | 0 hits | 0 hits |
| leaking (control) | 5.0 MB | 9,894 | **2 hits** | **2 hits** |

### What stage 1 contains

**Secret sources** (`space.seclume.secret`)

| Provider | Source | Platform |
|----------|--------|----------|
| `FileSecretProvider` | a file, read through `FileChannel` into a direct buffer | all |
| `EnvFileSecretProvider` | a `.env` file, key lookup off-heap | all |
| `UnixSocketSecretProvider` | an AF_UNIX socket (Vault agent, sidecar) | Unix |
| `ProcessSecretProvider` | a helper writes into a FIFO | Unix |
| `CallbackSecretProvider` | a lambda of your own (Vault, KMS, HSM) | all |
| `DpapiSecretProvider` | a DPAPI blob as a file, `crypt32!CryptUnprotectData` | Windows |
| `CredentialManagerSecretProvider` | `advapi32!CredReadW`, generic credential | Windows |

**Off-heap crypto** (`space.seclume.crypto`) — MD5, SHA-1, SHA-256, SHA-512, HMAC over
them, PBKDF2-HMAC, AES-128/192/256 in CBC and CFB, RSA (PKCS#1 v1.5 and OAEP) with big-number
arithmetic of its own, constant-time comparison. All on `MemorySegment`, every intermediate state
off-heap and wiped.

Proven by 107 tests: the official vectors (RFC 1321, FIPS 180-4, RFC 2202, RFC 4231, RFC 6070,
FIPS 197, NIST SP 800-38A) **and** cross-checks against the JCA over many random lengths — the
vectors show that the method is right, the cross-checks find the faults in buffer boundaries and
padding.

---

## The target picture

In the end this should be enough — add the dependency, fill in `application.properties`, done.
No driver setup, no pool setup, no extra class:

```properties
seclume.datasources.main.url=jdbc:seclume:postgresql://db:5432/app
seclume.datasources.main.username=app
seclume.datasources.main.secret.provider=file
seclume.datasources.main.secret.path=/run/secrets/db-password
seclume.datasources.main.pool.maximum-pool-size=20
```

The only difference to `spring.datasource.*` is the one line that is not there: **the password is
not in the configuration**, only where it comes from. Everything else — `DataSource`,
`JdbcClient`, `DataSourceTransactionManager`, JPA, `SQLExceptionTranslator`, Actuator health —
the starter sets up itself.

Whoever sets `spring.datasource.password` gets an abort at startup with a clear message instead
of a silent disabling of the core property.

### What of that works today

**The above, and for all four databases.** The starter knows every prefix and loads the matching
driver — and only that one, because the four modules are optional dependencies:

```properties
seclume.datasources.main.url=jdbc:seclume:postgresql://db:5432/app
seclume.datasources.main.url=jdbc:seclume:mysql://db:3306/app
seclume.datasources.main.url=jdbc:seclume:mariadb://db:3306/app
seclume.datasources.main.url=jdbc:seclume:sqlserver://db:1433/app
seclume.datasources.main.url=jdbc:seclume:oracle://db:1521/FREEPDB1
```

With Oracle the **service** stands where the database would; nothing else differs. If a prefix
appears in the configuration without its module, the abort names the missing dependency instead
of throwing a `NoClassDefFoundError`.

Without Spring the same works through `DriverManager`:

```java
String url = "jdbc:seclume:postgresql://db:5432/app"
           + "?user=app&provider=file&path=/run/secrets/db-password";
try (Connection connection = DriverManager.getConnection(url)) {
    ...
}
```

Or through a `DataSource`:

```java
SeclumeDataSource dataSource = new SeclumeDataSource();
dataSource.setHost("db");
dataSource.setDatabase("app");
dataSource.setUser("app");
dataSource.setProperty("provider", "file");
dataSource.setProperty("path", "/run/secrets/db-password");
```

The keys behind `provider` are the same ones that later stand in
`seclume.datasources.*.secret.*` — `SecretProviders` is the one place where a name becomes a
source, for the URL and the starter alike.

There is no `getConnection(user, password)`: the call takes the password as a `String`, and with
that it would be in the heap for the lifetime of the application. It throws with that reason.

---

## Checking against real databases (CI)

`.github/workflows/ci.yml` starts the databases as service containers and runs the tests against
them — PostgreSQL 15 **and** 18, MySQL 8.4 **and** MariaDB 11.4, Oracle Free 23ai, plus a SQL
Server 2022 standing ready.

That is not cosmetics but the missing piece. A development machine rarely holds more than one
database, and a home-made test server only confirms one's own assumptions. Only here does
„compiles and looks plausible" become evidence — and two server versions per product show
protocol differences before a user finds them.

The password comes in through a **file** in CI as well, that is, through the road the library
offers: no `echo`, no environment variable in the log.

**Honestly said:** the workflow is prepared but **untested** — the directory only became a Git
repository on 14.09.2026. The jobs for MySQL and Oracle today run against the existing protocol
and crypto tests only; the integration suites against those servers are in the list of open
points.

### Why the project lends itself to contribution

The core of this library is a promise one can destroy by accident: a single `new String(...)` in
the wrong place and the password is back in the heap. With most security libraries one would
have to trust that a contribution does not do that. Not here:

- `ForbiddenApiTest` reads the project's own source and trips if somebody introduces
  `new String`, `getBytes`, `BigInteger`, `javax.crypto` or `char[]` without justifying it with
  `// seclume-allow: <reason>`.
- The heap dump test writes a real dump from a second JVM and searches it — **with a
  counter-check**: a payload value from the same query *must* be found, or the empty result for
  the password would be worthless.

A contribution that breaks the core property therefore turns red without anyone having to read
it for that. For an open project that is worth more than any guideline in a wiki.

## Building

```
./mvnw clean test
```

The Windows platform test (DPAPI, Credential Manager) runs along automatically when executed on
Windows and is skipped otherwise.

---

## Provisioning on Windows

Without a Vault infrastructure the built-in credential store is the right road:

```powershell
# DPAPI, bound to the executing user - for a service, run as the service account
Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File -Encoding ascii C:\ProgramData\app\db.dpapi
```

```powershell
# Credential Manager, generic credential
cmdkey /generic:seclume/reporting /user:app /pass
```

---

## Speed

The goal is not merely „fast enough" but faster than the established Java drivers. The off-heap
construction helps; what that means in detail and where it has limits is in
[`docs/performance.md`](docs/performance.md).

The headline numbers, all recomputed and with their reasoning there:

| Measurement | seclume | vendor driver |
|---|---|---|
| batch of 500 rows, MySQL over LAN (604 µs RTT) | 18.7 ms | 278.6 ms (Connector/J) |
| check out, query, return (8 threads, local) | 62.4 µs | 70.9 µs (HikariCP + pgjdbc) |
| the same shape with `PreparedStatement` and a statement cache | **58.9 µs** | — (111.4 µs without a cache) |
| a `@Transactional` method with one query | **2 round trips** | 7 |
| batch of 200 rows, SQL Server | **1 round trip** | 200 (before, our own driver) |

Two findings that came out of it and are worth more than the numbers themselves: closing a
**shared arena** cost half the runtime under load (fixed now), and Oracle needed one round trip
too many for the second execution of a prepared statement, because one field in the call was set
to zero.

---

## Rules of honesty

- No placeholder that pretends to work. What is not implemented throws.
- No „provisional" delegation to a vendor driver, not even commented out.
- If a protocol detail cannot be reconstructed with certainty, that is recorded in
  `docs/protocol/<db>.md` and the feature counts as unsupported rather than being guessed.
- Test results are reported with their output. „Should work" does not count.
