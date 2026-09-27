# What it does, in detail

The README has the overview. This page has the detail on the drivers, the pool, several
servers, and the tools that prove a secret is not on the heap. TLS, observability and secret
providers each have a page of their own: [TLS.md](TLS.md),
[OBSERVABILITY.md](OBSERVABILITY.md) and [PROVIDERS.md](PROVIDERS.md).

## The JDBC surface, on all four

- `Statement`, `PreparedStatement` and `CallableStatement`, with bind variables of every JDBC
  type.
- OUT parameters and parameters by name, generated keys and batches.
- `ParameterMetaData`: the count only, because types are not asked of the server.
- Scrollable results (`TYPE_SCROLL_INSENSITIVE`), fetch size and block cursors.
- LOB streams, `setNull` and escape functions.
- Query timeouts and row limits.
- **Procedures that return rows**, in the form each server has one. On Oracle it is a
  `SYS_REFCURSOR` output, read with `registerOutParameter(i, Types.REF_CURSOR)`. On SQL Server
  it is the results a procedure selects, walked with `getResultSet` and `getMoreResults`,
  several of them, and without the driver's own bookkeeping showing up among them.
- Every Java type an application maps, old and new: `BigDecimal`, `UUID`, `LocalDate`,
  `LocalDateTime`, `OffsetDateTime`, `Instant`, `LocalTime`, `Duration`, `Year`, byte arrays,
  `Clob`/`Blob`, enums and booleans. Each is written and read back unchanged, on every server.
- `DatabaseMetaData` far enough for Hibernate's schema validation, Flyway and
  `SimpleJdbcCall` to work from the catalogue alone.
- **Distributed transactions (XA)** in all four, off by default.
- **Cancellation and query timeouts** that actually stop something, each by the mechanism its
  protocol has:

  | Server | How the statement is stopped |
  |---|---|
  | PostgreSQL | a CancelRequest on a second connection |
  | MySQL | `KILL QUERY` |
  | SQL Server | an ATTENTION packet |
  | Oracle | a break sent as TCP urgent data |

  A statement that overruns its deadline comes back as `SQLTimeoutException`, whatever the
  server called it, and the connection is still usable afterwards. **MySQL does not fail a
  cancelled statement**: a killed `SLEEP()` returns 1 and the call succeeds. Code written
  against PostgreSQL's behaviour would accept a partial answer there. `setQueryTimeout`
  handles this; a hand-written `cancel()` has to handle it itself.

## Oracle only

- **`tnsnames.ora` aliases.** `jdbc:seclume:oracle:tns:ORDERS` looks the alias up in
  `tnsnames.ora` (`tnsAdmin`, `-Doracle.net.tns_admin` or `TNS_ADMIN`). Address lists become the
  host list, `SERVICE_NAME` the service, and TCPS switches on TLS.

## MySQL only

- **Batches as multi-row inserts**, with `rewriteBatchedInserts=true`. A batch of a plain
  `INSERT ... VALUES (?, ...)` goes as `VALUES (...), (...), ...` in blocks of up to 128 rows.
  Like Connector/J's `rewriteBatchedStatements`, it is off by default, because a block
  succeeds or fails as a whole and the counts per row become `SUCCESS_NO_INFO` when a block's
  affected rows do not add up (`INSERT IGNORE`, `ON DUPLICATE KEY UPDATE`). Statements it
  cannot take apart with certainty run row by row as before.

- **`LOAD DATA LOCAL` from a stream.** `MyConnection.loadData(sql, inputStream)` is MySQL's
  bulk import (100 000 rows in about 0.4 s), switched on with `loadDataLocal=true`. The server
  never gets a file by name: during `loadData` it gets the caller's stream, and at any other
  time an empty file. This closes the classic hole where a malicious server reads client
  files.

## SQL Server only

- **`varchar` parameters for `varchar` columns.** Text normally goes as `nvarchar`, and a
  `varchar` column compared with an `nvarchar` parameter is converted row by row. Under a SQL
  collation that turns an index seek into a scan. seclume asks the server once per statement
  text (`sp_describe_undeclared_parameters`, never inside a transaction) which parameters meet
  a `varchar` column, and sends those as `varchar` when the value is plain ASCII. ASCII is the
  same byte in every code page, so no collation can misread it. Other text stays `nvarchar`.
  `varcharParameters=off` switches this off.

- **Bulk load.** `TdsConnection.bulkInsert(table, columns, rows)` uses SQL Server's own
  bulk-load protocol (`INSERT BULK`): 100 000 rows in about half a second. Unlike `bcp`,
  constraints are checked and triggers fire.

- **Table-valued parameters.** `setObject(i, TableValue.of("dbo.order_lines", rows))` sends a
  whole table as one parameter, for a statement or a procedure's `readonly` argument.

- **Integrated login (Kerberos).** `authentication=kerberos` (or mssql-jdbc's
  `integratedSecurity=true`) logs in with the ticket the process already holds, from `kinit`
  or a keytab. There is no user, no password and no provider. The service principal is
  `MSSQLSvc/<host>:<port>`, or `serverSpn=` if it is registered under another name. The login
  counts only when the server proved it holds the service's key (mutual authentication).
  Needs the GSSAPI library, so Linux; Windows' SSPI is not built. Shown against SQL Server 2022
  joined to a Samba Active Directory, all in containers (`proof/kerberos.sh`): logged in as
  `SECLUMElice`, with the server reporting `auth_scheme` KERBEROS, and refused without a
  ticket.

## PostgreSQL only

- **The types only PostgreSQL has.** `getArray` works on any array column, including nested
  ones, and keeps the difference between a null element and the word `NULL`. `getSQLXML`
  works on `xml` and `getRowId` on `ctid`. For large objects, `getBlob` on an `oid` column is a
  real locator that reads in chunks rather than the row's own bytes. `java.sql.Ref` stays
  refused, because none of the four servers has a type it could point at.
- **LISTEN / NOTIFY.** `PgConnection.notifications()` hands out what has arrived, oldest
  first, as `PgNotification(processId, channel, payload)`. If nothing has arrived yet, it asks
  the server with a bare `Sync`: one round trip, without the transaction a pending `BEGIN`
  would start. `notifications(Duration)` waits for the first one. On a virtual thread that
  wait is a sleep, not a blocked thread, which gives you cache invalidation and the outbox
  pattern without a thread per listener.
- **`COPY` for bulk import and export.** `PgConnection.copyIn(sql, inputStream)` and
  `copyOut(sql, outputStream)` stream the data in both directions without holding it whole:
  100 000 CSV rows in under 200 ms. A failure on either side leaves the session usable.
- **Behind PgBouncer or RDS Proxy.** Prepared statements work behind PgBouncer 1.21 and
  later in transaction mode. With `proxyMode=transaction`, read-only and the isolation level
  travel in each transaction's own `BEGIN` instead of being set on the shared server
  session, where they would reach the next client.
- **CockroachDB and YugabyteDB** run on the PostgreSQL driver, each with a password:
  CockroachDB over TLS with SCRAM-SHA-256, YugabyteDB with md5. The tests assert which method
  the server asked for, so neither can quietly stop asking.

## Writing, retrying, and not guessing

- **A whole list in one placeholder.** `where id in (?)` with `setObject(1, List.of(...))`
  binds the list as one value. The statement text no longer depends on the list's length, so
  there is one plan however long the list is, and no limit: SQL Server's 2100 parameters and
  Oracle's 1000 list entries do not apply. Whole numbers, decimals, strings and UUIDs;
  `not in (?)` and empty lists work too.

- **`Pipeline`**: one round trip for a whole unit of work. Inside the block, writes are
  buffered and answer with `SUCCESS_NO_INFO`, the value JDBC already uses for "done, count
  unknown". Anything that really needs an answer flushes them first: a query, a commit, or a
  requested count. The block only works inside a transaction, so a failure cannot leave half a
  unit of work behind.
- **`Retry`**: runs a transaction again when the server says it has to be, and not otherwise.
  The classification is the point and it is public:
  - retried: SQLState class 40 and `SQLTransientException`;
  - not retried: a dead connection, an expired deadline, a cancellation, and anything that
    will simply happen again.
- **A lost commit is not an ordinary failure.** When the connection breaks while a COMMIT is
  in flight, nobody knows whether it was applied. So the error is
  `TransactionResolutionUnknownException`, SQLState `08007`, and it is never retried. The same
  holds for a write in auto-commit mode, which commits itself. A read, or a write inside a
  transaction, keeps an ordinary failure, because its outcome is known. This is shown on all
  four against a relay that lets the COMMIT through and drops the answer: the client is told
  "unknown", and the row is there.

## Secrets in columns, not only in the login

**`Sensitive` and `SensitiveParameters`** read a column that holds a secret straight into
native memory, and bind a parameter straight out of it, without either becoming a `String`.
This is for applications that keep API keys, signing keys and refresh tokens in a table,
which until now read every one of them onto the heap. It is proved by a child JVM dumping its
own heap, with a control that must find the value when it is read the ordinary way.

## Secret memory

A `SecretScope` is native memory that is:

- **locked**, so it is never swapped out;
- **excluded from crash dumps** (`MADV_DONTDUMP` on Linux, `WerRegisterExcludedMemoryBlock`
  on Windows), so a core file or a crash report does not carry the secret to a disk;
- **wiped** when it closes.

Locking and dump exclusion are operating system service, and a limit (`RLIMIT_MEMLOCK`,
Windows' 512 excluded blocks) makes them fail. By default that is a warning, once. With
`-Dseclume.mlock.required=true` it is an error instead: a secret whose memory cannot be both
locked and excluded is refused before anything is written into it. `-Dseclume.mlock=false`
switches both off.

**A checkpoint image is not a crash dump.** CRaC and SnapStart write the process's memory by
their own means, and dump exclusion is not something to rely on there. What keeps secrets
out of a checkpoint image is `seclume-crac` (see [the pool](#the-pool)): nothing secret is
left in the process when the image is written.

## The pool

`seclume-pool` has no third-party dependency and is fit for virtual threads. It comes with
Micrometer metrics, a health indicator, a statement cache and leak detection. Its timeout
message names the oldest holders. Beyond that, what matters is what a connection brings back:

- **Session state does not go to the next borrower.** An application might run
  `SET app.tenant_id = 42` instead of `set_config(..., true)`. Without a reset, the tenant of
  one request then moves on to the next request on that connection, which is the most common
  way row-level security breaks in practice. The same goes for a `search_path`, a temporary
  table, a MySQL user variable, a session-level advisory lock, or an Oracle client identifier
  or package variable. The drivers note every statement that sets such state, and on return
  the pool resets only a connection that had some. The ordinary return costs nothing:

  | | the reset |
  |---|---|
  | PostgreSQL | one round trip (`RESET ALL`, `UNLISTEN *`, advisory unlocks, `DISCARD TEMP`, …); prepared statements stay |
  | MySQL | `COM_RESET_CONNECTION` |
  | SQL Server | the RESETCONNECTION bit on the next request, with no round trip of its own |
  | Oracle | package state, client identifier, module and client info; a connection with an `ALTER SESSION` is closed rather than lent again |

- **The tenant on every borrow.** With `PoolSettings.setSessionContext(...)`, or a
  `SeclumeSessionContext` bean in Spring, every borrow gives the connection the context of the
  moment, such as `app.tenant_id` for a row-level security policy, and the reset on return
  takes it off. On PostgreSQL and MySQL it rides with the first statement at no cost. See
  `space.seclume.SessionContext` for where each database keeps it.
- **Statements left open are closed on return.** Each one is a server cursor on Oracle
  (`ORA-01000` after enough of them) and result memory on the others. They are logged with
  their fingerprint; with `leak-detection-threshold` set, the log also shows where each
  statement was made.
- **Shutting down in order.** On close, as on SIGTERM, nothing new is lent and idle
  connections go at once. Borrowed ones get up to `shutdown-timeout` (10 s) to come back, so
  a running transaction is finished rather than cut. Only stragglers after that are cut, and
  they are named in the log.
- **Rotating credentials without an empty pool.** The pool retires a connection before its
  credential expires and opens the replacement first. See [PROVIDERS.md](PROVIDERS.md).
- **Keepalive, at two levels.** Every connection has TCP keepalive on and probes after a
  minute of silence, which keeps an idle pooled connection alive through firewalls, NATs and
  load balancers that forget quiet flows. And the pool reads the server's own idle limit
  (MySQL `wait_timeout`, PostgreSQL `idle_session_timeout`, Oracle `IDLE_TIME`) at its first
  connection. It then keeps idle connections alive at three quarters of that limit, unless a
  shorter `keepaliveTime` is configured.
- **A result limit by default**, for data sources the Spring starter makes. `maxResultBytes`
  is a quarter of the heap, at least 16 and at most 256 MB. A runaway query then fails with an
  exception naming the limit, instead of an `OutOfMemoryError` that takes every other request
  with it. `maxResultBytes=0` switches the limit off. The drivers themselves keep what the URL
  says.

**Checkpoint and restore (CRaC, Lambda SnapStart).** `seclume-crac` registers a pool so that it
gives up every connection before a checkpoint and logs in afresh after the restore. Without it
CRaC refuses the checkpoint over the pool's open sockets. Before the checkpoint it also:

- **waits** until no connection is borrowed and no secret is open, and refuses the checkpoint
  if that does not happen within `seclume.crac.quiesceMillis` (10 s);
- **wipes the cached credentials** - Vault's leased credential, the instance role's AWS keys,
  OAuth access tokens - which are fetched again after the restore;
- **holds new secrets back** from that moment until the restore, so a login that starts in
  between waits instead of landing in the image (`seclume.crac.holdSecrets=false` switches
  this off; `seclume.crac.holdMillis`, 60 s, is the longest a login waits).

After the restore, OpenSSL's random generator is reseeded from the operating system before
any new secret is made: otherwise every instance started from one image would begin with the
same generator state, and draw the same ephemeral key shares. With it the image was searched
and holds no password; `seclume-crac/proof` repeats that search on a CRaC JDK.

## Several servers, and which one to take

A comma-separated host list fails over while connecting. With `targetServerType`, it also
knows *where* it is going:

```properties
jdbc:seclume:postgresql://db1,db2,db3/app?targetServerType=primary
```

Each server is asked what it is. That takes one statement, and one an ordinary application
account can run. A server of the wrong kind is given back and the next one tried. Without this,
a driver takes whichever node answers first. After a switchover that is a standby: the
connection succeeds and the first write fails, at the moment a cluster is least able to explain
itself. A server that cannot answer is accepted rather than skipped, because refusing to
connect over an unanswered question would turn a working cluster into an outage.

**Or ask the cluster, with `patroni=`.** For a cluster managed by Patroni, the driver asks the
REST API (`/cluster`) where the leader and the replicas are before it connects, instead of
trying hosts until one answers the right way. If no endpoint answers, the URL's hosts are used.

**Aurora, with `aurora=true`.** An Aurora cluster endpoint is a DNS name for the writer. After a
failover it keeps pointing at the old writer for as long as resolvers cache it. Every Aurora
instance knows the whole cluster (`aurora_replica_status()`, `replica_host_status`), so the
driver asks after each login (at most once a second) and remembers the instances. The next
connect tries them directly: the writer first for `targetServerType=primary`, the readers
first for `secondary`, and the cluster endpoint last. Instance names come from the cluster
endpoint in the URL, or from `auroraInstanceHost=?.id.region.rds.amazonaws.com`. The server's
own answer to "what are you" is still checked, so a stale memory costs an attempt and never
sends writes to a reader. PostgreSQL and MySQL. Shown against a stand-in, not a live Aurora
(`seclume-postgresql/proof/aurora.sh`): a primary and a streaming replica with the Aurora
function, the "cluster endpoint" pointing at the primary. The primary is stopped and the
replica promoted. With `aurora=true` the next `primary` connection finds the new writer in
29 ms; without it the connection fails at the dead endpoint. The MySQL side is covered by
unit tests only.

**And the best one first, with `hostSelection=quality`.** Every attempt is measured: connect
time, failures, and the role a server reported. The figures are kept once per process rather
than per URL, so a `DriverManager` user benefits as much as a pool. A server that just failed
is tried last for a back-off period; the rest are tried fastest and most reliable first. A
figure older than a minute is renewed by asking that server again. The default stays the list
as written.

**A primary and a read replica as one data source.** `new ReadWriteSplit(primary, replica)`
sends every connection that is read-only at its first statement to the replica, and everything
else to the primary. That fits `@Transactional(readOnly = true)` without a routing data source
of your own. With `readYourWrites(Duration)` on PostgreSQL and MySQL (GTID mode), a read after a write waits until
the replica has replayed it, or goes to the primary when the replica is too far behind. In Spring:
`seclume.read-write-split.primary`, `.replica` and `.read-your-writes`.

**Testcontainers and Docker Compose.** With `@ServiceConnection` on a database container, or
Spring Boot's Docker Compose support, the starter builds its pool from the container's connection
details. There is nothing to configure in a test.

## Spring Data and JPA

Entities may be shaped any way JPA allows, and are:

- inheritance in all three strategies;
- `@EmbeddedId` and `@IdClass`;
- `@OneToMany`, `@ManyToMany` and `@ElementCollection` with `@OrderBy`;
- `@MapsId`, `@SecondaryTable` and `@NaturalId`;
- every `@GeneratedValue` strategy, `@Version`, auditing, converters and `@Lob`;
- projections, specifications, `@EntityGraph`, `@Lock`, paging and streaming.

This is proven by a running Spring Boot application against all four servers, with
`ddl-auto=validate`, so the schema is compared against the driver's own metadata before a
single test runs. Hibernate, Flyway, Liquibase, jOOQ, MyBatis and Spring Data JDBC are listed
in [FRAMEWORKS.md](FRAMEWORKS.md).

## Quarkus

`seclume-quarkus` makes the four drivers Quarkus datasource kinds for Agroal:

```properties
quarkus.datasource.db-kind=seclume-postgresql      # or seclume-mysql, -sqlserver, -oracle
quarkus.datasource.jdbc.url=jdbc:seclume:postgresql://db/app?user=app&provider=file&path=/run/secrets/db
```

The secret is named in the URL and read by the driver into native memory at each login.
**`quarkus.datasource.password` fails the build** for a seclume datasource: Agroal would keep
it as a `String` for the life of the application, in every heap dump. The build error names
the property and the URL option to use instead. Named datasources work the same way
(`quarkus.datasource."orders".db-kind=...`).

Shown in JVM mode against all four servers in one application
(`DatasourceTest`): each logs in, and afterwards a heap dump of the application holds none
of the four passwords.

**And as a native image.** `seclume-quarkus/native-it` is the same application as a
`@QuarkusMain`, built with GraalVM 25 (`native.sh` beside it builds and runs it on any Linux
machine with podman). The binary logs in to all four, dumps its own heap, and a search in a
separate process finds none of the four passwords in the dump. As a control, the same search
finds the user name. The extension has the library's classes initialised when the image
runs: Quarkus initialises at build time by default, and the first native build failed on
exactly that, trying to open Windows' `bcrypt.dll` on the Linux build machine.

## Kafka

`seclume-kafka` is SASL/SCRAM for the Kafka client with the password off the heap. The JAAS
configuration names where the password comes from instead of the password:

```properties
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-512
sasl.jaas.config=space.seclume.kafka.SeclumeScramLoginModule required     username="orders" provider="file" path="/run/secrets/kafka";
```

The options besides `username` are a secret provider's settings, the same ones a seclume
JDBC URL takes (`file`, `vault`, `aws-secrets-manager`, ...). With Kafka's own
`ScramLoginModule` the password sits in `sasl.jaas.config` as a `String`, is copied into the
JAAS subject, and becomes a `char[]` at every login: three copies for the life of the
application. Here the SCRAM client (SHA-256 and SHA-512, the latter being what Amazon MSK uses)
reads the secret into native memory when the broker's first message has arrived, turns it
into the proof, and wipes it before the proof leaves. It is read again at every login, so a
rotated password needs no restart. `password=` in the configuration is refused.

It plugs in through the JDK's SASL interfaces, not Kafka's internals: Kafka's own login module
keeps working beside it in the same JVM, for the logins configured with it. Spring Boot needs
nothing extra, `spring.kafka.properties.sasl.jaas.config` carries the line above.

Shown against Kafka's own SCRAM server in process (both mechanisms, a wrong password, a server
that does not know the password) and against a real broker (`LocalKafkaScramTest`, broker from
`seclume-kafka/proof/broker.sh`): a producer and a consumer with both mechanisms, a wrong
password refused, and afterwards a heap dump of the test JVM holds no copy of the password.
The same check against Kafka's own login module finds it. Delegation tokens (`tokenauth`) are
not covered: they are secrets Kafka hands out itself.

## Redis

`seclume-redis` is a socket factory for Jedis that hands over a connection which is already
logged in:

```java
JedisSocketFactory sockets = SeclumeRedisSocketFactory.of(
        "rediss://cache:6380?user=orders&provider=file&path=/run/secrets/redis");
try (Jedis jedis = new Jedis(sockets)) { ... }
RedisClient pooled = RedisClient.builder().connectionProvider(new PooledConnectionProvider(
        new ConnectionFactory(sockets, DefaultJedisClientConfig.builder().build()))).build();
```

Jedis given a password keeps it as a `String` in its client configuration and writes `AUTH`
from a heap buffer at every connect. Here Jedis gets no password. The factory opens the
connection, sends `AUTH user password` from native memory, reads `+OK` and hands Jedis the
socket. `rediss://` encrypts with seclume's own TLS 1.3 stack, with the certificate and host
name checked (`tlsRootCert=`, `tlsPin=`). It does not use the JDK's TLS, because `AUTH` would
then pass through JSSE's heap buffers. A server without TLS 1.3 cannot be reached this way, and
a password in the URL is refused.

Shown against Redis 8 (`LocalRedisTest`, server from `seclume-redis/proof/redis.sh`): an ACL
user over plain TCP and over TLS 1.3 with a CA of its own, one connection and a pool, a wrong
password refused, a certificate the JVM does not trust refused. Afterwards the heap dump of
the test JVM holds no copy of the password. Jedis configured the ordinary way leaves it there,
and the same check finds it. Lettuce is not covered: it takes the password as a `char[]` and
encodes it into Netty's buffers.

## Mail

`seclume-mail` sends over SMTP and reads over IMAP and POP3 with the password or the OAuth
token off the heap. For Jakarta Mail, and so for Spring's `JavaMailSenderImpl`, Spring
Integration's mail adapters and Camel, it is one session:

```java
Session session = SeclumeMail.session(
        "smtps://mail.example.com?user=reports&provider=file&path=/run/secrets/mail",
        "imaps://mail.example.com?user=reports&provider=file&path=/run/secrets/mail");

Transport.send(message);                        // smtps, logged in by seclume
Store store = session.getStore();               // imaps
store.connect();                                // no user, no password
Folder inbox = store.getFolder("INBOX");

sender.setSession(session);                     // Spring: no host, no user, no password

// Microsoft 365 with the machine's identity - no stored credential at all
"imaps://outlook.office365.com?user=reports@example.com&auth=xoauth2"
        + "&provider=azure-managed-identity&resource=https://outlook.office365.com"
```

With Spring Boot and `seclume-spring-boot-starter` it is two lines of `application.properties`
and no code: they make the `Session` and a `JavaMailSender` on it, and Boot's own mail sender
steps aside. `spring.mail.properties.*` still reach the session, and `spring.mail.password` is
refused, since it would sit in the `Environment` as a `String` and not be used.

```properties
seclume.mail.send=smtps://mail.example.com?user=reports&provider=file&path=/run/secrets/mail
seclume.mail.read=imaps://mail.example.com?user=reports&provider=file&path=/run/secrets/mail
```

In that session `smtp`, `imap` and `pop3` (and `smtps`, `imaps`, `pop3s`) are served by
seclume under their usual names. Nothing is registered globally: every other session in the
JVM is Jakarta Mail's as before. Without Jakarta Mail, `SeclumeMail.of(url).send(...)` sends
a message and `SeclumeMail.of(url).store()` opens a mailbox.

Jakarta Mail given a password keeps it as a `String` in its `Session` and builds the base64
login argument as another one, and JSSE encrypts it from heap buffers. Here Jakarta Mail gets
no password, and a password handed to it is refused. seclume logs in itself, the argument
built and base64-encoded in native memory and written to its own TLS 1.3 stack:

| Protocol | Logins | TLS |
|---|---|---|
| SMTP | `AUTH PLAIN`, `LOGIN`, `XOAUTH2` | `smtp://` STARTTLS, `smtps://` implicit |
| IMAP | `AUTHENTICATE PLAIN`, `XOAUTH2` (SASL-IR or not), `LOGIN` with the password as a literal | `imap://` STARTTLS, `imaps://` implicit |
| POP3 | `AUTH PLAIN`, `XOAUTH2`, `USER`/`PASS` | `pop3://` STLS, `pop3s://` implicit |

Left out, `auth=` picks PLAIN where the server offers it and the protocol's own login
otherwise; XOAUTH2 is used only when named. A server without STARTTLS is refused, and so are
bytes it sends after its STARTTLS reply and before the handshake: anyone on the path could
have injected them. `tls=none` exists for an SMTP relay without login and never logs in, since
a credential is never sent in the clear. The secret providers are the JDBC drivers': a file,
Vault, a cloud secret manager, or an OAuth token from the machine's Azure or GCP identity.

**Reading.** Folders, search, fetching and flags are Angus Mail's IMAP and POP3 stores,
unchanged, on a socket seclume has already connected, encrypted and logged in. IMAP has a word
for that: the store is greeted with `PREAUTH` and skips its login. POP3 does not, so the
session has the store log in with `USER` and `PASS` alone, and the socket answers both itself.
They carry a placeholder, not the password, and never reach the server. Each connection
Angus opens, pooled ones included, is logged in the same way.

**What is not off the heap: the mail.** Subject, addresses and bodies are the application's
data, written or read by the application. This is the same line the JDBC drivers draw: the
password is not a `String`, the rows are. MIME is Jakarta Mail's.

Shown by `NoCredentialOnTheHeapTest`: SMTP, IMAP and POP3 servers in a JVM of their own make
up a password and a token and write them, and the base64 forms they take on the wire, to
files. This JVM sends with PLAIN, LOGIN and XOAUTH2, reads over IMAP with AUTHENTICATE PLAIN,
LOGIN and XOAUTH2 and over POP3 with USER/PASS and XOAUTH2, alone and through Jakarta Mail.
Then it dumps its heap and searches it for all five: none is found. As a control, the PLAIN
argument read into a `String` on purpose is found. The protocols themselves (every login,
dot-stuffing, partial deliveries, a wrong certificate, the STARTTLS injection, reading a
mailbox through Jakarta Mail, Spring's `JavaMailSenderImpl`) are covered by
`SmtpConnectionTest`, `MailboxLoginTest`, `SeclumeTransportTest`, `SeclumeStoreTest` and
`SpringJavaMailSenderTest`.

## HTTPS APIs

`seclume-http` calls REST APIs with the API key, bearer token or Basic password off the heap:
Elasticsearch and OpenSearch, payment providers, AI APIs, an internal service. On its own, or
below Spring's `RestClient` and `RestTemplate` as their request factory:

```java
SeclumeHttp api = SeclumeHttp.of(
        "https://api.example.com/v1?provider=file&path=/run/secrets/api-token");   // Bearer

RestClient rest = RestClient.builder()
        .requestFactory(new SeclumeHttpRequestFactory(api))
        .baseUrl("https://api.example.com/v1")
        .build();
Order order = rest.get().uri("/orders/{id}", 42).retrieve().body(Order.class);

// Elasticsearch with an API key, from Vault
"https://search.internal:9200?auth=header&header=Authorization&prefix=ApiKey%20&provider=vault&..."
// Basic
"https://registry.internal?auth=basic&user=deploy&provider=file&path=/run/secrets/registry"
// a header of the API's own
"https://api.example.com?auth=header&header=X-Api-Key&provider=..."
```

With Spring Boot and `seclume-spring-boot-starter`, `application.properties` is enough, for as
many APIs as needed. Each has its own server and its own secret:

```properties
seclume.http.clients.payments.url=https://api.payments.example/v2?provider=file&path=/run/secrets/payments
seclume.http.clients.search.url=https://search.internal:9200?auth=header&header=Authorization&prefix=ApiKey%20&provider=vault&...
seclume.http.clients.search.interface=com.example.SearchApi      # optional: an @HttpExchange interface
```

```java
Checkout(@Qualifier("payments") RestClient payments, SearchApi search) { ... }
```

Every name becomes a `RestClient` bean of that name, with the URL's origin and path as its base
URL. With `interface=`, it also becomes an `@HttpExchange` client that can be injected by its
type. Where Boot's `RestClient.Builder` is present, each client starts from it, so message
converters, customizers and observation apply as usual. A client never sends its secret to
another client's server.

The usual way, a token set with `setBearerAuth`, a default header or an interceptor, is a
`String` for as long as the client lives, and JSSE encrypts it from heap buffers again with
every request. Here the application never sets it. For each request the client reads the
secret from the provider, builds the header line in native memory (for Basic, the base64 of
`user:password` as well) and writes it into seclume's own TLS 1.3. After that it is wiped. A
rotated key takes effect with the next request. Providers that fetch over the network (Vault,
the cloud secret managers, a managed identity) keep their own native cache, so they are not
asked on every request.

**OAuth 2.0 client credentials** (Entra ID, Keycloak, Okta, Auth0): with `auth=oauth2` the
client fetches an access token from the token endpoint and sends it as a bearer token:

```properties
seclume.http.clients.graph.url=https://graph.microsoft.com/v1.0?auth=oauth2\
  &token-url=https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token\
  &client-id=<app id>&scope=https://graph.microsoft.com/.default\
  &provider=vault&...
```

Usually both secrets stay on the heap: the client secret as a `String` in the client
registration, and the access token in the cache of authorized clients. Here the client secret
goes from its provider into the token request in native memory. It is form-encoded there, and
base64-encoded for `client-auth=basic` (the default; `post` puts it in the form). Even the
request's `Content-Length` is written there when the secret is in the body, since it would give
away the secret's length. The token endpoint's answer is decrypted by seclume's TLS into native
memory and parsed there. The access token is kept in a locked native segment and written into
each request. It is renewed before it expires (`expires_in`, as a number or as the string older
Entra ID sends), and at once when the API answers 401; the request is then sent again, once.
`scope=`, `resource=` (Entra ID v1, AD FS) and `audience=` (Auth0) are sent when given.
`token-tlsPin=` or `token-tlsRootCert=` apply to the token endpoint, which is usually another
server than the API. A refusal from the token endpoint comes back with its `error` and
`error_description`, for example `invalid_client: AADSTS7000215 ...`.

**Without any client secret: `client-auth=private_key_jwt`** (RFC 7523). The application
signs a short JWT with its private key instead: five minutes, for this token endpoint only,
never twice (`jti`). The key is decoded and held by OpenSSL, never by the JVM (see
[Signing keys](#signing-keys-jwt-and-webhooks)). `assertion-alg=` (RS256 by default; PS256,
ES256 ...), `assertion-kid=`, and `assertion-certificate=` for the certificate whose
SHA-256 thumbprint goes into the header as `x5t#S256` (the SHA-1 `x5t` is not sent). With it, the Entra ID app
registration needs no client secret at all, so there is none to steal.

**A JWT the client signs itself: `auth=jwt`.** GitHub Apps, Google service accounts, Apple,
Zoom and many service meshes take no secret at all. They take a short JWT signed with the
caller's private key:

```properties
seclume.http.clients.github.url=https://api.github.com?auth=jwt&jwt-alg=RS256\
  &jwt-iss=<app id>&jwt-ttl=540&provider=file&path=/run/secrets/github-app.pem
```

The client signs it with the key OpenSSL holds (or with an HMAC key read per use, for HS256)
and sends it as the bearer token. It reuses the token until shortly before it expires, and
signs it afresh after a 401. `jwt-sub=`, `jwt-aud=` and `jwt-kid=` are added when given, and
`iat` is set a minute back for clocks that disagree. The token is a credential while it lasts
and is on the heap as the string it is sent as. The key that makes it is not.

**The credential stays with its origin.** It goes to the scheme, host and port of the URL and
nowhere else. A request for another origin is refused rather than sent without it, redirects
are not followed (a 3xx comes back as it is), and a request that sets the credential's header
itself is refused: its value would be a `String` already. A secret with a line break in it is
not sent, since the break would end the header early. Only `https://`.

HTTP/1.1 with kept connections (`maxIdle`, `idleTimeout`). Responses may be of fixed length,
chunked or delimited by the close. A GET, PUT or DELETE that finds a kept connection closed by
the server is sent again on a new one; a POST is not. `tlsPin=` or `tlsRootCert=` for a CA
the JVM does not know, `connectTimeout=` and `timeout=` in milliseconds.

**What is not off the heap: requests and responses.** Paths, headers and bodies are the
application's data. It is the same line as for the databases and mail.

Shown by `NoCredentialOnTheHeapTest`: three HTTPS servers and an OAuth token endpoint run in a
JVM of their own and make up a token, a password, an API key and a client secret. This JVM calls them with a bearer token on its own, with
Basic through `RestClient`, with a key header through `RestTemplate` and with OAuth client
credentials through `RestClient`, over kept connections. Then it searches its heap dump for
all of them, for the access token that was issued, and for both Basic base64 forms: none is
found, and the control (the token read into a `String` on purpose) is. The protocol (every
way a body ends, connection reuse, the retry, the origin rule, a wrong certificate) is covered
by `SeclumeHttpTest`, `SpringRestClientTest` and `OAuthClientCredentialsTest`.

## Signing keys: JWT and webhooks

`seclume-jwt` signs with a key that stays off the heap. A heap dump holding the key that
signs the application's tokens lets anyone make a token for any user. A webhook secret lets
them fake "payment succeeded".

```java
SeclumeJwt jwt = SeclumeJwt.of("HS256?kid=2026-09&provider=vault&...");
String token = jwt.sign(Map.of("sub", "user-42", "exp", now + 900));
String claims = jwt.verify(token);        // or InvalidTokenException, saying why

SeclumeJwt rsa = SeclumeJwt.of("RS256?kid=app-1&provider=file&path=/run/secrets/key.pem");

SeclumeHmac webhooks = SeclumeHmac.of("SHA256?provider=file&path=/run/secrets/whsec");
webhooks.verifyGitHub(request.getHeader("X-Hub-Signature-256"), body);
webhooks.verifyStripe(request.getHeader("Stripe-Signature"), body, Duration.ofMinutes(5));
```

- **HMAC** (HS256/384/512, and webhook signatures): the key is read from its provider for
  each use, the HMAC is computed in native memory, and the key is wiped. A key shorter than
  the hash is refused (RFC 7518 3.2).
- **RSA and EC** (RS256/384/512, PS256/384/512, ES256/384/512): the PEM or DER key (PKCS#8,
  PKCS#1 or SEC 1) is read into native memory and decoded there by OpenSSL's own decoder. From
  then on it is an `EVP_PKEY` in OpenSSL's memory, and the JVM only ever sees signatures.
  This needs OpenSSL 3 on 64-bit Linux; HMAC works everywhere.
- **Verifying** tokens signed with this HMAC key takes the algorithm from the key, never from
  the token (`alg: none` and a swapped algorithm are refused). It compares in constant time
  and checks `exp` and `nbf` with a leeway (`leeway=`, 60 seconds by default). Tokens signed
  with a private key are checked with the public key, which is no secret, so any JWT library
  can do that.

What is on the heap is public: the claims, the token, the signature. Shown by
`NoKeyOnTheHeapTest`: the keys are made in a JVM of their own. This JVM signs and verifies
HS256 tokens, signs RS256, PS256 and ES256 tokens, and checks a GitHub webhook. Then it
searches its heap dump for the HMAC key, the webhook secret, both PEMs, both DER encodings
and the RSA private exponent: none is found. The controls, the HMAC key as a `String` and
the EC key's DER as a `byte[]` put on the heap on purpose, are found. `SeclumeJwtTest` and
`SeclumeHmacTest` check every signature against the JDK's own `Mac` and `Signature`.

## RabbitMQ

`seclume-rabbitmq` gives the official Java client, and with it Spring AMQP, a
`ConnectionFactory` whose login stays off the heap:

```java
ConnectionFactory factory = SeclumeRabbit.connectionFactory(
        "amqps://mq.example.com/orders?user=app&provider=file&path=/run/secrets/rabbit");
CachingConnectionFactory spring = new CachingConnectionFactory(factory);   // RabbitTemplate, @RabbitListener
```

The client holds a placeholder instead of the password. Its sockets encrypt with seclume's
TLS 1.3 and rewrite one frame, `Connection.Start-Ok`: the SASL PLAIN response, and the lengths
that follow from it, are written from native memory. Everything after the login is the
client's own, so channels, confirms, consumers and automatic recovery work as usual, and every
recovery is logged in the same way. A password set on the client is refused before it is
sent. `amqps://` only. The token of RabbitMQ's OAuth 2 plugin goes in the same place.
`RabbitBrokerTest` runs against a real broker in CI: publish and receive, Spring AMQP, a wrong
password, recovery after the broker drops the connection, and the heap proof with its control.

## Private keys: TLS servers, client certificates, SSH

`seclume-keys` keeps a private key where the JVM cannot see it. The key file is read by a
secret provider into native memory and decoded by OpenSSL, and the key stays in OpenSSL's
memory. Java gets a `PrivateKey` that holds none of it (`getEncoded()` is `null`, as for a key
in a hardware module). Signatures are made by seclume's JCA provider, which the JDK chooses
by itself for these keys. For all other keys nothing changes.

```java
String key = "provider=file&path=/run/secrets/tls.key";           // any secret provider
SSLContext server = SeclumeKeys.sslContext(Path.of("/etc/tls/chain.pem"), key);
KeyManagerFactory kmf = SeclumeKeys.keyManagerFactory(Path.of("/etc/tls/chain.pem"), key);
SeclumeTomcat.enableHttps(connector, Path.of("/etc/tls/chain.pem"), key);   // embedded Tomcat
```

With Spring Boot:

```properties
seclume.ssl.bundles.web.certificate=/etc/tls/chain.pem
seclume.ssl.bundles.web.key=provider=file&path=/run/secrets/tls.key
seclume.server.ssl.bundle=web      # Tomcat: HTTPS with that key
# server.ssl.bundle=web            # Reactor Netty, and clients that present a certificate
```

- **Keys:** RSA and EC, PEM or DER (PKCS#8, PKCS#1, SEC 1); an encrypted key goes through
  `provider=encrypted`.
- **Signatures:** TLS 1.3 and 1.2 with RSA-PSS, RSA PKCS#1 and ECDSA.
- **Checks:** a certificate chain that does not belong to the key is refused.
- **Platform:** OpenSSL 3 on 64-bit Linux.

Tests run the JDK's own client against an `SSLServerSocket` and against an embedded Tomcat.
The heap proof searches for the key's DER encoding and for its prime (RSA) or scalar (EC), the
form a `BigInteger` would hold. The control loads the same key the usual way, and the proof
finds it.

**SSH and SFTP.** `seclume-ssh` gives Apache MINA SSHD, and Spring Integration's SFTP on top
of it, such a key for public-key logins:

```java
SshClient client = SeclumeSsh.withIdentity(SshClient.setUpDefaultClient(),
        "provider=file&path=/run/secrets/id_ecdsa");
```

- **Keys:** RSA (`rsa-sha2-256/512`), and ECDSA on P-256, P-384 and P-521. An OpenSSH-format
  key is converted once with `ssh-keygen -p -m PEM`. Ed25519 is not supported yet.
- **Passwords:** a password login cannot be protected, because SSHD encrypts it in Java before
  it reaches a socket.
- **Spring Boot:** `seclume.ssh.key` makes a started `SshClient` bean.
  - Host keys are checked against `seclume.ssh.known-hosts`. An unknown server is refused
    unless `seclume.ssh.allow-unknown-hosts=true`.
  - With `seclume.sftp.host`, `.port` and `.user` there is also Spring Integration's
    `DefaultSftpSessionFactory` on that client.
- **Tests:** they use SSHD's own SFTP server.

## AWS

`seclume-aws` signs AWS SDK requests without the secret access key on the heap. The SDK's
signer derives the signing key from a `String` with `javax.crypto.Mac`. seclume's signer
reads the key from a secret provider into native memory for each request, runs the SigV4
derivation there and wipes the key. The SDK only holds a placeholder.

```java
S3Client s3 = SeclumeAws.configure(S3Client.builder(),
        "access-key-id=AKIA...&region=eu-central-1&provider=file&path=/run/secrets/aws-secret-key")
    .build();
// SqsClient, DynamoDbClient, SnsClient ... the same. MinIO, Ceph:
//   .endpointOverride(URI.create("https://minio.internal:9000")).forcePathStyle(true)
```

With Spring Cloud AWS, every client it makes (S3, SQS and its listeners, SNS, DynamoDB, SES
and more) signs this way:

```properties
seclume.aws.access-key-id=AKIA...
seclume.aws.secret-access-key=provider=file&path=/run/secrets/aws-secret-key   # the provider, not the key
seclume.aws.region=eu-central-1                                                 # optional
```

**How it is tested:**
- For thirteen request shapes the signature is compared byte for byte with the SDK's own
  signer: S3 with and without a signed body, CRC32 checksums, queries, non-ASCII, dot
  segments and more.
- The key derivation is checked against AWS's published test vector.
- The S3 and SQS clients, sync and async, run against a local server that checks every
  signature with the SDK's signer. S3 is also tested over HTTPS, where the body goes unsigned
  and the checksum goes in a header.
- The heap proof runs in a JVM of its own.

**Limits:**
- Long-term keys only (IAM users, MinIO, Ceph). Temporary credentials with a session token
  are refused, because the token would sit in a header the SDK holds as a `String`.
- Not supported yet: presigned URLs and SigV4a.
- An async client's body is collected in memory before it is signed. This is meant for the
  small bodies of SQS, SNS and DynamoDB. S3 over HTTPS sends its body unsigned, so nothing is
  collected there.

## LDAP and Active Directory

`seclume-ldap` gives JNDI, and with it Spring LDAP and Spring Security's LDAP support, a
socket factory. JNDI holds a placeholder instead of the service account's password. The
socket encrypts with seclume's TLS 1.3. In the simple bind that carries the placeholder, it
writes the real password and the BER lengths that follow from it, both from native memory.

```java
SeclumeLdap ldap = SeclumeLdap.of("ldaps://ad.example.com/dc=example,dc=com"
        + "?user=svc-app@example.com&provider=file&path=/run/secrets/ldap");
DirContext context = new InitialDirContext(ldap.environment());

LdapContextSource source = new LdapContextSource();          // Spring LDAP
source.setUrl(ldap.url()); source.setBase(ldap.base());
source.setUserDn(ldap.user()); source.setPassword(ldap.password());
source.setBaseEnvironmentProperties(ldap.socketFactory());
```

- **What passes through unchanged:** binds with any other password. An end user logging in
  through Spring Security binds with what they typed.
- **Limits:** `ldaps://` only, no StartTLS, no SASL binds.
- **Spring Boot:** `seclume.ldap.url=ldaps://...?user=...&provider=...` makes the
  `LdapContextSource` bean. Boot's `LdapTemplate` and Spring Security's LDAP authentication
  use it.
- **Tests:** they run against UnboundID's directory server in a process of its own, so the
  password is never in the test JVM.

## GraalVM native image

The library builds as a native image and connects from one to all four databases, with the
JDK's TLS and with seclume's own stack (TDS 8.0 on SQL Server, TCPS on Oracle). It uses no
JNI and no reflection, only FFM. An image has to be told two things, and both ship with
`seclume-core`, so nobody has to find out the hard way:

- the signature of every native call the library makes (`mlock`, `madvise`, OpenSSL's P-256
  for the TLS stack, and the Windows APIs), held to the source by a test;
- shared arena support, which every receive buffer here needs.

Built from the jar with no flags:

```
native-image --no-fallback -jar seclume-verify.jar
```

It starts in three milliseconds, against fifty-eight on the JVM. But once a database
connection is in the picture that difference is noise. The native image is for a process that
starts often, not for one that then talks to a server over a network.

## Proving there is no secret on the heap, for any application

- **`seclume-heapcheck`** proves for **any** running Java process whether a given secret is in
  its heap, including applications that do not use this library.
- **`seclume-tck`'s `NoSecretInHeap`** runs the same proof in **your own test suite**:
  - `@ExtendWith(NoSecretInHeap.class)` checks after every test.
  - `NoSecretInHeap.assertAbsent(secretFile)` checks at a moment you choose, say right after
    the login.

  The password comes as a file (`-Dseclume.tck.secret-file=/run/secrets/db`), and the search
  runs in a process of its own, because a pattern in the test JVM would be found in the very
  heap it searches. A hit says where the secret was, never what it is. It finds the leaks the
  driver cannot prevent: a configuration object, a log line, a `toString()`.
