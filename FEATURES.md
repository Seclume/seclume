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
  on Windows), so a core file, a crash report or a checkpoint image does not carry the secret
  to a disk;
- **wiped** when it closes.

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
CRaC refuses the checkpoint over the pool's open sockets. With it the image was searched and
holds no password.

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
