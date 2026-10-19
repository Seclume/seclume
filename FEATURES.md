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
- **Native Network Encryption.** Oracle's own encryption and checksums, for listeners that
  require it (`SQLNET.ENCRYPTION_SERVER`, `SQLNET.CRYPTO_CHECKSUM_SERVER`) instead of offering
  TCPS. `nativeEncryption` in the URL or on the data source:

  | Value | What happens |
  |---|---|
  | `accepted` (default) | As Oracle's own client: negotiated when the server asks for it, otherwise nothing changes, not even a round trip |
  | `requested` | Offered in the CONNECT; used when the server agrees |
  | `required` | Offered, and the connection refused without it. A server left at Oracle's defaults agrees, so this encrypts without anyone touching the server |
  | `off` | Never; a server that requires it is refused before the login, saying why |

  - **Algorithms:** AES-256, -192 or -128 in CBC, with SHA-256, -384 or -512 checksums. RC4,
    DES, MD5 and SHA-1 are not offered.
  - **Keys:** agreed by Diffie-Hellman on the group the server sends. The private exponent,
    the shared secret, the AES keys and the checksum keystream all stay in native memory, and
    the exponent is used in constant time.
  - **A session that moves** to another host is refused under native encryption: its
    checksum keystream cannot leave the process. Use TCPS on seclume's own TLS instead.
  - **Shown** against Oracle Free 23 with both settings REQUIRED (AES256, SHA256,
    `seclume-oracle/proof/nne.sh`, `LocalOracleNneTest`):
    - the server's own `v$session_connect_info` names the AES256 and SHA256 adapters;
    - a 69 000-character CLOB bind and a 200 KB result travel in many sealed packets;
    - failing statements go through the break and reset markers after which both ends derive
      the checksum keys anew;
    - the heap dump holds no password;
    - `required` against a listener at its defaults encrypts as well.
  - **Source:** the protocol follows go-ora (MIT, see [NOTICE](NOTICE) and
    [PROVENANCE.md](PROVENANCE.md)).
- **Kerberos.** `authentication=kerberos` logs in with the ticket the operating system holds.
  There is no user and no password: `kinit` or a keytab through GSSAPI on Linux, the logon
  session through SSPI on Windows.
  - **How:** the exchange runs inside Oracle's advanced negotiation. The server names its
    service and host, and the client answers with an AP-REQ for `service/host`.
  - **Mutual authentication:** the server's AP-REP is checked, so the login counts only once
    the server has proved it holds the service key.
  - **The database user** is the one the principal maps to (`IDENTIFIED EXTERNALLY AS
    'alice@REALM'`).
  - **Combines with native encryption** (`nativeEncryption=required`).
  - **Shown** with an MIT KDC, Oracle Free 23 and a client, all in containers
    (`seclume-oracle/proof/kerberos.sh`):
    - `SESSION_USER` KALICE, `AUTHENTICATION_METHOD` KERBEROS, `AUTHENTICATED_IDENTITY`
      alice@SECLUME.TEST, also with AES256;
    - without a ticket, refused with the library's reason.
- **Windows-native authentication (NTS).** `authentication=nts` logs in as the Windows user
  the application runs as, against an Oracle database that runs on Windows. There is no user
  and no password: SSPI does NTLM with the logon session's credentials, and the secret never
  enters the process.
  - **How:** NTLM's three messages travel inside Oracle's advanced negotiation.
  - **NTLM proves nothing about the server.** Where there is a domain, prefer Kerberos. NTS is
    only used when the URL asks for it by name; Kerberos never falls back to NTLM.
  - **The database user** is the Windows account with Oracle's prefix
    (`"OPS$HOST\ALICE" IDENTIFIED EXTERNALLY`).
  - **Combines with native encryption**, and a Windows server encrypts by default.
  - **Windows only**, on both ends.
  - **Shown** with a Windows Server 2022 VM running Oracle Database Free 23.9 for Windows
    (`seclume-oracle/proof/nts.sh`):
    - `SESSION_USER` `OPS$<HOST>\SECLUME`, `AUTHENTICATION_METHOD` OS, encrypted with AES256;
      also with `nativeEncryption=required` and, unencrypted, with `nativeEncryption=off`;
    - a Windows user the database does not know is refused with ORA-01017.

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

- **MariaDB's logins by signature: `client_ed25519` and `parsec`.** The server stores only a
  public key, so a stolen `mysql.global_priv` does not let anyone log in. Nothing to set: the
  server switches the login, and the driver answers.
  - **`client_ed25519`** (MariaDB 10.1.22+): the server's 32 random bytes, signed with Ed25519
    under the key MariaDB expands from the password.
  - **`parsec`** (MariaDB 11.6+): the key's seed is derived with PBKDF2-SHA-512 from the password
    and the salt the server sends, and the signature covers the server's scramble and one of
    the client's own.
  - **On native memory, on every platform:** the Ed25519 signature is seclume's own
    (`crypto/Ed25519`), because no library could take over. MariaDB expands the password
    itself where the standard expands a 32-byte seed, and Windows' CNG has no Ed25519 at all.
    The expanded key, the derived seed and every intermediate value live off the heap and are
    zeroed. Checked against RFC 8032's vectors, against the JDK's Ed25519 for 200 random keys,
    and against the public key MariaDB documents for the password `secret`.
  - **Shown** against MariaDB 11.8 (`seclume-mysql/proof/ed25519.sh`,
    `LocalMariaDbEd25519Test`): both users log in, a wrong password is refused by both, and
    the heap holds no password.

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
  On Linux through the GSSAPI library, on Windows through SSPI (see below). Shown against SQL Server 2022
  joined to a Samba Active Directory, all in containers (`proof/kerberos.sh`): logged in as
  `SECLUMElice`, with the server reporting `auth_scheme` KERBEROS, and refused without a
  ticket.

- **Kerberos on Windows: SSPI.** The same logins (SQL Server, PostgreSQL `gss`, MariaDB
  `auth_gssapi`) work on Windows through SSPI (`secur32.dll`).
  - **Credentials:** those of the logon session. On a domain member that is the user's own
    logon; outside a domain it is `runas /netonly` or equivalent, where the LSA holds the
    password and the process never does.
  - **Package:** only Kerberos, never Negotiate, so NTLM (a hash a server could relay) is
    never offered.
  - **Mutual authentication** is required.
  - **Shown** from Windows 11 (build 26200) outside any domain, against an MIT KDC and
    PostgreSQL 16 (`seclume-postgresql/proof/sspi-server.sh` and `sspi.ps1`):
    - with alice's network credentials: logged in as alice by `gss`;
    - without them: refused with `SEC_E_NO_CREDENTIALS`.
  - **Shown from a domain member against SQL Server:** a Windows Server 2022 VM joined to
    the Samba AD domain of `seclume-sqlserver/proof/kerberos.sh`, the proof run as
    `SECLUME\alice` (a real domain logon, by the task scheduler with her password). SQL
    Server reported the session as `SECLUME\alice`, `auth_scheme` KERBEROS, encrypted,
    from the VM's address (29.09.2026).
  - **Outside a domain, against Active Directory:** Windows 11 24H2 and later gets the TGT
    from a Samba AD KDC but asks for no service ticket with it, not even for `klist get`.
    This held for Samba 4.17 and 4.22, and matches the reported regression for machines
    outside the domain. From an MIT KDC it gets both. On a domain member (above) it works.

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
  or package variable. The pool resets every used Seclume connection, including calls whose
  side effects are hidden inside stored procedures or functions. SQL tracking is diagnostic
  only. Reset failures retire the connection; prepared statement caches are invalidated.

  | | the reset |
  |---|---|
  | PostgreSQL | `DISCARD ALL`, including server and local prepared statement caches |
  | MySQL | `COM_RESET_CONNECTION` |
  | SQL Server | the RESETCONNECTION bit on the next request |
  | Oracle | log off and log in again on the same connection: a new session, the same TCP and TLS connection and server process |

  This adds reset work to each used borrow, made while the connection waits in the pool, not
  by the next borrower. Oracle has no complete reset of its own: neither package
  reinitialisation nor `RESET_STATE` clears the client identifier or `ALTER SESSION`
  settings. A new session clears everything: package state, application contexts, client
  identifier, NLS settings, current schema, roles and temporary table rows
  (`LocalLogInAgainTest`). An open transaction is rolled back first, since a logoff would
  commit it. It costs one login, about 8 ms of which PBKDF2 is most, instead of a new
  connection and server process, which under load ran Oracle out of processes (ORA-12516).
  Kerberos and Windows logins cannot log in again on their connection; those sessions are
  still closed. Foreign JDBC drivers without `SessionReset` retain JDBC-only cleanup and do not
  receive this isolation guarantee. Migration with `detach()` / `adopt()` preserves the live
  session and its transaction; cleanup occurs only when the adopted borrow is returned.

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
- **A password rotated at its source, taken up on its own.** `pool.watchSecret(provider,
  interval)`, or `seclume.datasources.<name>.pool.secret-watch-interval=30s` in Spring, looks
  at the password's source: a mounted Kubernetes secret, a new Vault version, a replaced file.
  When the password changed, the pool rotates: idle connections go at once, borrowed ones
  when they come back, and new ones use the new password. See
  [Rotation without a restart](#rotation-without-a-restart).
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

## Spring Boot: data services from `application.properties`

With `seclume-spring-boot-starter` and the module of the service on the class path, one property
gives Spring Boot seclume's client, and Spring Boot's own configuration steps aside and builds
the rest on it - templates, repositories, listener containers, caches:

| Property | What you get | Built on it by Spring Boot |
|---|---|---|
| `seclume.mongodb.url` | `MongoClient` - seclume's own driver, or the official one on seclume's socket - and the reactive `MongoClient` | Spring Data MongoDB, sync and reactive |
| `seclume.elasticsearch.url` | `Rest5Client` | `ElasticsearchClient`, Spring Data Elasticsearch |
| `seclume.opensearch.url` | `OpenSearchClient` | - |
| `seclume.rabbitmq.url` | Spring AMQP's `CachingConnectionFactory` | `RabbitTemplate`, listener containers, `RabbitAdmin` |
| `seclume.nats.url` | a NATS `Connection` | - |
| `seclume.redis.url` | Spring Data Redis's `LettuceConnectionFactory` (standalone, Sentinel) | `RedisTemplate`, repositories, the cache |

A password in Spring Boot's own settings for the same service - `spring.mongodb.password`,
`spring.elasticsearch.password`, `spring.rabbitmq.password`, `spring.data.redis.password`, or a
URI with a password in it - stops the application at start: it would be a `String` in the
`Environment` for as long as the application runs, and it would not be used. Jedis is not offered
for Spring Data Redis, which gives Jedis no socket factory; use Lettuce, or `SeclumeRedisSocketFactory`
with Jedis directly.

## R2DBC

`seclume-r2dbc` is an R2DBC driver over the four JDBC drivers, not beside them. Everything
that makes seclume what it is - the protocols, its own TLS, the secret providers, the
password never on the heap, the session reset on every return - is in the JDBC drivers and
the pool, and a reactive application gets all of it. Each connection runs its calls one
after the other on a virtual thread: a blocked read costs a virtual thread, never one of the
few threads a reactive application has.

```
r2dbc:seclume:postgresql://app@db.internal/orders?provider=file&path=/run/secrets/db
```

- **The database's own placeholders**: `$1` on PostgreSQL, `?` on MySQL, `@name` on SQL
  Server, `:name` on Oracle - what each vendor's R2DBC driver takes, so SQL written for one
  of them runs unchanged. String literals, comments and dollar-quoted bodies are left alone.
- **No password in the URL**: `password=` is refused. The secret comes from a provider, as
  everywhere in seclume.
- **Rows as they are asked for**: a result read halfway is left there, and the connection
  carries on.
- **Over the pool**: `SeclumeConnectionFactory.over(pool)`, and with Spring Boot that is the
  application's `ConnectionFactory` as soon as `seclume-r2dbc` is on the class path - over
  the same `seclume.datasources` as the JDBC side, with Spring's `R2dbcTransactionManager`
  and `DatabaseClient` on top. A connection given back is reset like a JDBC one.
- **Transactions, savepoints, isolation, generated keys, batches, BLOB/CLOB, a text of
  several statements** with one result each.
- **R2DBC's errors**: SQLSTATE classes become `R2dbcBadGrammarException`,
  `R2dbcDataIntegrityViolationException`, `R2dbcTimeoutException` and the rest.

Proven by R2DBC's own conformance suite (`r2dbc-spi-test`, all 34 cases) against each of the
four databases, see [FRAMEWORKS.md](FRAMEWORKS.md). Where a database differs, the case says
how rather than being left out: MySQL refuses a text of several statements on purpose and
Oracle has none, so that case checks the refusal; on Oracle generated keys are asked for by
name, as Oracle requires, and a `NUMBER` is read as the `BigDecimal` it is.

Against r2dbc-postgresql on one connection it is level on `select 1`, 10 % faster on a row
with a bind and 37 % on a thousand rows. Over the pool it is slower, by the session reset
r2dbc-pool does not make - [BENCHMARKS.md](BENCHMARKS.md#r2dbc-on-postgresql-15102026).

## MongoDB

`seclume-mongodb` connects the official MongoDB Java driver (`org.mongodb:mongodb-driver-sync` 5.x)
with the password off the heap:

```java
MongoClient client = SeclumeMongo.client(
        "mongodb://orders@cluster.example.invalid:27017/?authSource=admin&provider=file&path=/run/secrets/mongo");
MongoDatabase db = client.getDatabase("orders");
```

Or on an existing `MongoClientSettings.Builder`:

```java
MongoClientSettings.Builder builder = MongoClientSettings.builder();
SeclumeMongo.configure(builder, url);
MongoClient client = MongoClients.create(builder.build());
```

The official driver given a password keeps it as a `char[]` in its `MongoCredential` and computes
SCRAM on the JVM heap at every connect; over TLS, JSSE copies the plaintext again. Here the driver
is given no credential at all:

- **Pre-authenticated TLS socket:** `SeclumeMongoSocketFactory` opens the connection, runs seclume's
  own TLS 1.3 stack with certificate and host name verification (`tlsRootCert=`, `tlsPin=`), and
  executes SCRAM-SHA-256 (`saslStart`, `saslContinue`) entirely in native memory (`MemorySegment`,
  `space.seclume.internal.Scram`) before handing the already-authenticated socket to the driver.
- **Off-heap secret lifecycle:** The password is read from its `SecretProvider` into a scoped native
  `MemorySegment` and wiped with zeroes immediately after the client proof is calculated. The client
  proof is encoded into BSON binary in native memory and sent over TLS without ever becoming a Java
  `String` or `byte[]`.
- **Driver compatibility:** Standard MongoDB URL parameters (`replicaSet`, multiple hosts, `readPreference`,
  `appName`, `connectTimeoutMS`, `w`, etc.) are preserved and passed to `MongoClientSettings` via
  `applyConnectionString`. The driver issues its subsequent `hello` and commands on the pre-authenticated
  connection without credentials.
- **Strict TLS enforcement:** `tls=false` and `ssl=false` are rejected with `IllegalArgumentException`.
  A password in the URL is strictly refused ("use a provider").
- **Mutual authentication and protocol hardening:**
  - SASLprep is enforced off-heap: passwords with non-ASCII characters are rejected in v1 with a clear
    error message before network traffic.
  - Iteration limits: server-requested iterations below 4096 (RFC 7677) or above 10,000,000 are refused.
  - Server nonce must start with the client nonce.
  - Server signature is verified in constant time in native memory (`Scram.verifyServerFinal`).

Shown against MongoDB 8 (`LocalMongoTlsTest` against `seclume-mongo` with TLS 1.3 requireTLS, and
`ScriptedMongoServerTest` with mock TLS 1.3 fixture):
- Successful SCRAM-SHA-256 authentication and `ping` command execution;
- Both the password and the client proof are proven absent from the JVM heap dump via `NoSecretInHeap.assertAbsent`;
- Refusal on missing SCRAM-SHA-256, low iterations (< 4096), invalid server nonce prefix, wrong server
  signature, premature connection termination, non-ASCII password, and TLS host name mismatch.

The login is part of connecting: the connect timeout bounds TLS and SCRAM, so a server that
answers TCP and then says nothing does not hold the connection. Only SCRAM-SHA-256 is used -
a user the server offers SCRAM-SHA-1 alone is refused, never logged in with the weaker one.
The reactive driver (Netty, `SSLEngine`) is not covered yet.

### seclume's own MongoDB driver (`seclume-mongodb-driver`, in progress)

A driver of its own, from the socket to the API: `SeclumeMongoClients.create(url)` returns a
`com.mongodb.client.MongoClient` (the official sync API, `mongodb-driver-sync` 5.13), with
`org.mongodb:bson` and the application's `CodecRegistry` for documents, POJOs and records.
The URL is the same as above.

- **There so far:** `insertOne`/`insertMany` (in batches within the server's limits, the
  documents as an OP_MSG document sequence), `find` with all its options, cursors with
  `getMore` and `killCursors` on an early close, `first` in one batch without a cursor,
  `countDocuments`, `estimatedDocumentCount`, `distinct`, `aggregate` (with `$out`/`$merge`
  and database-level pipelines), `updateOne`/`updateMany` (operators and pipelines),
  `replaceOne`, `deleteOne`/`deleteMany`, `findOneAndUpdate`/`Replace`/`Delete`, the
  collection's `bulkWrite`, indexes, `createCollection`, `createView`, `listCollections`,
  `listDatabases`, `runCommand`, `explain`, read and write concerns.
- **Errors as the official driver raises them:** `MongoCommandException`,
  `MongoWriteException`, `MongoWriteConcernException`, `MongoBulkWriteException` with what got
  through. `LocalSameAsOfficialTest` runs the same operations through both drivers against the
  same server and compares every result and every refusal.
- **Replica sets and mongos:** the set is found from any one member and followed by a
  monitor (`hello` every `heartbeatFrequencyMS`); reads go where the read preference chooses,
  tags and staleness included, within the latency window; a primary that steps down is noticed
  from the error and from `topologyVersion`, and writes go on once the next one is elected.
- **Sessions and transactions:** `startSession`, causal consistency (a secondary read waits
  for the session's own write), `startTransaction`/`commitTransaction`/`abortTransaction`,
  `withTransaction` with its retries, and a session closed with a transaction open aborts it.
  Server sessions are pooled and ended on close.
- **Retryable writes and reads:** a single-document write gets a `txnNumber` and is sent once
  more after a dropped connection or an error the server labels `RetryableWriteError`; the
  server applies it once (`LocalReplicaSetTest`, with the server's `failCommand` fail point).
- **Nothing of one borrower reaches the next:** a pooled connection is not logged in again or
  out through `runCommand` (`saslStart`, `authenticate`, `logout` are refused - the login is
  seclume's); a cursor left open in a session is killed when the session ends, since the
  pooled server session goes on under the same `lsid`; a reused server session starts without
  the last transaction; `maxIdleTimeMS` and `maxLifeTimeMS` retire connections
  (`LocalNothingCarriesOverTest`).
- **Change streams:** `watch` on a collection, a database or the whole deployment, with
  `resumeAfter`, `startAfter`, `startAtOperationTime`, `fullDocument` and pre-images; a stream
  resumes by itself after a network error or an error the server labels resumable, from the
  last resume token it handed out (`postBatchResumeToken` included).
- **The client-level `bulkWrite`** (MongoDB 8): writes to several collections in one
  command, ordered or not, with per-write results when asked for and what got through when
  something fails.
- **Snapshot sessions:** every read in the session sees the data as of the first read's
  `atClusterTime`.
- **Unacknowledged writes (`w: 0`):** sent with `moreToCome` - the server does not answer -
  and refused in a session or a transaction, where they would make no sense.
- **Client-side operation timeouts (`timeoutMS`):** one deadline per operation, on the
  client, the database, the collection or the session; the server is told what is left
  (`maxTimeMS`, less the round trip), and retries, server selection and a pooled connection
  all count against it. Cursors in both of the specification's modes, `CURSOR_LIFETIME` and
  `ITERATION`. Expiry is a `MongoOperationTimeoutException`.
- **`mongodb+srv://`:** the hosts from the SRV record (only under the name's own domain),
  the options from the TXT record (only `replicaSet`, `authSource` and `loadBalanced`, as the
  specification allows); TLS is on regardless.
- **Compression:** `compressors=zlib,snappy,zstd` (the first the server agrees to is used),
  `zlibCompressionLevel`; snappy and zstd through aircompressor, Java without a native library,
  an optional dependency as in the official driver. The replies are
  decompressed with their announced size checked first.
- **Logins besides SCRAM-SHA-256:** `MONGODB-X509` with a client certificate from seclume's
  client identities (the key never on the heap); `MONGODB-AWS` with the workload's role
  (`credentials=instance|container|web-identity`) or an access key from a secret provider,
  signed with SigV4 off the heap; `MONGODB-OIDC` with a token from any secret provider
  (`token-provider=...`), the Kubernetes service account (`ENVIRONMENT:k8s`), an Azure
  managed identity (`ENVIRONMENT:azure`, the user as its client id) or a Google service
  account's identity token (`ENVIRONMENT:gcp`), both for the cluster's `TOKEN_RESOURCE` and read
  from the metadata service into native memory; logged in again when the server says the token
  expired.
- **A session carried on by another client** (`SeclumeSessions`): `handOff(session)` lets
  go of a session without ending it and returns its state - the `lsid`, the transaction's
  number, state and options, the causal-consistency times; no credential and no key.
  `takeUp(client, state)` in another process, logged in as the same user, carries the open
  transaction on and commits it.
- **Spring Data MongoDB:** a Spring Boot application gets seclume's client as its
  `MongoClient` bean; repositories, `MongoTemplate` and `@Transactional` run on it, with the
  MongoDB driver version Spring Boot manages (FRAMEWORKS.md).
- **Behind a load balancer** (`loadBalanced=true`, also from a TXT record): mongos routers
  behind one address, as Atlas serverless and private endpoints put them. Nothing is
  monitored; each command borrows a connection, and a cursor or a transaction keeps the one
  it began on until it ends - the router behind it is the only one that knows it. A router
  that does not answer `hello` with a `serviceId` is refused, and a network error distrusts
  only the connections to the same router. Tested against two mongos behind HAProxy, with a
  control that shows the cursors and transactions failing without the pinning.
- **Atlas Search indexes:** `createSearchIndex(es)`, `updateSearchIndex`, `dropSearchIndex`,
  `listSearchIndexes` - the index management specification's commands, for Atlas or a server
  with mongot beside it; checked against the official driver for the same server answers.
- **GridFS:** the official driver's `GridFSBuckets.create(database)` runs on seclume's
  database - upload, download, streams, find, rename, delete - checked against the official
  client's buckets byte for byte.
- `mapReduce` is not offered (deprecated by MongoDB).
- **An APM agent in the process** (`ApmAgentHeapDumpTest`): the OpenTelemetry Java agent with
  its MongoDB instrumentation records the commands of both drivers, and the heap dump of that
  JVM does not hold the password. The control - the official driver given the password itself,
  under the same agent - is found by the same search.
- **The reply parser is strict and fuzzed** (`OpMsgFuzzTest`): it checks every length in a
  reply's documents before the bson library reads them, whose reader allocated whatever a
  length announced.

### The reactive API (`seclume-mongodb-reactive`)

`SeclumeMongoReactiveClients.create(url)` returns a
`com.mongodb.reactivestreams.client.MongoClient` (the official Reactive Streams API,
`mongodb-driver-reactivestreams` 5.x) over seclume's own driver: each publisher runs the
blocking operation on a virtual thread once it is subscribed to and asked for something,
and hands documents on only as they are asked for. A cancel ends the operation and closes
its cursor. The publishers pass the Reactive Streams TCK (`PublishersTckTest`); Spring Data
MongoDB reactive - `ReactiveMongoRepository`, `ReactiveMongoTemplate`, transactions through
`ReactiveMongoTransactionManager`, change streams - runs on it (FRAMEWORKS.md).

## Reports: JasperReports, embedded

JasperReports needs nothing of its own: it fills a report from a `java.sql.Connection`, and a
seclume connection is one. Hand it over directly:

```java
try (Connection connection = pool.getConnection()) {       // a SeclumePool, or any seclume DataSource
    JasperPrint print = JasperFillManager.fillReport(report, parameters, connection);
}
```

**Not through JasperReports' JDBC data adapters** (`.jrdax`, `JdbcDataAdapter`). They keep
the password as a `String` and pass it as the connection property `password` - the heap copy
seclume exists to avoid, and a property seclume refuses. A `DataSource` in your application,
a connection per fill, and the adapter left out: that is the whole integration.

`seclume-jasperreports-proof` fills three reports over a pooled seclume connection, keeps the
pool open, dumps the heap and searches it for the password - with a negative control that
puts the password into a report parameter and must be found. JasperReports is LGPL-3.0; it is
a test dependency of that module only, which is neither installed nor published, and no
seclume artifact depends on it.

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

### PLAIN and OAUTHBEARER

PLAIN sends the password itself, and OAUTHBEARER the token itself, so for these two the secret
has to reach the wire. With Kafka's own modules it passes through Kafka's request buffer and
then the JDK's TLS engine on the way, heap buffers that are never wiped. `seclume-kafka` puts
Kafka's TLS on seclume's own TLS 1.3 stack and gives Kafka a placeholder instead of the secret.
As the SaslAuthenticate request is encrypted, the engine writes the secret in the placeholder's
place from native memory, along with the two lengths that follow from it:

```properties
security.protocol=SASL_SSL
ssl.engine.factory.class=space.seclume.kafka.SeclumeSslEngineFactory
ssl.truststore.type=PEM
ssl.truststore.location=/etc/kafka/ca.pem
sasl.mechanism=PLAIN
sasl.jaas.config=space.seclume.kafka.SeclumePlainLoginModule required \
    username="orders" provider="file" path="/run/secrets/kafka";
```

```properties
sasl.mechanism=OAUTHBEARER
sasl.jaas.config=space.seclume.kafka.SeclumeOAuthBearerLoginModule required \
    token-url="https://login.example.com/oauth2/token" client-id="orders" scope="kafka" \
    provider="file" path="/run/secrets/client-secret";
```

- **PLAIN** (Confluent Cloud's API key and secret): the password is read from its provider at
  every login.
- **OAUTHBEARER** has two token sources. With `token-url`, it uses the OAuth 2.0 client
  credentials grant of `seclume-http` (same options as `auth=oauth2`; the client secret and
  the token stay in native memory, and the token is fetched again before it expires). Without
  it, the provider names the token itself: a file another process keeps fresh,
  `azure-managed-identity`, or `gcp-metadata`. `extension_<name>="..."` options go to the
  broker as SASL extensions, for example Confluent Cloud's `logicalCluster` and
  `identityPoolId`.
- **The engine factory**, `SeclumeSslEngineFactory`, always checks the broker's certificate and
  host name. It trusts `ssl.truststore.location` (PEM, JKS or PKCS12) or
  `ssl.truststore.certificates` if one is set, and otherwise the JVM's store;
  `seclume.tls.pin=sha256/...` pins the broker's key. It speaks TLS 1.3 only.
  - Turning host name verification off (`ssl.endpoint.identification.algorithm=`) is refused.
  - Client certificates (`ssl.keystore.*`) are refused.
  - SCRAM also works over this engine.
- **Without the engine** (`SASL_PLAINTEXT`, or the JDK's engine), the PLAIN and OAUTHBEARER
  modules refuse to log in rather than send the secret some other way.

Shown in three ways:
- **Kafka's own classes** (`SaslAuthenticateRewriterTest`): Kafka serialises the request in
  every SaslAuthenticate version, the rewrite runs, and Kafka parses it back. The secret sits
  where the placeholder was, and the frame and varint lengths agree, including a token long
  enough to push the varint to a second byte.
- **A real broker** on SASL_SSL (`LocalKafkaSaslSslTest`, broker 4.1 from `proof/broker.sh`):
  PLAIN, OAUTHBEARER and SCRAM each produce and consume, a wrong password is refused by the
  broker, and a broker whose CA is not named is refused by the client. The heap dump holds
  neither the password nor the token.
- **The control** (`-Dseclume.kafka.control=true`): the same search finds the password with
  Kafka's own `PlainLoginModule` on the JDK's TLS.

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
and the same check finds it.

### Lettuce

```java
// Standalone:
RedisClient redis = SeclumeLettuce.client(
        "rediss://cache:6380?user=orders&provider=file&path=/run/secrets/redis");
try (StatefulRedisConnection<String, String> connection = redis.connect()) { ... }
redis.shutdown();                      // shuts down its client resources as well

// Sentinel (and optional sentinelUser= / sentinel-provider= when Sentinel itself takes a login):
RedisClient sentinel = SeclumeLettuce.client(
        "rediss-sentinel://s1:26379,s2:26379?sentinelMasterId=mymaster"
        + "&user=orders&provider=file&path=/run/secrets/redis");

// Cluster:
RedisClusterClient cluster = SeclumeLettuce.clusterClient(
        "rediss://node-1:6379,node-2:6379?user=orders&provider=file&path=/run/secrets/redis");
```

Lettuce given a password keeps it as a `char[]` in its credentials and encodes it into a Netty
buffer for `AUTH` or `HELLO` at every connect and reconnect. Over TLS, the JDK's engine or
OpenSSL's then copies it once more. `SeclumeLettuce` gives Lettuce a random placeholder instead.
The password is read from its provider into native memory for each of those commands and
written in the placeholder's place, together with its RESP length, just before it leaves:

- over `rediss://` and `rediss-sentinel://`, by a Netty `SslHandler` on seclume's own TLS 1.3
  engine, put in front of the socket as the channel connects to its target node. Lettuce itself
  sees a plain connection. Each node's engine checks that node's own certificate and host name or
  IP address (`tlsRootCert=`, `tlsPin=`) — whether it is a seed node, a cluster shard discovered
  on topology refresh or redirect, a Sentinel, or the master Sentinel resolves — and puts the
  password into the cipher from native memory.
- over `redis://` and `redis-sentinel://`, by the first handler before the socket, which hands the
  socket a direct buffer over the native memory and wipes it once the socket has taken it.

When Sentinel nodes take a login of their own, `sentinelUser=` and `sentinel-provider=` (with
`sentinel-path=`, and so on) supply Sentinel's credentials through a second placeholder, also off
the heap.

Shown against Redis 8 (`LocalLettuceTest`) and multi-node TLS 1.3 Cluster and Sentinel topologies
(`SeclumeLettuceTopologyTest`):

- plain TCP and TLS 1.3 both log in over RESP3's `HELLO`;
- Cluster shards and Sentinel-resolved masters whose certificates carry their own host name or IP
  are verified per node, while a discovered shard or master presenting another node's certificate
  is refused before any password is sent;
- when the server kills the connection, Lettuce reconnects and logs in again through the same
  path;
- a wrong password is refused, and so is a server the JVM does not trust;
- the heap dump holds no copy of the Redis or Sentinel password.

With `-Dseclume.redis.control=true`, Lettuce is given the password itself, and the same search
finds it.

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
  On Windows the same key is imported into CNG (the software key storage provider) and signs
  there. So OpenSSL 3 on 64-bit Linux or CNG on Windows; HMAC works everywhere.
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

- **Keys:** RSA, EC and Ed25519, as PEM or DER (PKCS#8, PKCS#1, SEC 1), or as OpenSSH's own
  format, which `ssh-keygen` writes. An OpenSSH file is converted in native memory, and RSA's
  CRT values are computed there too, without `BigInteger`. A passphrase-protected OpenSSH key
  is refused with a hint; an encrypted key goes through `provider=encrypted`.
- **Signatures:** TLS 1.3 and 1.2 with RSA-PSS, RSA PKCS#1, ECDSA and Ed25519.
- **Checks:** a certificate chain that does not belong to the key is refused.
- **Platform:** OpenSSL 3 on 64-bit Linux, or CNG on Windows (RSA and ECDSA; Ed25519 keys sign
  with OpenSSL only - CNG has no Ed25519).

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

- **Keys with SSHD:** RSA (`rsa-sha2-256/512`) and ECDSA on P-256, P-384 and P-521, in any
  of the formats above, including OpenSSH's.
- **Ed25519, and JSch:** SSHD signs Ed25519 only with the key classes of `net.i2p` or Bouncy
  Castle, which cannot stand in for a key held by OpenSSL. JSch (the maintained fork, also used
  by Apache Camel's SFTP) takes an identity that signs by itself: `SeclumeJschIdentity.add(jsch,
  "provider=file&path=/run/secrets/id_ed25519")` covers Ed25519, ECDSA and RSA.
- **Passwords:** a password login cannot be protected, because SSHD encrypts it in Java before
  it reaches a socket.
- **Spring Boot:** `seclume.ssh.key` makes a started `SshClient` bean.
  - Host keys are checked against `seclume.ssh.known-hosts`. An unknown server is refused
    unless `seclume.ssh.allow-unknown-hosts=true`.
  - With `seclume.sftp.host`, `.port` and `.user` there is also Spring Integration's
    `DefaultSftpSessionFactory` on that client.
- **Tests:** they use SSHD's own SFTP server. Keys come from `ssh-keygen`, and each public key
  seclume derives must be the one `ssh-keygen` exports.

## Elasticsearch and OpenSearch

`seclume-elasticsearch` gives the official clients an API key, token or password they never
hold:

```java
ElasticsearchClient es = SeclumeElasticsearch.client(
        "https://es.example.com:9200/?auth=apikey&provider=file&path=/run/secrets/es-key");
OpenSearchClient os = SeclumeOpenSearch.client(
        "https://app@os.example.com:9200/?auth=basic&provider=file&path=/run/secrets/os");
```

- **Clients:** the typed `ElasticsearchClient` and the low-level `Rest5Client` of
  elasticsearch-java 9 (Apache HttpClient 5), the `RestClient` of elasticsearch-rest-client
  (HttpAsyncClient 4, under Elasticsearch 8's clients), and opensearch-java 3 on
  `ApacheHttpClient5Transport`. The application brings the client versions it uses.
- **How:** the client is given a placeholder in its `Authorization` header. Its connections are
  seclume's TLS 1.3 engine (`SeclumeSslContext`, in seclume-http), which writes the secret in from
  native memory as each request head goes into the cipher - the API key, the token, or
  `base64(user:password)` for Basic. A head the client writes in pieces is held until it is
  whole, so a placeholder split across two writes never goes out unreplaced.
- **Bodies are not touched:** a document that contains a placeholder is stored with the
  placeholder. Only request heads are rewritten - which is why the engine follows the HTTP/1.1
  framing (`Content-Length`, chunks) and offers no ALPN, so the clients stay on HTTP/1.1.
- **The URL:** `auth=apikey` (the encoded key, `base64(id:key)`, as Elasticsearch hands it
  out), `auth=bearer`, or `auth=basic` with the user before the `@`; any secret provider;
  `tlsRootCert`/`tlsPin`; several hosts separated by commas. `http://` and a password in the
  URL are refused. OpenSearch's security plugin has no API keys: Basic or a bearer JWT.
- **Tests:** against a local TLS server that accepts only the real credential, every client
  and Basic, with pieces of a byte at a time (`HttpCredentialRewriterTest`); against
  Elasticsearch 9.5 and OpenSearch 3.9 with TLS (`LocalSearchTest`: indexed, read back,
  searched, a wrong key refused by the server); and the key searched for in a heap dump after
  all four clients were used, the server in a JVM of its own (`NoKeyOnTheHeapTest`).
- **Amazon OpenSearch Service and Serverless, signed with SigV4:**
  `SeclumeOpenSearch.awsClient("https://<domain endpoint>/?auth=aws&region=...&access-key-id=...&provider=...")`,
  or `credentials=instance|container|web-identity` for a workload's temporary credentials;
  `service=aoss` for Serverless. opensearch-java's own `AwsSdk2Transport` signs with the SDK's
  signer and offers no way to replace it, so it is given a placeholder key, and its HTTP client -
  `SeclumeAws.resigning`, over seclume's TLS - drops that signature and signs each request again
  from native memory (`AmazonOpenSearchTest`: the signature that arrives is the one the SDK's
  signer makes with the real key; `ResigningTest`: the placeholder's own signature is refused).

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

**Temporary credentials**, the way AWS means workloads to get them:

```java
SeclumeAws.configure(S3Client.builder(), "credentials=instance&region=eu-central-1")      // EC2
SeclumeAws.configure(S3Client.builder(), "credentials=container&region=eu-central-1")     // ECS, EKS Pod Identity
SeclumeAws.configure(S3Client.builder(), "credentials=web-identity&region=eu-central-1")  // EKS IRSA
```

- **Where they come from:** the EC2 metadata service, the container credentials endpoint, or
  STS. For STS, the pod's web identity token goes in the body of `AssumeRoleWithWebIdentity`.
  Every secret on the way stays in native memory: the fetch tokens, the secret key and the
  session token.
- **How the session token is sent:**
  - The token is signed in native memory.
  - The SDK's Apache 5 client gets seclume's TLS as its socket, and that socket writes the
    token into each request's header block.
  - The socket follows the HTTP framing, so request bodies are never touched.
  - Credentials are refreshed five minutes before they expire. The last generations are kept,
    so a request signed just before a refresh goes out with its own token.
- **Limits:** only synchronous clients. With Spring Boot, `seclume.aws.credentials=...`
  customizes the synchronous clients only.

**Presigned URLs**, for a browser to upload or download directly:

```java
SeclumeS3Presigner presigner = SeclumeS3Presigner.of("access-key-id=AKIA...&region=eu-central-1&provider=...");
URL download = presigner.presignGet("reports", "2026/q3.pdf", Duration.ofMinutes(10));
```

- **Why not the SDK's own presigner:** `S3Presigner` signs with the SDK's signer and the
  credentials it was given. With a client set up here those are a placeholder, and S3 refuses
  the URLs.
- **Temporary credentials** are refused, because the session token would be part of the URL.

**How it is tested:**
- For thirteen request shapes the signature is compared byte for byte with the SDK's own
  signer: S3 with and without a signed body, CRC32 checksums, queries, non-ASCII, dot
  segments and more.
- The key derivation is checked against AWS's published test vector.
- The S3 and SQS clients, sync and async, run against a local server that checks every
  signature with the SDK's signer. S3 is also tested over HTTPS, where the body goes unsigned
  and the checksum goes in a header.
- A presigned URL is compared with the SDK signer's in query mode. It is also used the way a
  browser would, with a plain PUT and GET.
- Temporary credentials are tested against a container endpoint, STS and S3, all in a process
  of their own, so no secret is ever in the test JVM.
- The heap proofs cover the secret key, the session token, the container token and the web
  identity token. They run in JVMs of their own.

**Limits:**
- SigV4a (S3 multi-region access points) signs with ECDSA P-256 from a key derived from the
  secret key in native memory, as AWS derives it; OpenSSL 3 on 64-bit Linux or CNG on Windows,
  as seclume's other signing with a private key. Checked on both against AWS's own SigV4a test
  suite (the derived public key, and signatures that verify with it).
- An async client's body is collected in memory before it is signed. This is meant for the
  small bodies of SQS, SNS and DynamoDB. S3 over HTTPS sends its body unsigned, so nothing is
  collected there.

## Azure Storage

`seclume-azure` signs Azure Storage requests (Blob, Queue, File, Data Lake) with Shared Key.
The account key, base64 as the portal shows it, is decoded in native memory, and the HMAC is
computed there. The SDK's `StorageSharedKeyCredential` keeps it as a `String` instead.

```java
HttpPipelinePolicy signing = SeclumeAzure.sharedKey("account=mystorage&provider=file&path=/run/secrets/storage-key");
BlobServiceClient blobs = new BlobServiceClientBuilder()
        .endpoint("https://mystorage.blob.core.windows.net").addPolicy(signing).buildClient();
```

- **Equivalence:** five request shapes are compared with the SDK's own credential.
- **End to end:** Blob and Queue run against Azurite, Microsoft's emulator, in a process that
  reads the key from its file. A wrong key gets 403.
- **Heap proof:** it searches for the key as text and as decoded bytes.

## Google Cloud

`seclume-gcp` reads a service account's JSON key file into native memory. The `private_key` in
it is unescaped there and decoded by OpenSSL.

```java
GoogleCredentials credentials = SeclumeGcp.credentials(
        "provider=file&path=/run/secrets/service-account.json&scopes=https://www.googleapis.com/auth/cloud-platform");
```

- **Signing:** the auth library signs its JWTs through seclume's JCA provider. The public
  fields (e-mail, key id, project) are ordinary strings.
- **Limits:** the access token it gets back, valid for an hour, is the library's own
  `String`. The key itself, valid until it is deleted, stays in OpenSSL.
- **Test:** a token endpoint checks every assertion against the account's public key.

## Kubernetes, Git and gRPC

`SeclumeSslSocketFactory` (in `seclume-http`) is an `SSLSocketFactory` for HTTP clients that
were not written for seclume. The client gets a placeholder instead of the secret, and builds
its requests with it. The factory's sockets are seclume's TLS 1.3: they check the server's
certificate themselves (the JVM's trust, `tlsRootCert` or `tlsPin`) and write the secret
from native memory where the placeholder stands.

```java
SeclumeSslSocketFactory tls = SeclumeSslSocketFactory.of("tlsRootCert=/etc/ca.pem");
String token = SeclumeSslSocketFactory.placeholder("provider=file&path=/run/secrets/token");
OkHttpClient client = new OkHttpClient.Builder()
        .sslSocketFactory(tls, tls.trustManager()).hostnameVerifier(tls.hostnameVerifier()).build();
// request.header("Authorization", "Bearer " + token)
```

- **HTTP/1.1:** the sockets follow the framing (heads, bodies, chunks) and rewrite heads
  only. A placeholder anywhere in a head becomes the secret; `Basic base64(user:placeholder)`
  is decoded and encoded again in native memory. Bodies go through untouched.
- **HTTP/2** (`tls.http2()`): the sockets offer and require `h2`. They decode each header
  block and encode it again for the server. Every field is a literal without indexing, so
  the server's dynamic table stays empty; a field with a secret is *never indexed*. DATA
  frames go through untouched.
- **Rotation:** the secret is read for each request, so a rotated token file is picked up
  at once.
- **Safety:** placeholders carry a random per-process nonce, and an unknown one fails the
  request instead of being sent.

### Kubernetes: `seclume-kubernetes`

```java
ApiClient client = SeclumeKubernetes.inCluster();          // the pod's CA and token
ApiClient client = SeclumeKubernetes.client("https://api.cluster:6443"
        + "?tlsRootCert=/etc/kube/ca.crt&provider=file&path=/etc/kube/token");
```

`ClientBuilder.cluster()` puts the service account token into a `String`, and a new copy
into every request. Here the client holds a placeholder. The token is read from its
projected file for each request, so kubelet's rotations need no restart.

### Git: `seclume-jgit`

```java
HttpTransport.setConnectionFactory(SeclumeGit.connections("tlsRootCert=/etc/git-ca.pem"));
Git.cloneRepository().setURI("https://git.example.com/app.git")
        .setCredentialsProvider(SeclumeGit.credentials("deploy", "provider=file&path=/run/secrets/git-token"))
        .call();
```

The password or access token goes into JGit's Basic login as a placeholder. It is written in
native memory when the request leaves.

### gRPC: `seclume-grpc`

```java
ManagedChannel channel = SeclumeGrpc.channel("api.example.com", 443, "").build();
CallCredentials token = SeclumeGrpc.bearer("provider=file&path=/run/secrets/token");
stub.withCallCredentials(token).call(request);
```

- **Transport:** the channel is gRPC's OkHttp transport over the HTTP/2 sockets above.
  `SeclumeGrpc.header("x-api-key", spec)` covers API keys.
- **Limits:** the transport must not Huffman-code header strings; gRPC's OkHttp transport
  does not, and a block that does is refused rather than sent. The Netty transport is not
  covered: it does its own TLS.
- **Tests:** a gRPC server in another process checks every call; the tests cover rotation,
  header blocks larger than one frame, and the heap.

## LDAP and Active Directory

`seclume-ldap` gives JNDI, and with it Spring LDAP and Spring Security's LDAP support, a
socket factory. JNDI holds a placeholder instead of the service account's password. For
`ldaps://` (default port 636) the socket connects directly with seclume's TLS 1.3; for
`ldap://` (default port 389) it first sends the RFC 4511 StartTLS `ExtendedRequest`
(`1.3.6.1.4.1.1466.20037`), verifies the `ExtendedResponse` (and refuses any trailing
plaintext bytes injected before the handshake), and upgrades the connection to seclume's TLS.
In the bind that carries the placeholder, it either writes the real password and the BER
lengths that follow from it from native memory, or (when `authentication=kerberos` /
`authentication=gssapi` is set) drives the 3-step RFC 4752 SASL `GSSAPI` bind using the
operating system's Kerberos ticket cache (`libgssapi_krb5.so.2` on Linux, `secur32.dll` SSPI
on Windows) with mutual authentication and `NO_PROTECTION` (`0x01`) over the TLS channel.

```java
SeclumeLdap ldap = SeclumeLdap.of("ldaps://ad.example.com/dc=example,dc=com"
        + "?user=svc-app@example.com&provider=file&path=/run/secrets/ldap");
DirContext context = new InitialDirContext(ldap.environment());

// StartTLS on port 389 with Active Directory / Kerberos (SASL GSSAPI)
SeclumeLdap kerberos = SeclumeLdap.of("ldap://ad.example.com/dc=example,dc=com"
        + "?authentication=kerberos");

LdapContextSource source = new LdapContextSource();          // Spring LDAP
source.setUrl(ldap.url()); source.setBase(ldap.base());
source.setUserDn(ldap.user()); source.setPassword(ldap.password());
source.setBaseEnvironmentProperties(ldap.socketFactory());
```

- **StartTLS (`ldap://`):** negotiated inside `LdapSocket.connect` before any bind or directory
  operation leaves JNDI, and verified with the same `tlsRootCert` / `tlsPin` options as
  `ldaps://`.
- **Kerberos / GSSAPI (`authentication=kerberos`):** optional `serviceName=` (default `ldap`),
  `serverSpn=` (explicit SPN such as `ldap/dc1.example.com`), and `user=` / `authorizationId=`
  (RFC 4752 SASL authorization identity). No JAAS config and no keytab in the JVM heap.
- **What passes through unchanged:** binds with any other password. An end user logging in
  through Spring Security binds with what they typed.
- **Spring Boot:** `seclume.ldap.url=ldaps://...` or `ldap://...` makes the
  `LdapContextSource` bean. Boot's `LdapTemplate` and Spring Security's LDAP authentication
  use it.
- **Tests:** they run against UnboundID's directory server (both `--useSSL` and
  `--useStartTLS`) in a process of its own so the password is never in the test JVM, plus
  in-memory SASL `GSSAPI` servers testing mutual authentication and security-layer negotiation.

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

## Rotation without a restart

Passwords, keys and certificates are replaced at their source, and nothing should need a
restart for it. `SecretWatch` (in the core) notices the change:

```java
SecretWatch watch = SecretWatch.start("orders-db", provider, Duration.ofSeconds(30),
        () -> pool.rotateSecret(true));
```

- **How it compares:** it reads the secret into native memory, as for a login, and keeps
  only an HMAC-SHA256 of it under a random key. Both the key and the fingerprint are in native
  memory, so the watch holds neither the secret nor anything a dictionary could turn back
  into it.
- **What is not a change:** a source that cannot be read for a moment (Vault restarting, a
  file mid-swap). The watch keeps what it knew and looks again at the next tick.
- **Each rotation** is a `space.seclume.SecretRotation` JFR event with the watch's name and
  whether taking up the new secret worked. With `seclume.metrics.queries=true` it is also the
  Micrometer counter `seclume.secret.rotations{watch, outcome}`.

What uses it:

| | |
|---|---|
| **Pool** | `pool.watchSecret(provider, interval)`; Spring: `seclume.datasources.<name>.pool.secret-watch-interval` |
| **TLS server key and certificate** | `SeclumeKeys.keyManager(chain, keySpec, interval)`, `keyManagerFactory(...)`, `SeclumeTomcat.enableHttps(..., interval)`; Spring: `seclume.ssl.bundles.<name>.reload-interval` |
| **Client certificates** of the drivers | reloaded when the file changes, as before (`CertificateReload` event) |
| **HTTP, gRPC, Kubernetes, JGit, AWS static keys** | read for each request anyway: nothing to watch |

- **Server keys renew as a pair.** cert-manager and certbot replace the key and the
  certificate together, and each file on its own is a change. A new pair is served from the
  next handshake on, and only if the certificate is the key's. A renewal that is only half
  there (the new key, the old certificate) is refused while the old pair keeps serving; the
  second half arriving completes it.
- **In-flight handshakes are safe.** Each generation has an alias of its own, so a handshake
  that chose the old pair gets the old key and chain, and so does a TLS library that caches
  key material by alias. The old key is freed a minute after it was replaced.

## Proving there is no secret on the heap, for any application

- **`seclume-heapcheck`** proves for **any** running Java process whether a given secret is in
  its heap, including applications that do not use this library. For an audit it also:
  - checks a dump that exists already (`--dump app.hprof`, e.g. from
    `-XX:+HeapDumpOnOutOfMemoryError`);
  - checks several secrets at once (`--secret-file` again and again, or `--secret-dir` for a
    mounted Kubernetes secret); a file that is not UTF-8, such as a DER key, is looked for as
    bytes;
  - writes a report (`--report heapcheck.md`, `--report heapcheck.json`): the JVM, the dump's
    size and SHA-256, the method, and for each secret where it was found. Secrets are named by
    their files; the report holds neither a secret nor a hash of one.

  ```
  java -jar seclume-heapcheck.jar --dump app.hprof --secret-dir /run/secrets/app \
          --report heapcheck.md --report heapcheck.json
  ```

  Exit code 0: nothing found; 1: a secret is in the heap; 2: the check could not run.
- **`seclume-tck`'s `NoSecretInHeap`** runs the same proof in **your own test suite**:
  - `@ExtendWith(NoSecretInHeap.class)` checks after every test.
  - `NoSecretInHeap.assertAbsent(secretFile)` checks at a moment you choose, say right after
    the login.

  The password comes as a file (`-Dseclume.tck.secret-file=/run/secrets/db`), and the search
  runs in a process of its own, because a pattern in the test JVM would be found in the very
  heap it searches. A hit says where the secret was, never what it is. It finds the leaks the
  driver cannot prevent: a configuration object, a log line, a `toString()`.
