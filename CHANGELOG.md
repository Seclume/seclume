# Changelog

All notable changes to seclume are recorded here. Versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.10.0] - 2026-09-26

The three items listed under *Not yet* in 0.9.0 are done: the four wire
parsers are fuzzed, the compatibility matrix is generated from the test run
rather than written by hand, and the benchmark figures are recorded by a
harness that states the machine they came from.

Beyond that, in short:
- **Logins with no secret in the process**: Kerberos for PostgreSQL, MariaDB
  and SQL Server; PostgreSQL 18 OAuth; Azure SQL access tokens; RDS IAM and
  Secrets Manager from the EC2 instance role.
- **Beyond databases**: `seclume-kafka` (SASL/SCRAM) and `seclume-redis`
  (Jedis) without the password on the heap; `seclume-quarkus`, JVM and native.
- **Security work**: constant-time AES, Base64 and RSA; AES-GCM from the
  operating system; post-quantum key exchange; a code review's ten findings
  fixed; Semgrep, Trivy, CodeQL and Scorecard in CI.
- **Tested against real AWS**: seven bugs found there and fixed
  ([test-reports/aws-2026-09-26.md](test-reports/aws-2026-09-26.md)).
- A pool bug that lost a connection to every Spring `queryForStream`, and a
  login that could hang for ever on a silent server, fixed.

### Against real AWS: seven bugs no stand-in showed, and credentials from the instance role

A day on AWS (Aurora PostgreSQL, RDS MySQL and SQL Server, EC2 on x86 and ARM) found what
tests against stand-ins had not. The full log is in [test-reports/aws-2026-09-26.md](test-reports/aws-2026-09-26.md).
- **RDS IAM tokens were signed for the wrong service** (`rds` instead of `rds-db`), and every
  login was refused. The independently computed test vector shared the mistake. The token now
  matches the AWS CLI's, made in the same second, byte for byte.
- **`tlsRootCert=aws-rds` lacked the Amazon Trust Services roots** that Aurora's relay and RDS
  Proxy chain to. The four roots were added and checked against the JDK's trust store.
- **A login could hang for ever** on a server that accepted the connection and then went
  silent. An Aurora instance mid-failover did that. `connectTimeout` now bounds every wait of
  the login in all four drivers, and is lifted once logged in.
- **MySQL's IAM login broke**: 256 bytes were reserved for the answer, and a token is about
  370.
- **SQL Server 2019's TLS handshake overflowed** the buffer a flight is collected in on TDS 7.4.
- **Secrets Manager refused every signature**: a second `Content-Type` beside the signed one.
  AWS's own reason is now part of the error.
- **`aurora=true` refused a first `secondary` connection** before anything was known. It now
  learns the topology from whichever instance answers.
- **`credentials=instance`** for `rds-iam` and `aws-secrets-manager`: the EC2 instance role's
  temporary credentials from IMDSv2. The secret key and the session token go into native
  memory, and so does the metadata service's own token. `rds-iam` can now sign with a session
  token at all, and it writes the finished token, which is the password for fifteen minutes,
  straight into native memory. It used to be a `String` first.
- Also shown there: session moves, a real crash (`stop-instances --force`) and a real network
  partition across EC2 machines in splice and tunnel mode, and a crash taken over from an x86
  machine by an ARM machine. PostgreSQL and MySQL throughout.

### Aurora: failover without waiting for DNS

`aurora=true` on PostgreSQL and MySQL: after each login the driver reads the cluster's
instances from the instance itself, and the next connect tries them directly. The writer comes
first for `primary` and the readers first for `secondary`, with the cluster endpoint last. The
topology logic is generalised (`ClusterTopology`, which Patroni's now implements too). Shown
against a stand-in with PostgreSQL primary and replica (`proof/aurora.sh`): after the failover
the new writer is found in 29 ms, and without `aurora=true` the dead endpoint refuses.
- MySQL's role probe now reads `@@read_only or @@innodb_read_only`: an Aurora MySQL reader says
  it is one in the second.

### SQL Server: integrated login with Kerberos, and a LOGIN7 field table put right

`authentication=kerberos` (also `integratedSecurity=true`): LOGIN7 with `fIntSecurity` and the
first GSSAPI token, further tokens as SSPI packets. The login counts only when the server's
own token completes the context. Shown against SQL Server 2022 with a Samba Active Directory
(`proof/kerberos.sh`, domain controller, database and client in rootless containers).
- Found on the way: LOGIN7 had ten offset/length pairs before `ClientID` where MS-TDS has
  nine. `ClientID`, the SSPI pair and the rest sat four bytes late. That was harmless while
  all of them were zero, and wrong for the first token that had to go there.
  `Login7LayoutTest` pins the offsets.
- `authenticationMethod()` now says how the session logged in (password, token or Kerberos)
  instead of always "SQL login".

### The pool lost a connection to every `queryForStream`

`Statement.getConnection()` returned the driver's connection, not the pool's handle it was
made through. JDBC says it returns the connection that made the statement, and frameworks
rely on it: Spring's `JdbcTemplate.queryForStream` gives its connection back by closing
`statement.getConnection()`. Closing the driver's connection behind the pool's back ended the
session, and the pool never saw the handle return. Every streamed query cost the pool one
connection for good; after `maximum-pool-size` of them the pool was empty and waited out its
connection timeout. `DatabaseMetaData.getConnection()` and the XA handle had the same fault.
- Found by the build, not by a user: the Spring suite's JVM waited at exit for connections that
  could never come back, ten seconds per pool, and surefire killed it after thirty (61 s ->
  31 s for that module now).
- A driver connection now knows the handle in front of it (`Fronted`, set by the pool on
  borrow and by the XA connection on `getConnection()`, cleared on return). A statement or a
  metadata object names the handle that was in front when it was made; a cached statement
  names the handle that took it from the cache.
- `StatementsNameTheHandleTest`, all four, with and without the statement cache: the handle
  from every statement and the metadata, and closing what a statement names gives the
  connection back. With the handle not set, all four fail.

### Quarkus: the native image, built and checked

The extension had only been shown in JVM mode. The first native build failed. Quarkus
initialises classes when the image is built, and seclume's classes that bind native code
(CNG, OpenSSL, the memory lock) tried to do that on the build machine: `Cannot open library:
bcrypt.dll` on Linux. The extension now has the library's packages initialised at run time,
as a plain native image already does.
- `seclume-quarkus/native-it`: four datasources, built with GraalVM 25 in 1 min 44 s. From
  the binary all four log in (SCRAM-SHA-256, caching_sha2_password, LOGIN7 inside TLS,
  O5LOGON), and the image's own heap dump holds none of the four passwords. As a control,
  the same search finds the user name in the same dump.

### Redis: Jedis without the password on the heap

`seclume-redis`: a `JedisSocketFactory` that logs in before Jedis gets the socket. `AUTH` is
written from native memory, and over `rediss://` it goes through seclume's own TLS 1.3 with the
traffic keys off the heap as well. Jedis is given no password. Shown against Redis 8 with an ACL
user, plain and TLS 1.3, one connection and a pool. The heap dump afterwards holds no copy of
the password, while Jedis configured with it does. `proof/redis.sh` keeps only the password's
SHA-256 in the server's ACL file.

### Kafka: SASL/SCRAM without the password on the heap

The first client beyond databases. `seclume-kafka` holds a JAAS login module,
`SeclumeScramLoginModule`, that takes `username` and a secret provider's settings instead of
`password`, and a SCRAM-SHA-256/512 client that reads the secret into native memory for the
one step that needs it. Kafka's own module keeps the password as a `String` in the
configuration, a `String` in the JAAS subject and a `char[]` per login. It plugs in through
`javax.security.sasl` (a provider in front, stepping aside for logins it was not configured
for), so it compiles against no Kafka class.
- Shown against Kafka's `ScramSaslServer` in process, and against a Kafka 4.1 broker with
  kafka-clients 4.3.1: produce and consume with both mechanisms, a wrong password refused,
  the heap dump free of the password. With Kafka's own login module the same check finds it.
- SCRAM moved from the PostgreSQL driver into the core (`space.seclume.internal.Scram`),
  generic over the hash. It now encodes a user name as UTF-8 (it wrote each character's low
  byte, which PostgreSQL never noticed because it sends no name) and reports a server's
  `e=` error by its name.

### Constant-time crypto, and AES-GCM from the operating system

An outside review pointed at `Aes.java`: `SubBytes` looked up `SBOX[state byte]`, a table
indexed by secret data. That is the classic cache-timing channel against AES (Bernstein 2005;
Osvik, Shamir and Tromer 2006). The review was right, and the same pattern was in more places
than it named:
- **AES**: SubBytes and InvSubBytes, the key schedule's SubWord (indexed by the key itself),
  and `xtime`, which branched on the state's top bit;
- **Base64**: encoding the SCRAM client proof and decoding PEM keys went through tables;
- **RSA** (MySQL's password encryption): the multiplication skipped zero words, and the
  reduction branched on the bits of the value being reduced;
- **DPAPI hex decoding**: a branch per digit.

All of them are now arithmetic with masks and no branches or indexes on secret data:
- **The S-box is computed, not looked up.** It is the inverse in GF(2^8) (x^254 by an
  addition chain) and the affine map, evaluated bitsliced over all sixteen bytes of a block
  at once. `AesSubBytesTest` holds it to the table for all 256 inputs in both directions.
- **Base64** maps values to characters by range masks. `Base64OffTableFreeTest` checks every
  value and every byte, and an invalid character is no longer echoed in the error message
  (it may be part of a secret).
- **The RSA arithmetic** does the same work for every value: full rows, a carry stored
  rather than propagated in a loop, and an always-computed subtraction kept by a mask.

The price is speed. The constant-time Java AES is about seven times slower than the table
one: AES-GCM on 16 KB records went from 19 to 2.7 MB/s. That does not matter for Oracle's
login or the `encrypted` provider, which handle a few blocks. It matters for TLS records, so
those no longer use Java AES where there is a better one. **`AesGcmCipher`** takes OpenSSL's
EVP (Linux) or CNG (Windows), the libraries the TLS stack already needs for its key exchange.
They use AES-NI where the CPU has it, and they keep the key in their own key object, never
on the heap. Measured with CNG: **6.1 GB/s**, against 19 MB/s before. `AesGcmCipherTest` checks
that the native cipher agrees with the Java one byte for byte, across both key sizes and
lengths from 0 to 16 385 bytes, and matches NIST GCM test case 4. It also checks that a
flipped tag bit is refused with the output left zeroed. The same check ran against OpenSSL
3 on Linux (42 shapes). Elsewhere the constant-time Java version remains
(`-Dseclume.crypto.aesGcm=java` forces it).

### MySQL: `rewriteBatchedInserts`, and a fair batch benchmark

The README's biggest figure, 17.8 against 28.9 ms for a batch of 500 rows, compared seclume
with Connector/J's default. Connector/J sends a batch row by row by default and rewrites it
into multi-row inserts with `rewriteBatchedStatements=true`. With that set, it measured 5.4 ms
here, faster than seclume's 18. An outside review suspected this, and it was right.

Two changes:
- **`rewriteBatchedInserts=true`** does for seclume what Connector/J's setting does. A batch
  of a plain `INSERT ... VALUES (?, ...)` goes as multi-row inserts in blocks of up to 128
  rows. The rest is sent in powers of two, so a statement has at most eight shapes in the plan
  cache, and each shape's blocks are pipelined. It is off by default for the same reason as
  Connector/J's: a block succeeds or fails as a whole. The counts are 1 per row when a
  block's affected rows add up, and `SUCCESS_NO_INFO` when they do not. Anything the parser
  (`InsertBatch`) cannot take apart with certainty runs row by row:
  - `INSERT ... SELECT`, a `SET` form, a second tuple;
  - placeholders after the tuple;
  - a backslash or `#` comment, which MySQL reads differently from the generic scanner.
  `seclume-verify --migrate` now translates `rewriteBatchedStatements=true` into it.
- **`InsertBenchmark` measures both ways, with both drivers set alike** (`batching=default`
  and `batching=rewrite`). Without rewriting, seclume is ahead (17.9 against 29.1 ms). With
  it, neither is: every fork of either driver ran at about 5 or about 12 ms, a split that
  comes from the server. Both runs are in BENCHMARKS.md. The README table now shows only
  recorded rows; the LAN figures and the round-trip counts, which had no recorded run, are
  gone until they have one.

**Found on the way:** the first benchmark run of the new option failed at once. After a
rewritten batch the statement's parameters still held the last block's values, so the next
`addBatch()` took eight values instead of two. The tests had run one batch per statement.
The parameters are now cleared after a rewritten batch, and `LocalRewriteBatchTest` batches
the same statement three times.

### Longer fuzzing campaigns, and what the first one found

The coverage-guided targets had run for 30 to 60 seconds each. A 20-minute campaign per wire
decoder found one more defect within 80 seconds. **Oracle's chunked values** (LOBs and long
values in pieces) read a chunk length of up to 255 length bytes, unchecked. A length that came
out negative reached a memory copy as "size is negative". A chunk length now has at most four
bytes and must fit in what was received, otherwise the answer is refused as malformed. The
input is kept as a regression case.

The full campaigns (20 minutes each, about 25 million inputs in all) found three more:
- **SQL Server: a division by zero, and a loop of billions of steps.** A time scale off the
  wire above 18 made the tick divisor overflow to zero, and a `datetimeoffset` with a hostile
  length made the day correction step one day at a time over years of ticks. Scales above 7
  (SQL Server's finest) and time fields outside 3 to 5 bytes are now refused as malformed, and
  the day correction is one `floorDiv`.
- **Oracle: a session that never returned.** A sub-message whose length pointed backwards
  sent the answer walk round the same bytes for ever. The walk now requires every message to
  move forward, which catches this and any other parser that returns a position behind its
  start.
- **MySQL: a broken connection reported as usable.** An error packet whose SQLState was of
  class 08, the server saying the connection itself has failed, left the session open, and a
  pool would have handed it on. It now closes. PostgreSQL passed its 20 minutes (15.6 million
  inputs) without a finding.

To make hangs readable, the session contract now reports **where** the session was stuck: the
stack of the attempt, taken when the deadline passed. The Oracle hang was found with it. A
nightly job continues the search for 15 minutes per decoder.

### A code review, and what it found

A review of the uncommitted work, aimed at security and at doing what JDBC says, reported ten
findings. Each was checked against the code before anything changed. Nine were real:

- **SQL Server's default TLS checked no host name, and ignored `tlsRootCert` and `tlsPin`.**
  TDS 7.4 runs its handshake inside TDS packets and so cannot go through the path every other
  connection takes. It used the JVM's default context without endpoint identification: any
  certificate from a trusted CA passed, for any name. It now keeps the same trust as the
  rest. A `tlsPin` is the trust on its own and is compared after the handshake, even with
  `trustServerCertificate=true`. Otherwise the chain is checked against `tlsRootCert` (or the
  JVM's store) and the certificate has to name the host. `LocalTds74TrustTest` shows all three
  against the real server; before the fix, the wrong pin connected. **A connection to an
  address the certificate does not name is now refused**, as it should always have been.
- **Bearer tokens went to unauthenticated servers.** PostgreSQL's OAUTHBEARER over
  `tls=require`, and Azure SQL's FEDAUTH with `trustServerCertificate=true`. Both now require a
  checked certificate or a pin, and refuse with nothing sent. Proven for PostgreSQL 18 with
  the proof's new third case, and for SQL Server with `LocalAccessTokenTest`.
- **PostgreSQL accepted `AuthenticationOk` too early.** After SCRAM without the server's final
  message, the server never proved it knows the password, and channel binding was never
  checked. After Kerberos before the mutual-authentication reply, the server never proved it
  is the service. Both are refused now. A stub-server test covers SCRAM, and the Kerberos proof
  still logs in.
- **AES-GCM nonce reuse through `snapshot()`.** A copy kept for crash recovery stayed valid
  while the original went on writing. The copy's first record would then repeat a nonce under
  the same key: two ciphertexts on the wire that give away the XOR of their plaintexts and the
  authentication key. A connection with an outstanding copy now writes nothing, not even a
  `close_notify`, until `snapshotReleased()` says no copy can be thawed. The refusal is an
  `IOException`, so a driver closes quietly.
- **Releasing one secret unlocked another.** `munlock` and `MADV_DODUMP` work on whole pages and
  count nothing, so closing one secret put a neighbour on the same page back into swap and core
  dumps. Pages are now reference-counted (`MemoryLockPagesTest`).
- **The pool missed session state.** It missed SQL Server's `EXECUTE AS` and `SETUSER`, and any
  `SET` that was not the first statement of a batch ("select 1; set role admin"). The next
  borrower would have inherited rights or a tenant. Every statement of a batch is checked now.
- **A failed rewritten batch lost its counts.** MySQL batches, rewritten or not, now raise a
  `BatchUpdateException` with a count per row sent, `EXECUTE_FAILED` for the failed ones. The
  batch javadoc now says what really happens: the blocks pipelined with a failing one still
  ran, and the batch stops after them.
- **SQL Server recorded a long error twice** when a packet boundary cut its token after the
  text. The token is now recorded only once it is complete.
- **A double in a `real` bulk or TVP column** lost half its digits. `real` takes only a float
  now, and a column whose sample holds both is typed `float` (`int` and `bigint` likewise).

The tenth, SQL Server error 8152 no longer mapping to 22001, was deliberate. `ErrorCatalogTest`
aligned the states with mssql-jdbc, which reports `S000<state>` for it. The error number is
unchanged, and it is what Spring translates SQL Server errors by.

### Quarkus extension: `seclume-quarkus`

```properties
quarkus.datasource.db-kind=seclume-postgresql
quarkus.datasource.jdbc.url=jdbc:seclume:postgresql://db/app?user=app&provider=file&path=/run/secrets/db
```

Four datasource kinds for Agroal: `seclume-postgresql`, `seclume-mysql`,
`seclume-sqlserver` and `seclume-oracle`, with each driver and XA data source registered.
The secret goes in the URL, as a provider. **`quarkus.datasource.password` on a seclume
datasource fails the build** with the property's name and the alternative, because Agroal
would hold it as a `String` for as long as the application runs.

Tested with Quarkus 3.40 in JVM mode:
- one application with four named datasources, all four servers: each logs in (PostgreSQL
  by SCRAM), and a heap dump of the application afterwards holds none of the four passwords;
- the password property refused at build time.

A native build of a Quarkus application has not been run yet.

**Found on the way:**
- Quarkus runs no build step that produces nothing. The password check, written as a step of
  its own, was silently never executed, and Quarkus said so only at test time. It now runs
  inside the feature step.
- `QuarkusUnitTest` is deprecated for removal in 3.40; the tests use `QuarkusExtensionTest`.

### Semgrep and Trivy: the whole repository scanned, and kept scanned

**Semgrep** (1.177.0, rule sets `p/java`, `p/security-audit`, `p/secrets` and
`p/github-actions`) found 51 things on the first run:
- **41 GitHub Actions referenced by tag** (`actions/checkout@v4`), which a tag move can
  point at other code. Every action is now pinned to its commit SHA, with the version in a
  comment; Dependabot keeps both current.
- **3 `SSLContext.getInstance("TLS")`**. JDK 25 allows only TLS 1.2 and 1.3 there anyway, but
  that is the JDK's default, and a deployment can loosen it. The contexts are now `TLSv1.3`,
  and every engine enables TLS 1.3 and 1.2 explicitly (SQL Server's TDS 7.4 keeps its 1.2).
- **7 accepted on purpose**, each marked in the source with the reason on the line above:
  - the trust-everything manager behind `trustServerCertificate=true`, which is opt-in and
    reported as unsafe by `seclume-verify --migrate`;
  - the application's own statement passed to `sp_describe_undeclared_parameters` as an
    `N'...'` literal with its quotes doubled (T-SQL has no other escape);
  - plain HTTP to a Patroni endpoint configured as `http` (`https` is verified);
  - the loopback servers of the benchmark and the test kit.

A second run finds nothing.

**Trivy** (0.74.0) against a CycloneDX SBOM of the whole build, test and benchmark
dependencies included (57 components; the drivers themselves have none beyond the JDK),
found two HIGH advisories in `micrometer-core` 1.15.4: CVE-2026-40983 and CVE-2026-40984,
denial of service through Micrometer's gRPC and Jetty instrumentation. The starter uses
neither, and Micrometer is an optional dependency that an application brings in its own
version, but the build now declares 1.16.7. A second run finds nothing.

Both run in CI from now on (`security.yml`: on push, pull request and weekly), and fail on
any Semgrep finding or on a HIGH or CRITICAL advisory. **Dependabot** watches Maven and the
Actions weekly.

### Benchmark regressions are flagged; CodeQL and Scorecard

The nightly benchmark job used to keep its numbers and compare nothing. A
threshold on absolute times would fail on every slow runner, so it compares
**ratios**: seclume's time over the vendor driver's, both measured in the same
run on the same runner (`BenchRegression`, baseline in
`seclume-bench/baseline.properties`, from the run recorded in BENCHMARKS.md).
The job fails when
- a ratio is more than 15 % worse than the baseline, or
- a clear lead (more than 5 %) turns into a tie or a loss, since a "faster
  than" in the README would then be false.

A pair the run did not measure is reported, not failed; a new pair is listed.
`BenchRegressionTest` covers the four cases, including a runner 60 % slower
across the board, which must not fail.

Two workflows join CI: **CodeQL** (security-and-quality queries, built with
the project's own Maven build) on pushes, pull requests and weekly, and
**OpenSSF Scorecard** weekly. Both run only once pushed; neither has run yet.


The README now starts with what seclume is for: heap dumps without database
credentials. The drivers are the means. It shows the claim with a run anyone
can repeat: the same application against PostgreSQL and a Vault dev server,
once with pgjdbc (Vault answer as a `String`) and once with seclume, then
`seclume-heapcheck` on both JVMs:
- **pgjdbc:** the database password and the Vault token are both found in the
  heap, after the application dropped its references and asked for a GC;
- **seclume:** neither is found.

The script makes the password and the token for the run and shreds them after
it; the recorded output is in the README and in `demo/heap-dump/README.md`.

### Azure SQL token login (`FEDAUTH`)

```
jdbc:seclume:sqlserver://srv.database.windows.net/app?authentication=token
    &provider=azure-managed-identity&resource=https://database.windows.net/
```

`authentication=token` makes the secret an Entra access token. The pre-login
announces it (FEDAUTHREQUIRED), and LOGIN7 carries no user and no password
but a feature list with FEDAUTH: the security-token library, the server's echo
bit, the token in UTF-16LE (converted from the provider's scope straight into
the send buffer), and the server's nonce if it sent one. mssql-jdbc's
`ActiveDirectoryManagedIdentity`/`ActiveDirectoryMSI` are accepted as names for
the same thing.

**Checked against:** SQL Server 2022 without Entra, which parses the login
and refuses it as a login (18456, 28000) rather than as a broken packet
(`LocalAccessTokenTest`). **Not yet run against a live Azure SQL.**

### PostgreSQL 18 OAuth login (`OAUTHBEARER`)

```
jdbc:seclume:postgresql://db.example/app?user=alice&tls=verify-full&provider=gcp-metadata
```

With `oauth` in `pg_hba.conf`, PostgreSQL 18 offers the SASL mechanism
`OAUTHBEARER` (RFC 7628) instead of SCRAM. The driver answers with
`n,,^Aauth=Bearer <token>^A^A`, the token being whatever the secret provider
returns: a managed identity's, the metadata server's, a file's. It goes from
the provider's scope into the send buffer like a password. There is no device
flow and no browser: a server-side application has its token already.
- **Only to a server that proved who it is.** A bearer token works for
  whoever reads it, and nothing in it is bound to the connection, so the
  driver sends it only with `tls=verify-full` or a `tlsPin`. `tls=require`
  encrypts but would hand it to anybody in the middle, so the driver refuses
  before it reads the token. The proof shows that as a third case.
- **A refused token** gets the server's JSON reason, the one-byte
  acknowledgement RFC 7628 asks for, and then the server's own error.

Shown against PostgreSQL 18 in a container, script in
`seclume-postgresql/proof/oauth.sh`. PostgreSQL ships no validator, so the proof
builds a twenty-line one (`tokenval.c`) that accepts the token in one file:
- **the accepted token:** `logged in as alice (oauth:alice) by oauthbearer`;
- **the control**, another token: "OAuth bearer authentication failed".

A stub-server unit test shows the refusal without TLS, with nothing sent.

### Kerberos for MariaDB (`auth_gssapi`)

```
jdbc:seclume:mariadb://db.example/app?user=alice&provider=none
```

The same library and the same ticket as for PostgreSQL. A user created
`IDENTIFIED VIA gssapi` makes the server switch the login to
`auth_gssapi_client` and name its principal
(`mariadb/db.example@EXAMPLE.COM`); the driver asks GSSAPI for that principal's
tokens and exchanges them as plain packets until the context stands. `Secured`
reports `auth_gssapi_client`. With the Spring starter, `secret.provider:
integrated` now means this for MariaDB and MySQL URLs too.

Shown in `seclume-mysql/proof` like the PostgreSQL one - a KDC, MariaDB 11.4
with the plugin, a JDK 25 client:
- **with a ticket:** `logged in as alice@% by auth_gssapi_client`;
- **the control** without a ticket: refused as a login failure (28000), with
  "No Kerberos credentials available".

A unit test covers the switch against a stub server: without a ticket, or on a
machine without the library, the refusal is 28000 and names Kerberos.

### Kerberos for PostgreSQL: a login with no secret in the process

```
jdbc:seclume:postgresql://db.example/app?user=alice&provider=none
```

This was always the answer the README gave to "where should the password
come from": nowhere. The ticket is the operating system's, in the credential
cache that `kinit`, a keytab or the machine's login filled. When the server
asks for GSSAPI (`gss` in `pg_hba.conf`), the driver asks the system's MIT
GSSAPI library, through FFM (`Gssapi`), to turn that ticket into the tokens
for `postgres@<host>`, and passes them on. No key is ever in Java memory; the
tokens are protocol data. `Secured` reports the method as `gss`.

Linux, 64-bit, with `libgssapi_krb5.so.2`. On Windows, SSPI would be the
library, and it is not supported yet; neither are SQL Server Integrated
Security and Oracle's Kerberos. A server asking for those is refused with a
message naming what does work.

Shown with a KDC (realm `SECLUME.TEST`), PostgreSQL 16 and a JDK 25 client in
containers, script in `seclume-postgresql/proof` (the realm, its master
password and the keytabs are made for the run and shredded after it):
- **with a ticket** from alice's keytab: `logged in as alice by gss`, with no
  password anywhere;
- **the control**, the same client without a ticket: refused, with the
  library's own words, "No Kerberos credentials available".

**Found on the way:** the database container could not read its keytab and
said "Key table entry not found". The cause was SELinux: `:Z` gives a mounted
directory to one container, and the next container's `:Z` took it away. The
script mounts with `:z`.

### Post-quantum key exchange: X25519MLKEM768

"Harvest now, decrypt later" is the case where encrypted traffic is recorded
today and read once a quantum computer exists. A database connection carries
exactly the kind of data that is still worth reading in ten years. seclume's
own TLS stack now offers the hybrid group X25519MLKEM768 (0x11EC): ML-KEM-768
and X25519 together, so the session keys hold as long as either of the two
does.
- **Where it runs:** through OpenSSL 3.5 or later, like P-256. The private
  keys belong to OpenSSL, and the 64-byte shared secret goes into native
  memory (`HybridMlKem`).
- **Fallback:** P-256 is offered beside it. The stack does no
  HelloRetryRequest, so both shares go in the first flight, and a server
  without the hybrid simply picks P-256.
- **Where it does not run:** Windows' CNG has no ML-KEM in the versions
  tested here, and there, as on an older Linux, the ClientHello is exactly as
  before. `-Dseclume.tls.postQuantum=false` switches the hybrid off.
- The connection's description names the group:
  `TLS_AES_256_GCM_SHA384 with X25519MLKEM768`.

Shown against OpenSSL 3.5.8 `s_server` in an Alpine container, script in
`seclume-core/proof`:
- a server offering only the hybrid: the handshake completes with it, through
  the verified Finished, so both sides derived the same secret;
- a server offering only P-256: the client falls back at once;
- **the control:** the hybrid-only server with the hybrid switched off refuses
  with `handshake_failure`, so the first run really used ML-KEM.

**Found on the way:** the native-image check reads downcalls written as
`bind("name", ...)`. Written with the library as the first argument, the new
ones slipped past it, and a native image would have failed at run time. They
are in the recognised form now, and the one new signature is registered.

### The secret classes for other libraries: SECRETS-API.md

What keeps the database password off the heap serves any Java code that holds
a secret. `SECRETS-API.md` shows library authors the pattern: read, use and
wipe the secret in native memory with `SecretProviders`, `SecretScope` and the
`MemorySegment` cryptography. It also names the classes that follow semantic
versioning from 1.0. New for this purpose is `SecretProviders.fromUri("file:/run/secrets/key")`,
the one-line form the Spring starter already had, now in the core. The starter
uses it too, so there is one parser. `LibraryUseTest` is the page's example
run for real: a webhook is signed with an HMAC key that is then searched for
in a heap dump and not found, and the control shows that the same key held as a
String is found.

### Patroni: ask the cluster where its leader is

```
jdbc:seclume:postgresql://db1,db2,db3/app?targetServerType=primary
    &patroni=http://db1:8008,http://db2:8008,http://db3:8008
```

After a switchover a host list learns where the new leader is by trying each
server in turn, and DNS or a load balancer by noticing eventually. With
`patroni=`, the driver asks the cluster's REST API first:
- `GET /cluster` on the first endpoint that answers lists the members and their
  roles;
- for that attempt they replace the URL's hosts, the leader first for
  `primary` and the replicas first for `secondary`, with stopped members left
  out;
- the answer is kept for a second, so a burst of new connections asks once;
- when no endpoint answers, the URL's hosts are used as before;
- the server's own answer to "what are you" is still checked after
  connecting.

The request is plain HTTP, or HTTPS through the JDK's TLS with the host name
checked. It goes through the same code path for all four drivers, and so it is
useful to anything Patroni manages.

`PatroniTopologyTest` reads an answer in the shape Patroni documents, checks
the ordering and the cache, and skips an endpoint that is down.
`PatroniFailoverTest` covers a URL that names only a server that is gone, with
a stand-in answering `/cluster`: the connection reaches the leader it reports,
and without the option it fails. That stand-in is the one limit of the
evidence: it answers in the documented format, but it is not a running Patroni
cluster.

### Testcontainers `@ServiceConnection` and Docker Compose

Both are how a test or development database is wired in Spring Boot today, and
both hand over a `JdbcConnectionDetails`: the container's vendor URL, user and
password. The starter now takes that when no `seclume.datasources` is
configured:
- it translates the URL (`jdbc:postgresql:`, `jdbc:mysql:`, `jdbc:mariadb:`,
  `jdbc:sqlserver:`, `jdbc:oracle:thin:@`) into seclume's;
- it adds what the containers need: a public key over an unencrypted MySQL
  connection, and trust in a SQL Server container's self-signed certificate;
- the result becomes the application's pool.

The password arrives as a String, which is how the containers report it, and
the log says plainly that this path is for tests and development. A production
configuration names a secret provider, and there this does nothing.
`ConnectionDetailsTest` covers the translation of each container's URL, and a
Spring context whose connection details point at the test PostgreSQL, logging
in through the resulting pool.

### Checkpoint and restore: `seclume-crac`

```java
SeclumeCrac.register(pool);
```

CRaC and AWS Lambda SnapStart write the whole process to disk, and they refuse
to while a socket is open. A pool full of connections therefore made the
checkpoint fail outright. Behind that was the next gap after the heap dump:
an image holds every session's keys. The new module `seclume-crac` (on the
`org.crac` API, so the drivers and the pool keep their no-dependency promise)
registers a pool:
- before the checkpoint the pool gives up every connection with the new
  `SeclumePool.suspend()`: idle ones at once, borrowed ones on return, and
  housekeeping opens none;
- after the restore `resume()` lets it fill again, from new logins, with the
  secret fetched anew from its provider.

Shown in a CRaC JDK (`azul/zulu-openjdk:25-jdk-crac`) against a throwaway
PostgreSQL, script in `seclume-crac/proof`:
- **registered:** the checkpoint is taken, the restore queries over a new
  login, and the image holds the password **0 times**;
- **control 1:** the same run with the password held as a String on purpose,
  where the search finds it (2 matches), so the 0 means something;
- **control 2:** the pool not registered, where CRaC refuses the checkpoint
  with `CheckpointOpenSocketException` for both pooled sockets.

`SuspendTest` covers the pool side without a container.

### Coverage-guided fuzzing, and what it found at once

The fuzzing so far was corpus-based: prepared broken frames, replayed. Now
Jazzer searches as well, guided by the code an input reaches. It starts with
the parsers that read every statement an application hands in, where an
exception is an outage rather than a bad input:
- `QueryFingerprint`;
- the placeholder scanner;
- `SessionState`;
- the IN-list rewrite.

An ordinary build replays the saved inputs; `JAZZER_FUZZ=1 mvn test
-Dtest=TextParsersFuzzTest#<target>` searches (30 s per target, some 20 000 to
90 000 inputs a second).

**Found in the first twenty seconds:** the IN-list rewrite took an `in` at the
end of a comment for the operator. On PostgreSQL, `-- in` on the line before
`(?)` turned the placeholder into comment text, and the statement lost its
parameter. The search for `in` now skips comments and strings in both
directions, and a comment between `in` and the bracket is still allowed. The
input that found it stays in the corpus as a regression case, and
`InListsTest` states both cases in words.

**Then the wire.** Each driver's decoder test got a Jazzer target that feeds a
hostile server's answer to a session and holds it to the existing contract:
- a `SQLException` or `IOException` with a message, and nothing else;
- no hang;
- no `OutOfMemoryError`;
- a session that knows whether it is still usable.

The same goes for seclume's TLS client handshake, where everything a server
can send before any key exists was covered (`ServerHelloFuzzTest`). The
corpus-based sweeps had passed all of these. Coverage-guided search found four
more within seconds, each now a regression input:
- **SQL Server: a hang.** A negative length in a FEATUREEXTACK entry walked the
  reading position backwards, and the decoder looped for ever, which in a pool
  is a connection that never comes back.
- **Oracle: `Illegal Capacity`.** A column count off the wire reached an
  `ArrayList` constructor unchecked. It is now bounded by Oracle's own limit of
  4096.
- **Oracle: `NegativeArraySizeException`.** An eight-byte bit-vector length was
  cast to `int`. It is now bounded by the buffer the answer is in.
- **Oracle: an `IllegalStateException`** for a list of batch errors the driver
  does not read. It is now the same broken-connection `SQLException` as any
  other unreadable answer.

All four now end in a `SQLNonTransientConnectionException` that says what was
wrong. `WireBuffer.malformed(...)` is the one way to say so. After the fixes,
PostgreSQL, MySQL, SQL Server and Oracle each ran 60 s (130 000 to 1 100 000
inputs) without a finding, and so did the TLS handshake.

### Release hygiene: an API check against 0.9.0, and an SBOM

- **`mvn -Papicheck verify`** compares every module's jar with the released
  0.9.0 (japicmp) and writes `target/japicmp/`. The internal packages and the
  protocol layers under the JDBC classes are left out: they are exported only
  for the session-moving transport, not for applications. Before 1.0 it reports
  rather than fails.
  - **Found on its first run:** two binary breaks nobody had decided on,
    `Observed.failover(String, String, String)` and the eleven-argument
    `PoolStatistics` constructor. Both are back, delegating to their
    replacements, and the check now reports no incompatible change in any of
    the 13 modules.
- **`mvn -Prelease package`** writes a CycloneDX 1.6 SBOM per module
  (`target/bom.json`). It states the dependency promise in a form a
  procurement check can read: `seclume-core` lists **no** runtime component at
  all, and `seclume-pool` lists only `seclume-core`.

### Oracle: `tnsnames.ora` aliases

```
jdbc:seclume:oracle:tns:ORDERS?user=app&provider=file&path=...&tnsAdmin=/etc/oracle
```

This is how Oracle connections are configured in practice. The alias is looked
up in `tnsnames.ora`, in the directory named by `tnsAdmin`,
`-Doracle.net.tns_admin` or `TNS_ADMIN`, in that order. Its descriptor becomes
the URL the driver already understands:
- every `ADDRESS` (also inside an `ADDRESS_LIST`) becomes a host of the list;
- `SERVICE_NAME` becomes the service;
- `PROTOCOL=TCPS` switches on `verify-full` unless the URL says otherwise.

The file is read as Oracle writes it: comments, several aliases for one entry,
descriptors over many lines. What a descriptor can say beyond that is refused
by name rather than silently ignored: a `SID`, `FAILOVER_MODE`,
`SOURCE_ROUTE`, a protocol other than TCP/TCPS. `seclume-verify --migrate`
translates `jdbc:oracle:thin:@ORDERS` into the `tns:` form. `TnsNamesTest`
covers the parsing, the rewriting, and a real login through an alias against
the test server. Native Network Encryption is still not supported.

### A primary and a read replica as one data source: `ReadWriteSplit`

```java
DataSource both = new ReadWriteSplit(primaryPool, replicaPool)
        .readYourWrites(Duration.ofMillis(500));
```

Every Spring application with a replica builds this by hand, out of an
`AbstractRoutingDataSource` and a `LazyConnectionDataSourceProxy`. A connection
from `ReadWriteSplit` chooses when its first statement runs:
- read-only goes to the replica, everything else to the primary. Spring's
  `@Transactional(readOnly = true)` sets read-only after taking the
  connection, so it is known by then;
- a connection taken and given back without a statement opens nothing.

**Read your writes**, for PostgreSQL and MySQL:
- when a writing connection commits or is given back in auto-commit, the
  primary's log position is noted;
- a replica connection first waits until it has replayed that far, up to the
  limit;
- after that the read goes to the primary rather than returning data without
  the caller's own write;
- on MySQL (GTID mode on) the primary's executed GTID set is noted, and the
  replica waits with one `WAIT_FOR_EXECUTED_GTID_SET` call: the server does the
  waiting;
- on other databases the setting is refused, not ignored.

In Spring it is three properties, and the application's `DataSource` is then
the split:

```properties
seclume.read-write-split.primary=main
seclume.read-write-split.replica=reporting
seclume.read-write-split.read-your-writes=500ms
```

`ReadWriteSplitTest` ran against a real PostgreSQL 16 primary and its streaming
replica, in containers set up for the run and removed afterwards. Replay on the
replica was paused where a test needed it behind, so "not yet replicated" is
certain rather than a race. It covers:
- the routing, including Spring's call order;
- the control: without read-your-writes, the own write is missing on the
  replica;
- the fallback to the primary while the replica stands still;
- the wait while it catches up;
- a committed transaction being noted like an auto-commit write.

`ReadWriteSplitMySqlTest` does the same against a MySQL 8.4 primary and its GTID
replica in containers. The replica's applier is stopped where a test needs it
behind: the control, the fallback, and the wait. (Setting it up taught one
thing worth writing down: the database and the user must come to the replica by
replication. Created there too, the replica stops with error 1396.)

### `tlsRootCert=aws-rds`: the RDS CA bundle ships with the driver

The usual answer to "PKIX path building failed" against RDS is to switch the
check off. `tlsRootCert=aws-rds` verifies against Amazon RDS's global bundle
instead: 108 certificates covering every region's roots and intermediates,
taken from `truststore.pki.rds.amazonaws.com` on 25.09.2026 and bundled in
`seclume-core`, including for the native image. Azure Database chains to a
root the JVM already trusts, and Cloud SQL has a CA per instance, so neither
gets a bundle. `AwsRdsBundleTest` checks that every entry is an Amazon CA and
that nearly all of them are valid today, which is the check that fails when
the bundle needs refreshing.

### MySQL `LOAD DATA LOCAL`, without handing the server a file

```java
MyConnection my = connection.unwrap(MyConnection.class);
long rows = my.loadData("load data local infile 'orders.csv' into table orders "
        + "fields terminated by ','", csvStream);
```

The driver deliberately never offered LOCAL INFILE. With that capability a
server may ask the client for any file, and a malicious or taken-over one reads
`/etc/passwd` out of the application container. That stays the default.
`loadDataLocal=true` (URL, or `setLoadDataLocal` on the data source) offers it,
and even then **no file is ever opened by the name the server sends**:
- during `loadData` the server gets the caller's stream, whatever file name the
  statement mentions;
- at any other time it gets an empty file.

A stream that fails to read closes the connection, so the server rolls the
statement back. An empty packet would have ended the file, and the server
would have kept the rows sent so far.

100 000 rows load in 398 ms. `LocalLoadDataTest` needs `local_infile=ON` on the
server and skips itself otherwise; it was run against the test server with the
setting switched on for the run and back off afterwards. It covers:
- a statement naming `/etc/passwd` loads the stream;
- a plain LOAD DATA LOCAL naming an existing file loads nothing;
- without the option, the load is refused;
- a stream that breaks leaves no rows behind.

### SQL Server table-valued parameters

```java
statement = connection.prepareStatement("insert into lines select * from ?");
statement.setObject(1, TableValue.of("dbo.order_lines", rows));
```

A `TableValue` is a whole table in one parameter, for a user-defined table type:
in a statement's `from`, beside other parameters, or as a procedure's
`readonly` argument. 10 000 rows of ten types arrive in about 100 ms.
- **Types:** each column's type comes from its first non-null value, and the
  server converts it into the table type's column (text into `varchar`, a wide
  decimal into `decimal(12,2)`). The type's own constraints still hold.
- **Checked before sending:** the type name must be `type` or `schema.type`,
  plain or in brackets, because it stands in the declaration; rows of different
  widths and a value that does not fit its column are refused.
- **No rows** is an empty table. The server takes that only as the parameter's
  default, so it goes that way.

### SQL Server bulk load: `INSERT BULK`

```java
TdsConnection sql = connection.unwrap(TdsConnection.class);
long loaded = sql.bulkInsert("dbo.orders", new String[] {"id", "label", "total"}, rows);
```

This is the path `bcp` and SSIS use: one bulk-load message carries the column
description and every row, streamed a packet at a time. 100 000 rows of nine
types (int, nvarchar, varchar, decimal, date, datetime2, uniqueidentifier, bit,
varbinary, with NULLs) load in 526 ms against the test server.
- **Types:** each column's type comes from its first non-null value among the
  first thousand rows. Text goes as `nvarchar` and the server converts it into
  a `varchar` column, so no code page is guessed here.
- **A row that does not fit** is refused before a byte of it is sent. The load
  is then cancelled, and nothing of it remains.
- **Unlike `bcp`'s default, check constraints and foreign keys are checked and
  triggers fire.** A bulk load here means what an insert would, only faster.

**Found on the way:**
- A NOT NULL target column has to be described as not nullable, or the server
  answers "Invalid column type from bcp client". The driver reads the target
  columns' nullability first.
- A setting waiting to ride along must go out on its own, because "Insert bulk
  cannot be used in a multi-statement batch".

`LocalBulkInsertTest` covers:
- the 100 000 rows, each value read back exactly;
- a violated check constraint (error 547, nothing loaded);
- a row that does not fit at row 1200 (nothing loaded);
- a rollback taking the load with it.

### PostgreSQL `COPY`: bulk import and export

```java
PgConnection pg = connection.unwrap(PgConnection.class);
long rows = pg.copyIn("copy orders (id, total) from stdin (format csv)", csvStream);
pg.copyOut("copy (select * from orders) to stdout (format csv)", fileStream);
```

The driver knew no CopyIn/CopyData handling at all, and COPY is the import
path: 100 000 CSV rows in 185 ms against the test server.
- **In:** the input is streamed in 64 KB CopyData messages and never held
  whole. A failure reading the caller's stream goes to the server as CopyFail,
  so nothing is copied, and the caller gets the reading failure.
- **Out:** a failure writing to the sink does not stop the reading, because
  the rest of the answer is still on the wire and the session has to get past
  it. The failure is reported at the end.
- **The wrong direction**, a `COPY ... FROM` given to `copyOut`, is named
  rather than hung on.

`LocalCopyTest` covers:
- 100 000 rows with commas, quotes and umlauts, in and out;
- a rollback taking the copied rows with it;
- a failing input stream, a failing sink, and bad data (`22P02`), each
  followed by a check that the connection still works.

### PostgreSQL behind PgBouncer and RDS Proxy: `proxyMode=transaction`

Measured behind PgBouncer 1.25 in transaction mode, with one server connection
for all clients:
- **Prepared statements work** across clients sharing a server session.
  PgBouncer 1.21 and later track protocol-level named statements (with
  `max_prepared_statements` set), and seclume's `seclume_N` plans pass through.
- **`setReadOnly` and `setTransactionIsolation` leaked.** Both went to the
  server as `SET SESSION CHARACTERISTICS`, and the session belongs to another
  client for the next transaction. After `setReadOnly(true)` on one connection,
  the next client's session answered `transaction_read_only = on`, and an
  isolation level travelled the same way.

With `proxyMode=transaction` (URL, or `setProxyMode` on the data source) neither is
ever set on the session. They travel in the transaction's own opening,
`BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY`, which the driver sends with the
first statement anyway, so this costs no round trip. In auto-commit mode they are
hints, as JDBC allows, because there is no transaction of one's own to carry
them. `SessionContext` is refused in this mode with the reason.

`PgBouncerTest` runs against a real PgBouncer with `default_pool_size = 1`:
- prepared statements from three clients, interleaved;
- the control, which shows the leak without `proxyMode`;
- with `proxyMode`, read-only and serializable inside the client's own
  transaction, and read-write and read committed for the next client.

A new CI job, `pgbouncer`, runs it on every push.

### MIGRATING.md: the errors that go away

A page for the move from HikariCP, pgjdbc, Connector/J, mssql-jdbc and ojdbc. It
lists the exact error texts people search for (`column is of type jsonb but
expression is of type character varying`, `cached plan must not change result
type`, `ORA-01795`, the 2100-parameter limit, `Communications link failure`,
`ORA-01000`, `PKIX path building failed`), what happens instead, and the test
that shows it. The silent failures and what is only warned about have tables of
their own, and so does what still fails. Two of those claims had no test of their
own until now and have one: `PgjdbcErrorsTest` (a `setString` into `jsonb` and
`uuid`, and a prepared statement surviving an `ALTER TABLE` under it).

### `seclume-verify --migrate`: an existing configuration, translated

```
java -jar seclume-verify.jar --migrate application.properties
java -jar seclume-verify.jar --migrate "jdbc:postgresql://db/app?sslmode=require"
```

The tool reads pgjdbc, MySQL Connector/J, MariaDB, mssql-jdbc and Oracle thin URLs,
HikariCP's settings and Spring's `spring.datasource.*`, plus every other property
that holds a JDBC URL, each becoming a data source of its own. It prints the
`seclume.datasources.*` properties that mean the same, and names every unsafe
setting it found:
- `sslmode=prefer`/`require`, and a missing `sslmode`;
- `useSSL=false`;
- `trustServerCertificate=true`;
- `NonValidatingFactory`;
- `allowPublicKeyRetrieval=true` without required TLS;
- a password in the file, in the URL or elsewhere (`spring.mail.password`).

Settings with no equivalent are listed as such, and the ones seclume does on its
own (`rewriteBatchedStatements`, `cachePrepStmts`, `sendStringParametersAsUnicode`,
`connection-test-query`) are dropped with the reason. **Password values are never
read**: a property holding one is dropped as the file is loaded and noted by
name, and the translation points at a secret provider instead. Exit code 1
means unsafe settings were found, so it fits a build step. `MigrateTest`
includes the check that every translated URL is accepted by the seclume
drivers.

### The tenant on every borrow: `SessionContext`

The reset on return (below) stops a tenant from leaking to the next borrower.
The other half is setting it reliably in the first place. Row-level security
is usually wired with a statement the application writes itself, and that
statement is forgotten on one code path. Now the pool does it: with
`PoolSettings.setSessionContext(supplier)`, or in Spring a
`SeclumeSessionContext` bean, every borrow asks for the context of the moment
(`Map.of("app.tenant_id", "42")`) and hands it to the connection through the
new `space.seclume.SessionContext`:

| | kept as | read by a policy with | costs |
|---|---|---|---|
| PostgreSQL | `set_config(..., false)` | `current_setting('app.tenant_id')` | nothing: rides with the first statement |
| MySQL | a user variable | `@app_tenant_id` | nothing: rides with the first statement |
| SQL Server | `sp_set_session_context` | `SESSION_CONTEXT(N'app.tenant_id')` | nothing before a plain statement, one round trip before a prepared one |
| Oracle | `client_identifier` only | `SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER')` | one round trip |

A value never enters a statement unquoted in a way a server setting could
change: PostgreSQL takes it dollar-quoted, MySQL as a UTF-8 hex literal, and
SQL Server as `N''` (T-SQL has no escape character). Names are letters, digits,
underscores and dots. A connection that cannot take the context is not handed
out, because a request that runs without the tenant it expected is exactly the
failure this is for. Oracle's other application contexts live in a namespace a
DBA creates and only its own package may set, and are refused with that
explanation.

`SessionContextTest` on all four, with one connection in the pool so that
every borrow is the same session:
- the tenant arrives;
- a borrower without one sees nothing;
- a value with `'`, `$seclume$`, `"`, `\` and an umlaut arrives exactly;
- on PostgreSQL and MySQL the query with the context costs exactly one round
  trip.

**Found on the way, both leaks of exactly the kind this is for, and both proved
by switching the fix off:**
- A connection borrowed with a tenant and returned **unused** was never reset,
  because nothing had run on it. The context still waiting to be sent then
  went out with the next borrower's first statement. Now a borrow with a
  context counts as used.
- On SQL Server a context still waiting at the reset rode along with the next
  request, which the RESETCONNECTION bit resets *before* running, so it set
  the old tenant for the new borrower. The same would have happened on MySQL
  after `COM_RESET_CONNECTION`. A reset now drops a context not yet sent.

### SQL Server: `varchar` parameters where the column is `varchar`

The best-known performance trap of Java against SQL Server: every driver sends
text as `nvarchar`, `nvarchar` ranks above `varchar`, and so a `varchar` column
compared with the parameter is converted row by row. Under a SQL collation
that turns an index seek into a scan; the published cases go from seconds to
minutes. The vendor driver's answer is one global switch,
`sendStringParametersAsUnicode=false`, which is wrong for every `nvarchar`
column in the same application.

Now it is decided per parameter. Once per statement text and process, outside
any transaction, `sp_describe_undeclared_parameters` is asked which text
parameters the server would declare `varchar`: those compared with, or written
to, a `varchar` column. Those parameters go as `varchar` **when the value is
plain ASCII**, which is the same byte in every code page SQL Server has, so no
collation can make it mean something else. Anything else stays `nvarchar`, as
before. A statement the server cannot describe keeps `nvarchar` and is not
asked about again. Inside a transaction nothing is asked, because with
`XACT_ABORT ON` a failed question would roll back the caller's work.
`varcharParameters=off` (URL, or `setVarcharParameters` on the data source)
restores `nvarchar` for everything.

`VarcharParametersTest` reads the plan the server cached. With the feature, the
plan shows an index seek with no `CONVERT_IMPLICIT`. The control, the same
statement with `varcharParameters=off`, shows the conversion. The column's
collation still decides (`'ABC'` finds `'abc'`), non-ASCII text still finds its
row, and a statement inside a transaction runs as before.

### A whole list in one placeholder: `where id in (?)`

`setObject(i, List.of(...))` (or an object array) on a placeholder that
stands alone in an `in (...)` binds the whole list as **one value**. Before,
every list length was a statement of its own: its own plan on the server, its
own entry in every cache, and a limit at the end, with SQL Server's 2100
parameters and Oracle's `ORA-01795` at 1000 entries. Now the statement text no
longer depends on the length:

| | `x in (?)` with a list of numbers becomes |
|---|---|
| PostgreSQL | `x = any(cast(? as bigint[]))` |
| MySQL | `x in (select v from json_table(?, '$[*]' columns (v bigint path '$')) as seclume_in)` |
| SQL Server | `x in (select v from openjson(?) with (v bigint '$'))` |
| Oracle | `x in (select v from json_table(?, '$[*]' columns (v number path '$')))` |

The elements decide the type: whole numbers, decimals (declared with the
precision and scale the values need), strings and UUIDs. `not in (?)` works,
and so does the empty list: `in` matches nothing and `not in` everything,
which a literal `in ()` cannot even express. Refused, each with its own
message: a null element (`not in` with a null matches no row, silently), mixed
element types, a list on any other placeholder, and a list in a batch.

`InListTest` on all four servers: every element type, a string with `"`, `'`,
`\`, a comma, braces and an umlaut, `not in`, the empty list, **5000
elements**, and one statement run with lists of three lengths, which on
PostgreSQL leaves exactly one server-side plan. `InListsTest` for the text:
placeholders in comments and strings, `min(?)`, `in (?, 2)`.

**Found on the way:** MySQL's `json_table` gives a typed string column the
connection's collation, which clashes with the compared column's ("Illegal
mix of collations"). Strings therefore go through `json_unquote`, which is
coercible like a parameter and so takes on the column's collation:
`'A' in ('a')` stays true under a case-insensitive collation.

### Shutting down in order: borrowed connections get to finish

`SeclumePool.close()` closed every connection at once, borrowed ones included.
On SIGTERM that cut a scheduled job or a message listener off mid-transaction,
which meant a rollback and an error in the log, or, with a commit in flight, an
outcome nobody knows. Now closing happens in order. Nothing new is lent, and a
borrower waiting for a connection is told the pool is closed at once instead of
at its timeout. Idle connections go immediately. Borrowed ones are closed as
they come back, and only those still out after `shutdownTimeout` are cut and
counted in the log. The default is 10 s, inside the 30 s a container platform
usually allows between SIGTERM and SIGKILL (`seclume.datasources.<name>.pool.shutdown-timeout`,
0 for the old behaviour). `close(Duration)` takes it per call. A handle whose
connection was cut reports `isClosed()`. `ShutdownDrainTest`.

**Found on the way:** a borrower waiting in `getConnection` while the pool
closed could take the permit a retired connection gave back and **open a new
connection in the closed pool**, which nothing would ever close. The wait now
checks for the close, and a connection opened across it is closed at once. The
test proves no connection is opened while closing.

**Also:** `credential-spread` was documented as a starter property and was not
one; `seclume.datasources.<name>.pool.credential-spread` now exists.

### Idle connections kept alive below the server's idle limit

A pool keeps connections idle by design, and a server with an idle limit closes
them by design: MySQL after `wait_timeout`, PostgreSQL after
`idle_session_timeout`, Oracle after a profile's `IDLE_TIME`. The next borrower
then got a connection the server had already closed. The usual remedy is a
keepalive set by hand below the limit, in a second place, and remembered when
the limit changes. The four connections now offer `space.seclume.ServerIdleLimit`
(SQL Server has none and says so), the pool reads it at its first connection,
and when its own `keepaliveTime` is off or longer it keeps idle connections
alive at three quarters of the limit, saying so once in the log.
`IdleLimitTest`: a session limited to 6 s, left idle for 14 s, is still the
same connection; the control, the same session without the pool, is closed by
the server; and with the derivation switched off the pool test fails.

**Found on the way:** the keepalive was measured from the connection's return,
not from the last keepalive, so once an idle connection passed
`keepaliveTime` it was pinged in every housekeeping round, every few seconds.

### The `transport` option, per connection

`Transports` has always said a transport can be chosen by the system property
`seclume.transport` **or the URL option of the same name per connection**. No
driver read the option: `...?transport=x` quietly got a socket, and the only
choice was the property - for every connection in the process at once. Now all
four read it, through the driver and through the data source (`setUrl`, or
`setTransport`), the connection property winning over the URL as for every
other option. `Transports.option(url, properties)` reads it and
`Transports.using(kind, opening)` applies it to the opens on the calling
thread. `TransportOptionTest` asks each of the four, both ways, for a
transport that does not exist and expects to be told so by name.

### `/actuator/seclume`: how every data source is secured

The question an audit asks and an application usually cannot answer. With the
actuator on the class path the starter registers an endpoint (exposed like any
other: `management.endpoints.web.exposure.include=seclume`) that reports, per
pool: the login method as the protocol names it, the TLS protocol, suite and
stack, the certificate the server showed - subject, issuer and **expiry**, the
date that ends in an outage when nobody looks - the server's connection limit
and use, the pool's numbers, and the seclume version. Never a password, a
statement or a value. Against the test server: `scram-sha-256-plus`, `TLSv1.3 /
TLS_AES_256_GCM_SHA384 (seclume)`, the certificate expiring 2027-09-14, 97
connections allowed. `SeclumeEndpointTest`.

### The heap check at a moment of the test's choosing

`NoSecretInHeap` checked after each test (`@ExtendWith`). Where the secret
leaks matters as much as whether: `NoSecretInHeap.assertAbsent(secretFile)`
runs the same check in the middle of a test - right after the login, between
two steps, before the connection closes - with the same rule: the test JVM
holds the path, the search runs in a process of its own. `NoSecretInHeapTest`
(a clean child passes, a leaking one is reported "on the heap at this point").

### Secrets left out of crash dumps

A secret's pages were locked (`mlock`, `VirtualLock`), which keeps them out of
swap - and not out of a core dump, which `MemoryLock`'s own comment claimed it
did. A core file, a crash report sent to a vendor, a checkpoint image are the
process's memory on a disk, the secret with it. Every `SecretScope` is now
also excluded from dumps: `madvise(MADV_DONTDUMP)` on Linux, over the whole
pages it lies on, and `WerRegisterExcludedMemoryBlock` on Windows, registered
off again when the scope closes (Windows keeps at most 512 such blocks; beyond
that the secret is merely locked, as before). `DumpExclusionTest`, and on a
Linux container the kernel's own view of a secret's page:
`VmFlags: rd wr mr mw me lo ac dd sd` - `lo` locked, `dd` not dumped.

### Statements left open are closed on return - and it says where they were made

The pool's leak detection works per connection: held too long. A connection
that came back in time with statements still open was not noticed - each of
them a server cursor on Oracle (`ORA-01000: maximum open cursors exceeded` after
enough of them) and result memory on the others, outliving the request that
forgot them. The four connections now offer `space.seclume.OpenStatements`, and
the pool closes what a borrower left open when the connection comes back - its
own cached prepared statements excepted - and logs it with each statement's
fingerprint: the first ten times, then every thousandth. With
`leak-detection-threshold` set, the statements record where they were made and
the warning shows the caller's frames, not the driver's; without it, a stack
trace per statement is not paid for. Tested on all four in `SessionResetTest`.

### "Too many clients already" - said before it happens

The cause is almost always arithmetic nobody did: instances times pool size
over the server's limit, found the first time the deployment scales out. The
four connections now offer `space.seclume.ServerCapacity` - the connections the
server allows and the ones open now, each asked on its own and `-1` where the
user may not see it (Oracle's `v$session` needs a grant most application users
lack): PostgreSQL's `max_connections` less the superuser reserve and its client
backends, MySQL's `max_connections` and `Threads_connected`, SQL Server's
`@@max_connections` and user sessions. The pool asks once, at its first
connection, and logs a warning when it alone could fill what is left, or when
there is room for only one instance of it; `seclume-verify` prints a
`capacity` line. `CapacityTest` on all four (the real servers answered 97, 151,
32767 and, for Oracle, 322 with the use not visible), `CapacityWarningTest`.

### Which build is running

Every jar carries `Implementation-Title` and `Implementation-Version` in its
manifest now, and `space.seclume.Version.current()` reads it - `0.10.0`, or
`development` for code that did not come from a jar. The first line a support
request needs, and one an application can log at start.

### PostgreSQL 17: direct TLS, one round trip fewer

`tlsNegotiation=direct` (libpq's `sslnegotiation=direct`, which is accepted
too) starts the TLS handshake at once, with ALPN `postgresql`, instead of
asking with an `SSLRequest` first and waiting for its one-byte answer - one
round trip fewer on every connect, which is most of what a pool's warm-up and
a serverless cold start pay. PostgreSQL 17 and later; an older server refuses
it and the connect fails, it does not fall back unnoticed. Both TLS stacks.
`LocalDirectTlsTest` against a PostgreSQL 17 (encrypted session, both stacks)
and a 16 (refused).

**Found on the way:** `PgSession.Settings.at(host)` rebuilds the settings for
every host - also for a single one - and dropped the new component, exactly
as its own comment warns it once dropped the TLS stack. The first test against
PostgreSQL 17 passed anyway, because 17 also answers the classic way; only the
test against 16, which must refuse, showed the option never reached the
connect.

### PostgreSQL: LISTEN / NOTIFY

The driver knew `NotificationResponse` by name and dropped every one. Now they
wait on the session (up to 10 000, the oldest dropping and counted beyond
that) and `PgConnection.notifications()` hands them out, oldest first, as
`PgNotification(processId, channel, payload)` - asking the server with a bare
`Sync` when none has arrived with an earlier answer: one round trip, and not
even the transaction a pending `BEGIN` would start. `notifications(Duration)`
waits for the first, asking every fifty milliseconds, which on a virtual thread
is a sleep and not a thread - cache invalidation and the outbox pattern without
a thread per listener. A `LISTEN` counts as session state for the pool's
reset, so a returned connection stops listening. `LocalNotificationTest`.

### A CA file or a pinned key, per connection - instead of switching the check off

"PKIX path building failed" is what `verify-full` gets from a server whose CA
the JVM does not know, and `trustServerCertificate=true` is what the first
search result says to do about it. Two options that keep the check, on all
four drivers, through the driver and the data source, on both TLS stacks:
`tlsRootCert=/path/ca.pem` names the CA for that connection alone (PEM or
DER, one or more certificates), as libpq's `sslrootcert` does, and leaves the
JVM's trust store and every other connection alone; `tlsPin=sha256/<base64>`
makes the server's public key the trust - compared byte for byte, no chain and
no host name - for a self-signed certificate with no CA to name, in the
notation curl's `--pinnedpubkey` uses. A wrong pin is refused before a byte of
the protocol, naming the pin the server did present.
`seclume-verify --print-pin "<url>"` connects once without checking and prints
the pin with the certificate's subject, issuer and expiry, to compare with the
server's owner. `Secured.serverCertificate()` says which certificate a
connection was shown. `TrustChoiceTest` (both stacks against a CA the JVM does
not know), `PinnedTlsTest` (all four servers, both stacks: refused without a
pin, connected with the right one, refused with a wrong one).

**Found on the way:** Base64 has `+`, which URL decoding turns into a blank -
half the real servers' pins failed to parse until the pin was taken as
written.

### Connections cut on the way: kept alive, and named when they are cut anyway

"Communications link failure", "Got minus one from a read call": a pooled
connection idle for minutes, and a firewall, a NAT or a load balancer on the
way - Azure's after four minutes - forgot the flow without telling either end.
Every connection now has TCP keepalive on, probing after a minute of silence
where the platform lets that be set (`TCP_KEEPIDLE` 60 s, 10 s between probes,
5 probes), which keeps the flow alive in all of them. And a connection that
ends after more than 30 s without traffic says so instead of just ending: "the
connection was cut after 241 s without traffic - that matches an idle timeout
between here and the server (a firewall, a NAT, a load balancer) or the
server's own (wait_timeout, idle_session_timeout)". An end of stream without
the silence before it is an ordinary end, as before. `SocketTransportSilenceTest`.

### A result limit by default, in the Spring starter

The compatibility matrix said it on all eight servers: result limit *off - a
runaway query ends in an OutOfMemoryError*. A missing `where` or a join that
multiplies read rows until the heap was gone, and the error took every other
request with it. A data source the starter makes now gets a limit when its URL
sets none: `maxResultBytes` of a quarter of the heap, at least 16 and at most
256 MB, said in the log at start. That statement then fails with an exception
naming the limit; nothing else notices. A URL that names `maxResultBytes` or
`maxResultRows` keeps its own, and `maxResultBytes=0` switches the limit off.
The drivers themselves are unchanged - a URL given to `DriverManager` still
means exactly what it says. `ResultLimitDefaultTest`.

### Tracing on OpenTelemetry's stable database conventions

The spans carried the attribute names from before the database conventions
were stable - `db.system`, `db.statement`, `db.operation`. Now:
`db.system.name` (`postgresql`, `mysql`, `microsoft.sql_server`,
`oracle.db`), `db.query.text` (the fingerprint, as before), `db.operation.name`,
`db.query.summary` - the operation and its first table, `SELECT orders`, which
is also the span name now instead of the bare operation - and `error.type` on
a failed statement (`_OTHER`: the failure is not described further, for the
reason a status message is not set). `OTEL_SEMCONV_STABILITY_OPT_IN` naming
`database/dup` adds the old names beside the new ones, the switch OpenTelemetry
defines for the move. The fingerprint was already exactly what
`db.query.summary` asks to be summarised from.

### The tenant leak: session state no longer goes to the next borrower

A pool put back what JDBC knows - the transaction, auto-commit, read-only, the
isolation - and nothing a statement set. `SET app.tenant_id = 42` instead of
`set_config(..., true)` handed the tenant of one request to the next request on
that connection: the most common way row-level security breaks in practice.
The same for a `search_path`, a temporary table, a MySQL user variable, a
session-level advisory lock, an Oracle client identifier or package variable.

Now the four drivers note every statement that sets such state as it passes
(`SessionState` - its first word and a handful of calls, erring towards
noting), and the connections offer `space.seclume.SessionReset`. The pool asks
on return and resets only a connection that had one, so the ordinary return
costs nothing:

| | the reset |
|---|---|
| PostgreSQL | one round trip: `CLOSE ALL`, `SET SESSION AUTHORIZATION DEFAULT`, `RESET ALL`, `UNLISTEN *`, `pg_advisory_unlock_all()`, `DISCARD TEMP`, `DISCARD SEQUENCES` - prepared statements stay |
| MySQL | `COM_RESET_CONNECTION`; the pool's cached statements are closed first, the session's cache of prepared plans is cleared with it |
| SQL Server | the RESETCONNECTION bit on the next request - `sp_reset_connection` without a round trip of its own |
| Oracle | package state, client identifier, module and client info; an `ALTER SESSION` cannot be undone, and that connection is closed rather than lent again |

An isolation or read-only setting the connection has is sent again after the
reset when it is not the login's. `SessionResetTest` on all four: a tenant set
by one borrower is gone for the next borrower of the same session, a cached
prepared statement still runs; an altered Oracle session is replaced.

**Found on the way:** `MyConnection.reset()` left the session's cache of
prepared plans in place after `COM_RESET_CONNECTION` had dropped them on the
server - the next use of a cached statement would have named a statement id
that no longer existed.

### `snapshot()` beside `detach()`

The four sessions hand their stream over with `detach()`, which finishes the
session object. `snapshot()` describes the same state and **keeps the session**:
the stream and the encryption it returns are the live ones, to be described,
never used - with the TLS layer's new `TlsLayer.snapshot(out, offset)`, which
writes the keys and record counters as `freeze` does without giving the layer
up. The same refusals as `detach()` (work in flight, open cursors, on SQL
Server an explicit transaction), and a setting waiting for the next statement
is sent first, so the description says what the server has. Taken at a quiet
moment it is exact until the next record - and a copy kept after that fails
its first record rather than being taken for the connection. Also new:
`SecretScope.allocateShared`, a scope one thread writes and another reads.

### Oracle: a refused connection says why

When the listener refuses a connection it says why in the refusal -
`(ERR=12516)` - and the driver dropped that: the message was "the listener
answered with REFUSE instead of ACCEPT", where ojdbc names ORA-12516. Now the
number is the message and the error code (`ORA-12516: the listener refused
the connection - no free server process at the moment`), and the refusals that
pass by themselves - 12516, 12519, 12520, a listener whose count of free server
processes runs behind - are a `SQLTransientConnectionException`, so a pool or a
retry can tell them from a service the listener does not know (12514), which is
final. Found by a test that logs in several thousand times in a few seconds
(`ListenerRefusalTest`).

### Fuzzing

A corpus generator (`seclume-tck`, package `space.seclume.tck.fuzz`) takes a
handful of plausible server answers per protocol and produces the ways a
server can be wrong: every truncation, every length field spoilt, every byte
replaced in turn, messages spliced and repeated, and rubbish. A sample of it
runs in every build; the whole of it runs nightly under the `fuzz` profile.

Two sweeps per driver. The **decoders** are driven through a session that
resumed a scripted transport - what the driver does with a hostile answer.
The **login** is driven through the handshake itself, and the question there
is not what was decoded but whether the credential is still in this process
afterwards: `SecretScope.open()` has to be back where it started after every
single case.

PostgreSQL and MySQL are fuzzed from `open()`, because a script can be the
whole server. SQL Server and Oracle are entered one layer lower - TDS never
carries a password outside TLS, and Oracle's connect sequence would have to be
answered by half a server - so their sweeps drive `Login7`/`LoginResponse` and
`TtcFastAuth`/`TtcLogin` over a scripted channel. That is the code the
credential passes through; what is skipped in front of it holds nothing to
protect.

### Fixed

Everything here was found by the sweeps above, and every one of them is the
same shape: **an unchecked exception reaching the application** where a
`SQLException` was owed.

- `WireBuffer` accepted negative lengths, read past the limit through the
  absolute accessors, and let `limit()` be set beyond the capacity. Four
  fixes in the one class all four drivers read through.
- All four drivers turned a truncated answer into an `IllegalStateException`
  out of `executeQuery`. They now catch `WireBuffer.Truncated` alongside
  `IOException` and report a closed connection.
- SQL Server and Oracle ordered their login catch clauses so that a
  `Truncated` left as itself - anything answering on the port reached the
  parser before a credential was exchanged.
- `TtcParameters` threw a bare `IllegalStateException` on a chunk length that
  did not match the field length, which left `getConnection` unchecked.
- `TtcLogin` handed the server's PBKDF2 round counts straight to the JDK. A
  count of zero came back as "iterations must be at least 1"; a count of two
  billion was a server telling a client to spend an hour on a login. Both are
  now refused with a bound.
- `TtcResult` walked the fields of an Oracle error block past the end of the
  message. A LOB call answers with a shorter block than a statement does, and
  the walk read the wiped remainder of the receive buffer, got zeros, and
  arrived at "no error" by accident. It now stops where the message does - the
  same answer, on purpose. Found because `WireBuffer` began checking its
  bounds - no test had noticed, because the accident produced the right
  number.
- PostgreSQL grew its receive buffer to whatever a length field claimed;
  MySQL read a field-count and a length-encoded integer without bounds;
  Oracle grew its packet buffer past the negotiated SDU.
- A refused PostgreSQL login came back as `SQLException` with no SQLState and
  sometimes no message; it is now `SQLInvalidAuthorizationSpecException` with
  28000.

### The caller in the wrong order

`MisuseContract` (`seclume-tck`) drives twenty-seven JDBC calls made out of
order - a column read before `next()`, a `commit()` with no transaction, a
result set whose statement was closed - against a real server, and after every
one of them asks the connection for a row. A driver that writes a request it
should have refused has put a byte on the wire that the next answer is read
against, and that failure surfaces three calls later in code that did nothing
wrong.

Fixed, all of them found by that contract:

- PostgreSQL and MySQL threw `IllegalArgumentException` for a parameter index
  of 0. Oracle and SQL Server already refused it as a `SQLException`; now all
  four do, with SQLState 07009.
- All four accepted `executeUpdate` on a statement that returned rows. JDBC
  requires a refusal - a caller that gets 0 back from a `select` believes the
  statement ran and changed nothing. The rows are closed before the refusal,
  so the stream is not left mid-answer.
- All four ignored a negative timeout in `isValid`. Now 22023.
- Oracle allowed `commit()`, `rollback()` and `setSavepoint()` while
  auto-commit was on. PostgreSQL had refused these from the start; the
  difference only shows up when the same application is pointed at both.

### Cancellation, and the query timeout that depends on it

`Statement.cancel()` did nothing on any of the four drivers - it threw
`SQLFeatureNotSupportedException`, which is honest and is also a query timeout
nobody keeps. All four do it now, each by the only mechanism its protocol has,
and each proved against a real server by a `LocalCancelTest` that starts a
long statement on one thread and stops it from another.

| | how | what the caller sees |
|---|---|---|
| **PostgreSQL** | a CancelRequest of sixteen bytes down a **second** connection, carrying the process id and secret key from `BackendKeyData` | fails with SQLState `57014` |
| **MySQL** | `KILL QUERY <id>` on a second connection, which therefore costs a full login | **not always a failure** - a killed `SLEEP()` returns 1 instead of 0 and the statement succeeds |
| **SQL Server** | an eight-byte ATTENTION down the **same** socket, while the reader is still blocked on it | fails with SQLState `HY008` |
| **Oracle** | a `!` as **TCP urgent data** and a break MARKER behind it, down the same socket | fails with `ORA-01013` |

`Transport` has a fifth method for the Oracle one: `sendUrgent`. It took a
protocol to justify it. Oracle's server is running the statement and is not
reading the socket at all, so an in-band marker waits in its receive buffer
until the thing it was meant to stop has finished - measured, with the marker
framed exactly as the reset marker that already works elsewhere. Urgent data
is delivered ahead of the queue and raises `SIGURG`, which is what makes the
server look up. Transports that cannot send it say so and the marker goes on
its own, which is right for a listener configured with `DISABLE_OOB=ON`.

Three things that are easy to get wrong and are handled:

- **The acknowledgement.** SQL Server answers an ATTENTION with a message of
  its own, separate from the answer it interrupted. A client that does not
  read it finds it at the head of the next statement's answer and is one
  message behind from then on. It is counted, not flagged: two cancellations
  put two acknowledgements on the wire.
- **The gap between two statements.** A CancelRequest, a `KILL QUERY` and a
  break all name a connection rather than a statement, so one sent when
  nothing is running stops the *next* one - which is what a query-timeout
  thread does every time its query finishes first. All four drivers now check
  whether an answer is outstanding before sending anything. The narrow race,
  where the answer arrives while the cancellation is in flight, remains and is
  documented rather than hidden.
- **A statement that is cancelled and succeeds anyway.** MySQL's is the case;
  a driver that only rewrote exceptions would hand the caller a short answer
  with no sign its deadline had expired.

**`setQueryTimeout` therefore works**, on all four. It used to refuse every
non-zero value on the grounds that accepting a limit it could not enforce
would be a lie; `space.seclume.internal.jdbc.Deadline` enforces it now, on one
shared daemon thread that is created on first use and never at all if no
application sets a timeout. A statement that overruns comes back as
`SQLTimeoutException` whatever its protocol reported, because a retry is
written against the JDBC type and not against four vendor codes - and the
connection is still usable afterwards, which each driver's
`LocalQueryTimeoutTest` checks by running `select 42` on it.

### Seeing a desynchronised stream

`Flight` (`seclume-core`, public API, all four drivers) records the last N
messages a connection sent and received - direction, type, byte count - and
attaches the tail to the exception when the connection breaks.

There is one class of defect in a hand-written protocol driver that is worse
than a crash: a connection that is **one message behind**. Nothing fails when
it goes wrong; three calls later something fails, in code that did nothing,
and the stack trace points at the innocent caller. Several of the defects
fixed in this release had exactly that shape. Nothing that looks at one
statement can see it, because every statement looks fine - what shows it is
the *order*.

**Types and counts, never a payload.** A recorder that kept the bytes would be
a ring buffer holding a password during the handshake and a customer's name
during a query, in the heap, offered to whatever reads a diagnostic.

And one byte count is withheld: the message that carries the credential.
Found by reading the recorder's own first output, where a `PasswordMessage`
stood with a length beside it. Under SCRAM that length is the protocol's;
under cleartext authentication it is the password's length plus a constant,
which is the single most useful fact for anybody about to guess one.

**That question has a different answer in each protocol**, which is why the
four were decided rather than copied:

| | what carries the credential | why its length is withheld |
|---|---|---|
| PostgreSQL | `PasswordMessage` | under cleartext authentication it is the password's length |
| MySQL | the handshake response, and any auth-switch response | `mysql_clear_password` - which LDAP and PAM use - puts the password in it as itself |
| SQL Server | `LOGIN7` | the password is XOR-obfuscated, which is not encryption. That it also travels inside TLS protects it on the wire, not in a ring buffer in this process |
| Oracle | the second O5LOGON message | AES-encrypted and hex-encoded, so its length is the password's to within sixteen bytes - coarser than cleartext, finer than nothing |

The recorder is installed **before** the login on every driver, because a
login that fails is exactly when somebody wants to know what the server said -
and by then there is no session to ask.

Off unless asked for - `-Dseclume.flight=64` - because this sits on the path
of every message of every connection, and a diagnostic every application pays
for so that one of them can debug something is the wrong trade. Process-wide
rather than per connection for now, which is named in the javadoc rather than
left to be discovered.

### Rotating a credential without a gap

The pool has always retired a connection before its dynamic credential
expired. What it did next was retire first and refill afterwards, in that
order and in the same housekeeping round - so for the moment in between, a
cohort that lapsed together left nothing behind. That is not an outage; it is
every caller arriving in that moment paying a full handshake, and with a
dynamic credential an HTTP round trip to fetch the password before the
connection can even be opened. It shows up as an unexplained latency spike on
the hour and is very hard to attribute.

Two changes, and the second is the one that does most of the work:

- **The replacement is opened first.** `prewarm()` runs ahead of the sweep and
  opens one connection per idle entry whose credential has lapsed, so the
  sweep retires them into a pool that already holds their replacements. Only
  into spare capacity - a pool at `maximumPoolSize` has nowhere to put one,
  and taking a permit that is not free would be growing past the size an
  operator set. There it degrades to what it did before, and says so.
  `PoolStatistics.prewarmed()` counts it.
- **The deadlines of a cohort are spread out.** Connections opened in one
  burst by one credential share an expiry to the second, so they reached their
  deadline in one round. Each deadline is now drawn at random from a window
  ahead of the margin - `credentialSpread`, defaulting to the margin, zero for
  the old behaviour. Only ever earlier than the margin, never later.

### Reading a secret out of the database

`Sensitive` (`seclume-core`, public API, implemented by all four result sets)
copies a column straight from the receive buffer into native memory the caller
owns - usually a `SecretScope` - without it ever becoming a `String`.

This library's claim was always about the connection password. **The half
nobody says out loud is that a great many applications store secrets in the
database**: API keys, webhook signing keys, OAuth refresh tokens, TOTP seeds,
the credentials of every third-party system a tenant has connected. Every one
of them was read with `getString`, and from that moment had exactly the
lifetime the connection password had before any of this was written.

The row is already in native memory - it came off a socket - so this hands out
the window instead of copying it twice. What it promises is that the value does
not become a heap object *on the way out of the driver*; it cannot promise
anything about what the caller does next, and does not pretend to. What it
changes is that the careful path exists at all.

Proved the same way the connection password is: a **child JVM** reads the value
natively and dumps its own heap, and the dump must be clean - with a control
run that reads the same value with `getString` and whose dump must contain it.
The first version ran in the test's own JVM and failed, correctly: the value is
a constant in the test class, interned and permanent. A proof about what is in
a heap cannot run in a process that was told the answer.

Each driver supplies only the window - which buffer, what offset, how many
bytes - and the bounds check and the copy are shared. That is the part that can
be wrong per driver and wrong silently, so each one has a test that compares
the **bytes** rather than the length.

`SensitiveParameters` is the other half, and without it the first is half a
feature: an application that reads an API key off the heap has a problem, and
one that **writes** one with `setString` has the same problem in the same
process. Rotating a key, storing a freshly issued refresh token, saving a TOTP
seed at enrolment - every one of those is a parameter. All four drivers now
bind one straight from native memory, and each has a round-trip test: written
from a `SecretScope`, read back into one, never a `String` at either end.

Two decisions worth knowing:

- **SQL Server binds it as `varchar`, not `nvarchar`.** An nvarchar parameter
  is UTF-16 on the wire and the caller's bytes are not; converting them would
  need the buffer this path exists to avoid. The server converts into an
  nvarchar column itself.
- **Nothing is copied.** The driver holds the caller's segment and reads it
  when the statement is sent, so the scope has to still be open then. That is
  the contract a `byte[]` parameter has always had and nobody writes down;
  it is written down here because a closed arena fails louder.

### Finding the N+1

`QueryStorms` (`seclume-core`, public API) watches for **the same statement
shape, repeated, on one thread, inside one moment**, and reports it once -
through a callback and as a `space.seclume.QueryStorm` Flight Recorder event
with a stack trace.

Slow-query logging cannot find this. Two hundred statements of a millisecond
each are the reason a page takes a second, and every one of them is healthy on
its own; nothing that looks at statements one at a time can see the shape. It
is the most common performance defect in applications that use an object
mapper, and not because anybody writes it deliberately - a `for` loop over a
collection and a lazy association look identical in the source.

Each of the three conditions earns its place, and the tests are mostly about
what must **not** be reported:

- **One thread**, because an N+1 is a loop in somebody's method. Counting per
  process would make every busy server a permanent storm report.
- **One shape**, because a hundred different statements are a complicated
  request and a hundred identical ones are a loop.
- **One moment**, because the same statement a hundred times over an hour is a
  cache doing its job.

It carries the fingerprint and nothing else, which is what lets it be on by
default. The stack trace is the other half of the answer: the fingerprint says
*what* is looping, the stack says *where*.

`Observed.listen` still takes one listener - a list would be a plugin system
on the statement path, paid for by every application - so this composes
explicitly with `alongside(...)` and the application decides the order.

### No statement text in an exception message

`QueryFingerprint` exists because the SQL text is the one thing that must not
be recorded - a literal in it can be a password, a card number or a person.
The JFR events were written to that rule from the start. **The exception
messages were not.** Twenty-seven places across five modules read
`"... : " + sql`, and an exception message is more certain to be logged than
any event: it goes into the application's own log, into a stack trace, into a
ticket, into a screenshot.

Every one of them now carries the statement's shape instead. What is lost is a
literal nobody should have had; what is kept is which statement it was, which
is the whole reason the text was in the message.

`NoStatementTextInMessagesTest` checks the source in every module, the same
way `ForbiddenApiTest` does and for the same reason: this is a property one
loses while writing a single line, and every functional test keeps passing
while it is lost. It has a control of its own - the rule has to be shown
capable of failing.

Auditing the rest of the observability surface on the same question found
three more, and left the rest confirmed clean (the JFR events and the tracing
spans carry fingerprints by design, and say so):

- **A wrong JDBC URL was echoed back whole.** A seclume URL carries a provider
  and a path and no credential - that is the design, and it is why nobody
  looked. But the message that names a *wrong* URL is the one that gets handed
  a **vendor's**, and those routinely read `...?user=app&password=...`.
  `JdbcUrl.redact` keeps the shape and replaces every value; the three places
  that print a URL use it.
- `getURL` on a column that does not hold one quoted the JDK's message back,
  and the JDK's message contains the value. That value is a row.
- A malformed PostgreSQL array literal was quoted whole into its exception.
  Also a row. It now reports the length instead.

The last two are the same mistake as the first twenty-seven, one layer down:
**row data is not the driver's to publish either.**

### Retrying a transaction the database asked you to retry

`Retry` (`seclume-core`, public API) runs a block in a transaction and runs it
again when the server says the transaction cannot stand - a serialization
failure or a deadlock, which are not faults but the price of not taking locks
that would have been slower.

The loop is three lines and nobody gets that wrong. **The classification is
where applications get it wrong, in both directions**, so it is public
(`Retry.worthRetrying`) and has a test of its own:

- Retried: SQLState class **40**, transaction rollback, and
  `SQLTransientException`. That is the whole list.
- Not retried: class **08**, because the connection is gone and the block
  would fail identically on it three times while hiding the first cause;
  `SQLTimeoutException`, because a deadline the caller set has already passed;
  `57014`, because somebody asked for this to stop; and everything that will
  simply happen again - constraint violations, syntax, authorisation.

The backoff is jittered, and that is not politeness: two transactions that
deadlock and retry on the same schedule deadlock again on the same schedule.

`LocalRetryTest` proves it against a real PostgreSQL with a deliberate write
skew - two transactions that meet at a barrier between their read and their
write, so the conflict is certain rather than likely. It has a **negative
control**: the same pair is run first without the retry and one of them has to
fail with 40001, because a test in which both happen to succeed proves nothing.

### No stored credential at all: workload identity

Two providers that store nothing, because the database accepts the machine's
own cloud identity:

- `azure-managed-identity` - an Entra ID token from the Instance Metadata
  Service, for Azure Database for PostgreSQL and MySQL
  (`resource=https://ossrdbms-aad.database.windows.net`, optional `client-id`
  for a user-assigned identity);
- `gcp-metadata` - a service account's token from the metadata server, for
  Cloud SQL IAM database authentication.

The SDKs hand the token out as a `String`; here it goes from the socket into
native memory and only `access_token` is copied out. Both also serve as the
`token-` of a vault - `azure-key-vault` with `token-provider=azure-managed-identity`
reads Key Vault with the machine's identity and nothing else configured.

Both endpoints are plain HTTP on the link-local address, which is how they are
meant to be reached. `SecretFetch` now allows plain HTTP **only** to a
link-local or loopback address, checked on the resolved address before
anything is sent; pointing one of these at a real host by mistake fails
instead of handing a token across a network. Expiry is deliberately not
reported to the pool: the token is checked at login only, so a connection
outlives it.

**Not covered:** App Service and Functions (a different endpoint), Azure Arc,
SQL Server's Entra login inside LOGIN7 (`FEDAUTH`), and SPIFFE's JWT-SVIDs.

### Found by the framework suites

Four new suites, each on all four databases, went where the Spring Data tests
never did: **Spring's own JDBC and its transactions** (`REQUIRES_NEW`,
`NESTED`, `readOnly`, isolation, a transaction timeout, `batchUpdate`,
`NamedParameterJdbcTemplate`, `KeyHolder`, `SimpleJdbcInsert`, a script split
by `ScriptUtils`, the JDBC escapes, a streamed read); **Hibernate's edges**
(JSON, LOBs as values and as streams, `@Formula`, bulk HQL); **Liquibase, jOOQ,
MyBatis and Spring Data JDBC** through their own APIs; and **one JTA
transaction over all four** - Atomikos coordinating, Spring's
`JtaTransactionManager` in front: a commit that reaches every database, a
rollback that reaches every database, and a failure in the last that takes back
what the first three had done.

They found this, and every item has a regression test of its own at driver
level unless it says otherwise:

- **The Spring Boot starter dropped almost every URL option.** It copied host,
  port, database and a few flags into the `DataSource` one setter at a time;
  `tls` was not among them. `tls=verify-full` in `application.properties` meant
  `prefer` on PostgreSQL and MySQL - encrypted, server unchecked - and no TLS at
  all on Oracle, without a word. The client certificate, `targetServerType`,
  `hostSelection` and the result limits went the same way. It now hands over the
  whole URL, and every `DataSource.setUrl` takes every setting the URL can carry.
- **PostgreSQL had no savepoints**, so `Propagation.NESTED` did not work at all.
- **MySQL kept one deferred setting, and each replaced the last.** Spring
  prepares a transaction with `setReadOnly`, `setTransactionIsolation` and
  `setAutoCommit(false)`; only `autocommit=0` reached the server. Read-only and
  serializable transactions ran as ordinary ones while the connection said
  otherwise. And the settings did not ride with `COM_STMT_PREPARE`, so the first
  UPDATE after a read-only transaction was refused at prepare time (1792).
- **Oracle's read-only and isolation lasted one transaction** and were sent
  while auto-commit was still on - committed away with themselves. Isolation is
  now `ALTER SESSION`, read-only is sent in front of each transaction.
- **A query timeout inside a transaction did not cancel anything** on PostgreSQL
  and MySQL: the answer to the deferred `BEGIN` / `SET` riding in front made the
  driver believe nothing was running, and the statement ran to its end.
- **A plain `executeUpdate` after a plain `select` on the same PostgreSQL
  connection was refused** as "returned rows" - the last RowDescription was
  never cleared. A pool validating with `select 1` made that every plain update.
- **PostgreSQL lost a prepared statement's Parse** three ways: one slot for the
  owed Parse (a second `prepareStatement` replaced the first's); a Parse counted
  done once sent, so one that failed - on a table not created yet - was never
  sent again; and a rollback discarded owed Parses. All three ended in
  "prepared statement seclume_N does not exist".
- **Oracle kept cursors it must not keep**: one for DDL, so a repeated
  `create table` or `truncate` of the same text did nothing and said nothing;
  and one for a statement that had failed at parse, answering every later run
  with ORA-01003.
- **`prepareCall` refused plain SQL.** pgjdbc, ojdbc and mssql-jdbc accept it and
  Liquibase depends on it for its default schema; it now runs as a query, and
  only OUT parameters are refused.
- **MySQL returned text in a `_bin` collation as `byte[]`** from `getObject` - the
  BINARY flag decided, not the character set.
- **PostgreSQL's prepared `execute()` with generated keys reported `true` and an
  update count of -1**; MyBatis read it as an insert that changed nothing.
- **Generated keys**: PostgreSQL answered `supportsGetGeneratedKeys()` with false
  though it has them; Oracle answered false, which made `SimpleJdbcInsert`
  refuse, and its plain statements ignored a request for keys instead of refusing.
- **JDBC escapes** (`{fn ...}`, `{d}`, `{t}`, `{ts}`, `{escape}`, `{oj}`) were
  refused outright. They are translated now - nothing on SQL Server, which reads
  them itself, only `{escape}` on MySQL, everything on PostgreSQL and Oracle -
  and a brace in a literal, a comment or a dollar quote is left alone.
- **PostgreSQL two-phase commit had never been proven here**: the shared test
  server has `max_prepared_transactions = 0`, and the driver's own XA test skips
  that part when refused. It is proven now against a server of its own.

**Closed since** - every gap the suites named, each with a test of its
own at driver level:

- **Streams, `Blob` and `Clob` as parameters are read and sent as a value** on
  all four. They were refused "so the size stays visible at the call site";
  Hibernate binds a `Blob` or `Clob` from its `LobHelper` with
  `setBinaryStream(index, stream, length)`, where the size is visible, and the
  Oracle driver had accepted streams from the start for exactly that reason.
  The rule is now one rule, in `ParameterSetters` and `StreamValues`: the value
  passes through memory (a stream buys convenience here, not thrift), a length
  that is given is held to - a stream that ends early is an error, not a
  shorter value - and `setUnicodeStream`, deprecated since JDBC 2.0, stays
  refused.
- **PostgreSQL `setBlob`/`setClob` create a large object and bind its oid** -
  what pgjdbc does, and what Hibernate's `@Lob` needs there, since it maps to
  `oid`. This reverses a decision: it was refused because a large object
  outlives the row that points at it. It does, with pgjdbc as well - that is
  PostgreSQL's model, and a database with `oid` columns cleans up with the `lo`
  extension's `lo_manage` trigger or `vacuumlo`. What the driver does decide:
  only inside a transaction, so that the object and the row commit or roll back
  together (a rollback leaves nothing, tested); under auto-commit it is refused
  before anything is created, as pgjdbc refuses it. A Clob is stored as UTF-8;
  `getClob` and `getCharacterStream` on an `oid` column read it back.
- **Oracle: a value past 32 KB followed by other binds was refused** with
  ORA-01461, naming the wrong position. The server takes a bind that wide for
  a `LONG` and reads its value after all the others; the driver wrote it in
  place. A long value as the *last* bind worked, which is why every earlier test
  passed - Hibernate's insert, with LOB columns in alphabetical order and nulls
  behind them, did not. In a batch the row was read out of step (ORA-01483).
  Long values now go last, as python-oracledb sends them.
- **Oracle's native `JSON` type is read as JSON text.** A `JSON` column arrives
  as a temporary LOB locator - 38 bytes, announced by 40 instead of the CLOB's
  114 - and the row reader, looking for 114, read the rest of the row as the
  next columns: the connection broke on the first JSON column selected.
  The locator is read now, and its OSON is decoded (`OracleJson`) into the text
  `json_serialize` would produce - held against the server's own
  `json_serialize` for nested documents, arrays of records with shared field
  ids, more than 255 field names, a tree past 64 KB, strings past 64 KB,
  escapes, surrogate pairs, scalars, dates, timestamps and binary. `getString`,
  `getObject` and `getBytes` (UTF-8) answer with the text.
- **Oracle: a cancellation the server acted on late cancelled the next
  statement.** A PL/SQL block in `dbms_session.sleep` finishes its sleep before
  it takes a break - python-oracledb 4.0.2 against the same server: cancel one
  second into an eight-second sleep, ORA-01013 after eight; a long query,
  ORA-01013 after one. That part is the server's. The driver's part: the
  sleep's answer arrived as a success, and the break's markers and ORA-01013
  behind it were read by the *next* statement, which then failed as
  "cancelled". A query timeout firing late took down an innocent statement.
  The late answer is now the cancelled call's own outcome, as in
  python-oracledb, and a late answer nobody asked for is cleared before the
  next request goes out. The moment a break is sent is locked against the
  moment an answer ends, so neither can slip between the other.

**Limits that are not the driver's**, for the record:

- A string past 32 KB cannot be the *argument of a function* on Oracle
  (`json(?)`, `to_clob(?)`): it is a `LONG` there, and a `LONG` is no function's
  argument. ojdbc has the same limit; a column takes it.
- jOOQ's free edition has no SQL Server or Oracle dialect; that is jOOQ's.
- `Propagation.NESTED` through `JpaTransactionManager` is refused by Spring
  itself (`HibernateJpaDialect` offers no savepoints), with any driver.

### All four in a native image - and the downcalls it had not been told about

The native image had been proven against PostgreSQL only. Built again from the
current jar and run against all four: PostgreSQL, MySQL, SQL Server and Oracle
each answer `everything answers` in `seclume-verify`, over the JDK's TLS and
over seclume's own stack - including TDS 8.0 on SQL Server and TCPS on Oracle.

It did not start that way. With `tlsStack=seclume` the first connection failed
with `MissingForeignRegistrationError`: the TLS stack's P-256 goes through
OpenSSL by the foreign linker, and the image metadata named one downcall -
`mlock`, the only one the first image had reached. The metadata now holds every
signature in the source, twenty-two of them, the Windows APIs included, and
`NativeDowncallMetadataTest` reads them out of the source and holds the file to
it in both directions: a native call added without a registration fails the
build, not an image in production.

### Fixed: three types that broke every column behind them

Found while adding `getSQLXML` and `getRowId`, with a probe against the live
servers; each has a test that also reads a column *behind* the type:

- **SQL Server `xml`** was counted among the four-byte types, so its
  description - a schema flag and names, not a length - was read as a length.
  Every column after it, and the rows, came from the wrong place: the
  connection broke on the first `xml` column selected. It now reads as the
  document, and `getSQLXML` answers for it.
- **Oracle `ROWID`** is five numbers of the protocol's own width, not a
  length-prefixed value. Its leading byte was taken for a length - fourteen,
  where the five take eleven - and the next column lost three bytes. It now
  reads as the eighteen characters Oracle prints (held against
  `rowidtochar`), as `Types.ROWID`, through `getRowId`, and binds back with
  `setRowId`. `getRowIdLifetime()` says `ROWID_VALID_FOREVER`, as ojdbc does.
- **Oracle `XMLType`** is an object, and an object column describes itself
  with an object id, a schema and a type name, each a length and then the
  bytes. Read as bare blocks, the description went out of step and the result
  looked empty. It now reads as the document (held against `getClobVal()`), as
  `Types.SQLXML`, through `getSQLXML`. An XMLType stored as a LOB, and other
  object types, are refused by name.

### Fixed: an Oracle LOB write failed once in 256 calls

`writeLob` - behind `setClob`, `setBlob`, `Clob.setString` and every temporary LOB - sometimes
failed with `a row arrived before its description`, a few times over the months, only in full
builds and never when anybody tried to reproduce it. It was no race. A write or a free is
answered with the locator alone; the parser expected a number behind it, as a read, a length or
a create has, and read the status message that follows as one: its first byte as the count of
digits, four bytes of it as the value - and the walk carried on at the low byte of a counter the
server raises with every call. Mostly that byte is no message type and the walk stopped quietly;
once in 256 calls it is 7, the row message, and the write failed after it had succeeded. (At 4
it would have read garbage as an error, at 8 as a parameter.) A test loop never saw it because
256 is a multiple of its four calls per round: the 7 fell on the same, correctly read, call every
time.

Now the answer is read by what was asked: a number only where the call carried an amount.
`LobAnswerTest` holds the server's own bytes with the counter at every value that matters, and a
stress run of 600 rounds of five calls - so that the 7 fell on writes and frees - passed.

### Fixed: Oracle `TIMESTAMP WITH TIME ZONE` was written and read off by its offset

Oracle keeps the fields of a `TIMESTAMP WITH TIME ZONE` in UTC, with the zone
beside them. seclume wrote the *local* fields of an `OffsetDateTime` and read
the stored fields back as local, so its own round trip agreed - and every
other client saw the value shifted by the offset: `13:14+02:00` was stored as
`15:14+02:00`. `Instant` (offset zero) was not affected. Now both directions
are right and held against ojdbc and the server's `to_char`. **Values written
with a non-zero offset by an earlier seclume are stored shifted**; they read
back shifted now, as they always did for other clients.

Found with it:

- A zone given as a region (`Europe/Vienna`) arrives as the number of the
  region in Oracle's time zone file; it read as an offset of `+113:156` and
  `getTimestamp` threw. The names now come from the server's own
  `v$timezone_names`, asked once per connection when the first one appears.
- `TIMESTAMP WITH LOCAL TIME ZONE` travels in the database's zone and was
  handed out that way; it now reads in the session's zone.
- `getString` on both writes what ojdbc writes (`2024-02-29 13:14:15.5 +2:00`,
  `... Europe/Vienna`); `getObject` is an `OffsetDateTime` and a `Timestamp`.
- A JSON value holding such a timestamp had the same shift.

### Fixed: SQL Server `varchar` in any collation but plain ASCII read wrong

A `char`, `varchar` or `text` column is bytes in the code page of its collation, and the
collation comes with the column description. It was skipped, and every such value read as
Latin-1: Cyrillic, Greek, Hebrew, Arabic, Thai, Chinese, Japanese and Korean text came back as
other characters, and even the default `SQL_Latin1_General_CP1_CI_AS` - code page 1252, not
Latin-1 - lost the euro sign and typographic quotes. No error, the wrong text. Now the collation
is read and the value decoded in its code page, `sql_variant` included; UTF-8 collations as
UTF-8. `SqlServerCollationTest` reads seventeen collations like mssql-jdbc does (`varchar` and
`text`, plain and prepared, SQL Server 2022 and 2025) - 60 columns differed before - and holds
the code page of every one of the ~5 500 collations the server lists to what the server itself
says. A runtime without the extended charsets (a trimmed image) falls back to Latin-1, as
before.

A GraalVM native image carries only the standard charsets, so the SQL Server jar now brings
`-H:+AddAllCharsets` in its own `native-image.properties`. Checked by building a probe twice
(GraalVM CE 25, Linux): with the jar as shipped, Cyrillic, Greek, both Chinese, Japanese, Korean,
Thai, code page 1252 and UTF-8 read right, plain and prepared; with that one file removed from
the jar, every non-Latin code page came back as Latin-1 mojibake.

### Scrollable results, on all four

`createStatement` and `prepareStatement` with `TYPE_SCROLL_INSENSITIVE` threw
`SQLFeatureNotSupportedException` on every driver - while the README listed scrollable results
among the features. That is the type Hibernate's `scroll()` asks for by default and that
reporting tools open their queries with, and all four vendor drivers have it. Now the result is
read whole into the same native block a forward-only one uses - no fetch size, no block cursor,
no pause on SQL Server - and `previous`, `first`, `last`, `absolute` (from either end),
`relative`, `beforeFirst` and `afterLast` move over it; no value is copied onto the heap for it.
`ScrollableResultTest` walks seven rows through seclume and through the vendor's driver, plain
and prepared, with and without a fetch size in an open transaction, and compares every answer,
row number and value; and it goes to the end of 10 000 to 20 000 rows and back, past the
16 384 after which a forward-only SQL Server result pauses. Identical on all four.

Still refused, with a reason: `TYPE_SCROLL_SENSITIVE` (it would have to see later changes) and
`CONCUR_UPDATABLE`. A forward-only result still refuses `previous()` rather than guess.
`getFetchSize()` keeps saying what was asked for; the fetch size simply has no effect on a
scrollable result.

Two silent answers on the way, now refusals or right:

- `prepareCall(sql, type, concurrency)` ignored both on all four and handed back a forward-only
  statement; it now takes them like `prepareStatement` does.
- Oracle's `prepareStatement(sql, int[] columnIndexes)` returned a plain statement, so an
  insert that asked for its key got none and no error. It now refuses with the reason, as the
  PostgreSQL driver already did - name the columns instead.

### `closeOnCompletion()`, on all four

It threw `SQLFeatureNotSupportedException` everywhere; every vendor driver has it. Now a
statement told so closes when the application closes its result. `CloseOnCompletionTest`
compares the stories that matter with the vendor's driver - the flag before and after, open
while reading, closed with its result, still open after the last row until the result is
closed, and nothing happening without the flag - plain and prepared, identical on all four.

One place where the vendors disagree among themselves, and seclume takes the side that breaks
nothing: running the statement again closes its first result, and pgjdbc, ojdbc and mssql-jdbc
count that as the completion - the statement closes under its own second execution, which then
fails. Connector/J keeps it open, and so does seclume on all four; a driver closing its own
result for the next execution is not the application closing it.

The pool does not cache a statement that was told `closeOnCompletion()`: JDBC has no call to
take it back, and the next borrower's result would close a statement it never asked to lose.

### Fixed: a connection on seclume's own TLS stack worked only in the thread that opened it

With `tlsStack=seclume`, the first statement from any thread but the one that opened the
connection failed with `WrongThreadException: Attempted access outside owning thread` - on all
four databases. The record layer kept its AES key schedule in a confined arena, which only the
creating thread may touch. Every connection pool opens connections in one thread and hands them
to others, so the own TLS stack was, in practice, unusable behind a pool; every test ran in one
thread and never saw it. The JDK's stack was not affected. The key now lives in a shared arena -
still off the heap and wiped when the key is closed. `TlsAcrossThreadsTest` opens a connection on
each of the four and uses it from another platform thread, a virtual thread and the first one
again. Found while handing an encrypted session from one gateway process to another.

### Every JDBC method, against the vendor's driver - and what that found

`ApiSurfaceTest` calls every method of `Connection`, `Statement`, `PreparedStatement`,
`CallableStatement`, `ResultSet` and `ResultSetMetaData` - 656 of them - through seclume and
through the vendor's driver, on a fresh object each, and fails wherever the vendor does it and
seclume answers `SQLFeatureNotSupportedException` without a reason on record. The first run found
33 such methods on PostgreSQL, 60 on MySQL, 83 on Oracle and over 90 on SQL Server. Now there are
none; what is still refused is listed in the test with its reason (updatable results, REF,
SQL Server's missing ARRAY and ROWID types, batches of calls, holdability past a commit, keys by
column number, the text-taking methods JDBC forbids on a prepared statement).

Done now, each checked against the vendors:

- **Against the letter of JDBC before:** `setCatalog` on Oracle and `setSchema` on MySQL are
  ignored, as JDBC says for a database without catalogs or schemas; PostgreSQL's `setCatalog`
  and SQL Server's `setSchema` accept the value they already have (a pool putting back what it
  read) and still refuse another, where the vendors silently ignore it. `setCursorName` is the
  no-op JDBC prescribes without positioned updates. `setFetchDirection` is a hint on statements
  and results, and only a value that is no direction is refused. `getObject(i, map)` with an
  empty map is `getObject(i)`. `getTypeMap` returns a mutable map. A `null` through `setArray`,
  `setRowId`, `setRef`, `setSQLXML` and `setURL` is a NULL, as for every setter.
- **`executeLargeUpdate` with generated keys**, on all four.
- **`setObject(i, x, JDBCType.X)`** - JDBC 4.2's form - on all four; it was left to the
  interface's refusing default, so `Types.INTEGER` worked and `JDBCType.INTEGER` did not.
- **`createSQLXML`** on all four: written as text, through a writer, as UTF-8 bytes or a
  `StreamResult`, and bound with `setSQLXML`. `setURL` binds the text - pgjdbc and mssql-jdbc
  have no `setURL` at all. `XmlAndUrlBindTest` writes both into real `xml`/`XMLTYPE` columns.
- **`createClob`, `createBlob`, `createNClob`** on MySQL and SQL Server. `LobCreateTest` makes
  the same edits - write, overwrite in the middle, append by stream - through both drivers.
- **Fixed: Oracle's `createClob`/`createBlob` cut everything behind a write off.**
  `clob.setString(8, "AUS")` on "Grüße aus Wien" left "Grüße aAUS"; JDBC says a write
  overwrites and grows only past the end. All three drivers now share one implementation.
- **OUT parameters** as `getClob`, `getNClob`, `getBlob`, `getCharacterStream`, `getSQLXML`,
  `getURL` and `getRowId`, by index and by name.
- **`getParameterMetaData()`** on all four: the parameter count - with question marks in
  strings and comments not counted - and the mode. The types are refused with the reason: they
  would cost a round trip to ask for. `ParameterCountTest` compares the count; mssql-jdbc itself
  refuses for `select ?`, because it asks the server for types it cannot name.
- **`setMaxFieldSize`** on all four, cutting text by characters and binary by bytes and leaving
  numbers alone. The vendors disagree - pgjdbc does the same, Connector/J and mssql-jdbc cut
  nothing, ojdbc cuts UTF-8 bytes through a character and the digits of a NUMBER - so
  `MaxFieldSizeTest` holds seclume to JDBC and compares with pgjdbc only.
- MySQL's `getSQLXML` reads the text column the XML lives in; MySQL has no XML type.

### `setNetworkTimeout`, on all four - a server that stops answering no longer holds a thread for ever

There was no read timeout at all: `setNetworkTimeout` threw `SQLFeatureNotSupportedException`,
and a server that stopped answering in the middle of a statement - a network partition, a host
frozen by its hypervisor - held the calling thread until the operating system gave up on the TCP
connection, which can take a quarter of an hour. HikariCP calls it around every validation and
close and quietly does without when refused.

Now a connection with a network timeout gives up on a read or write that waits longer, closes
itself, and says why (`SocketTimeoutException`: no answer within the network timeout of N ms).
`NetworkTimeoutTest` runs the same story through seclume and the vendor's driver - the default
0, the value set is the value read, a quick statement undisturbed, a statement sleeping past
the timeout failing near it, the connection closed and invalid afterwards - identical on all
four; and zero waits again. The executor is accepted and not needed.

How it is watched matters for speed: not a timer per read, but one daemon thread for every
connection that has a timeout, looking at when each started to wait a few times a second. A
read costs one `nanoTime` more when a timeout is set and nothing at all when it is not; the
timeout fires up to 50 ms late, which against the seconds such timeouts are set in is noise.

The pool puts a borrower's network timeout back when the connection is returned, as it does
auto-commit, read-only and the isolation level.

### Errors raised like the vendor's driver: SQLState, code and type

An application branches on an error's SQLState, its vendor code or its `SQLException`
subclass - Spring's translators, Hibernate, `catch (SQLIntegrityConstraintViolationException e)`,
a check for 23000. `ErrorCatalogTest` raises thirteen everyday errors on all four (unique,
foreign key, not null, check, too long, division by zero, syntax, no such table or column,
numeric overflow, bad cast, deleting a referenced row, a user-raised error) through seclume and
through the vendor's driver and compares all three, reading every result to the end so that an
error behind the column description counts. PostgreSQL already matched; the other three now do.

| Driver | Before | Now |
|---|---|---|
| Oracle | own states (42S02, 23502, 22018, HY000 by default), always plain `SQLException` | ojdbc's states (42000 for 942/904/1722, 23000 for 1400, 72000 by default, ...) and its JDBC 4 types (`SQLIntegrityConstraintViolationException`, `SQLSyntaxErrorException`, `SQLDataException`, `SQLTimeoutException` for ORA-01013, `SQLRecoverableException` for a lost connection) |
| MySQL | the server's state, always `MyException` | a value that does not fit (1264, 1265, 1365, 1406) is a `java.sql.DataTruncation` with state 22001, as with Connector/J; classes 22/23/28/40/42/0A get their JDBC 4 type; the rest stays `MyException` |
| SQL Server | S0001 for anything unmapped | S0002 for a missing table, 23000 for NOT NULL (515), otherwise `S` and the server's state byte (a missing procedure is S0062), as mssql-jdbc |

Behaviour changes, deliberately:

- Oracle `ORA-12899` (value too large for column) is 72000, not 22001, and `ORA-00942` 42000,
  not 42S02 - what ojdbc says. Code that checks the number is unaffected.
- Oracle `ORA-00060` and `ORA-08177` keep ojdbc's states (61000, 72000) but arrive as
  `SQLTransactionRollbackException`, `ORA-04061`/`04068` as `SQLTransientException` - ojdbc
  throws the base class for them. `Retry` recognises them by that type.
- MySQL: a syntax error, a constraint violation and the like are no longer `MyException`.
  `getErrorCode()` carries the server's number on every one.

### At least as fast as the vendor's driver, on every one of four workloads and four databases

Measured with each vendor driver against the same servers on one LAN: 50 000
rows read with `getObject` and `getString` on every column, best of five.

| | rows | JSON | timestamp with zone | numeric |
|---|---|---|---|---|
| PostgreSQL vs pgjdbc | 54.5 / 54.5 ms | 195 / 200 ms | **25 / 30 ms** | 25.4 / 25.6 ms |
| MySQL vs Connector/J | 48.3 / 49.4 ms | 115 / 116 ms | **54 / 70 ms** | **21.5 / 25.1 ms** |
| SQL Server vs mssql-jdbc | 45.3 / 45.6 ms | 43.1 / 43.5 ms | **71 / 92 ms** | 19.9 / 20.2 ms |
| Oracle vs ojdbc | **55 / 160 ms** | **317 / 454 ms** | **98 / 185 ms** | **43 / 163 ms** |

Where the two are level, both wait for the network and the server; a driver
cannot be faster than the rows arrive. Where they were not level, this is what
it took:

- **SQL Server hands out rows while the rest is arriving.** `executeQuery`
  used to wait for the last packet, and every value was decoded after the
  network was done - the network's time plus the application's. The answer is
  now read packet by packet, `executeQuery` returns with the first rows, and
  `next()` reads on, so the application works while the network does, as with
  mssql-jdbc. Whatever else uses the connection meanwhile - another statement,
  a commit, metadata - finds the rest read in first and the open result intact;
  a result closed half-way has its rest dropped. The receive buffer now holds a
  packet or two instead of the whole answer. `SqlServerPausedResultTest` holds
  all of it, with a second result behind a paused one, an error after the first
  rows, and values of a megabyte and more across dozens of packets.
- **SQL Server asks for 32 KB packets** instead of 4 KB: an eighth of the TLS
  records and server flushes.
- **SQL Server decimals** that fit a `long` - every `decimal(18)` - no longer
  go through text on the way to a `BigDecimal`, and printing one no longer runs
  a regular expression per value.
- **Timestamps with an offset** (`timestamptz`, `datetimeoffset`) are read by
  arithmetic on the characters instead of two java.time parsers per value:
  twice as fast, and held against java.time over 800 000 spellings.
- **Batches.** SQL Server sends the full packets of a batch while the rest is
  still being encoded, so the server runs the first rows meanwhile, and puts up
  to 16 384 calls into one message instead of 1 024; the values go without
  their `@P0` names, bound by position as mssql-jdbc sends them - a third of
  the bytes of a short row. Splitting a message into packets no longer
  allocates a buffer per packet. Oracle encodes a `BigDecimal` from its digits
  instead of its text, a `Timestamp` without the old calendar classes, a whole
  second in seven bytes, and binds each row of a batch as a view instead of a
  copy. 5 000 rows: SQL Server 66.6 against mssql-jdbc's 66.8 ms (was 91),
  Oracle 5.7 against ojdbc's 5.7 ms (was 10.1); `WireBuffer.ensureCapacity`
  is small enough now to be inlined into every write.
- **Fixed on the way:** growing the SQL Server receive buffer dropped the bytes
  of the next packet that had already arrived, and `WireBuffer.getIntLe` did not
  check the valid length the way `getByte` does - found by the first
  `nvarchar(max)` of a megabyte read packet by packet.

### Fixed: Oracle JSON and VECTOR past the first hundred rows - and faster than ojdbc

A native `JSON` or `VECTOR` value comes as a locator to a LOB made for that
fetch, and it lives only until the next one. seclume fetched every block of a
result before handing out the first row, so a result of a hundred rows or more
answered `ORA-24826` from its first value - and a smaller one paid a round trip
per value. A cursor with such a column now gets a define that brings the
values in the row: two round trips once per cursor, none per value after that.
`OracleValueLobTest` reads a thousand rows of JSON and VECTOR next to a CLOB,
a BLOB, a LONG, a ROWID and the national and time types, like ojdbc does.

`VECTOR` (23ai) reads at all now: the column description carries three more
fields for it, one of which was read as a length, and the value is a vector
image, rendered as the server and ojdbc write it (`[1.0E+000,2.5E+000]`,
`-1.00000005E-003` for a `FLOAT32`, `[1,2,3]` for `INT8` and `BINARY`) - in
long arithmetic, held against the exact `BigDecimal` rendering over two million
values.

A result read to its end no longer asks for a fixed hundred rows per round
trip: the fetch doubles from there, as long as a fetch stays near a megabyte by
what the rows weighed. Measured against ojdbc 23.6 on the same LAN:

| | seclume | ojdbc |
|---|---|---|
| 10 000 rows, two columns | 20 ms, 7 round trips | 40 ms, 43 round trips |
| 50 000 JSON documents, `getString` | 133 ms | 221 ms |
| 1 000 vectors of 1536 `FLOAT32`, `getString` | 188 ms | 518 ms |
| 100 000 `TIMESTAMP WITH TIME ZONE`, `getTimestamp` + `getString` | 0.85 s | 6.2 s |

The JSON a server serializes carries a timestamp's fraction to six places
(`.500000`); an OSON value read through seclume does too now.

### Every type on all four, read like the vendor's driver

A catalog test (`TypeCatalogTest` in `seclume-diff`) takes each server's list
of types - `pg_type`, `sys.types`, the manuals for MySQL and Oracle - writes a
NULL and a sample of each, and reads both through seclume and the vendor's
driver, with a column behind to catch a row that went out of step. Every
difference fails the test unless it is listed with its reason (the vendor's
own classes and type codes outside `java.sql.Types`, mostly). What it found:

- **Types that broke the connection or the row:** SQL Server `geography`,
  `geometry` and `hierarchyid` (CLR types - their description has four names,
  and their values are always chunked); Oracle `UROWID` (a length in front of
  the bytes, and logical row ids of index-organized tables print as ojdbc
  prints them) and `BFILE` (a locator, now framed; `getString` answers null,
  as with ojdbc).
- **Types that read as garbage:** Oracle `INTERVAL YEAR TO MONTH` and
  `INTERVAL DAY TO SECOND` now read as `1-2` and `1 2:3:4.5`; MySQL `bit` in a
  plain statement read the raw byte instead of the number.
- **PostgreSQL:** `oid` reads as `BIGINT`/`Long`, `bit` as `BIT`, a one-bit
  value as `Boolean`; `time` and `timetz` as `Time`, with the offset honoured;
  `money` as `DOUBLE`/`Double`; `refcursor` as `REF_CURSOR`; every built-in
  type reports its `pg_type` name.
- **MySQL:** `year` is a `DATE` and reads as `2024-01-01`, `json` is
  `LONGVARCHAR`, `int unsigned` and `mediumint unsigned` are `INTEGER`,
  `bit(1)` a `Boolean` and a wider `bit` its bytes, and `bit`/`year` lose the
  `UNSIGNED` the server flags them with. A `timestamp(3)` read through a
  prepared statement has three digits, not six.
- **SQL Server:** `numeric` is `NUMERIC`, `smalldatetime` and `smallmoney`
  report their own names, a row version is `timestamp`, `sql_variant` hands
  out what it holds, and `smalldatetime` prints as `Timestamp` does.
- **Oracle:** `NCLOB` is `NCLOB`, `BOOLEAN` prints `true`, `XMLType` is named
  `SYS.XMLTYPE`.
- **JSON functions:** `JsonFunctionTest` runs every JSON function each server
  has - 55 on PostgreSQL (operators, `jsonb_path_*`, SQL/JSON where the server
  has it), 34 on MySQL (through the text and the binary protocol), 15 on SQL
  Server (`OPENJSON`, `FOR JSON`, the 2025 `json` type and aggregates), 23 on
  Oracle (`JSON_TABLE`, `JSON_TRANSFORM`, `RETURNING JSON`, dot notation) - and
  compares them the same way. One finding: MySQL answers `json_unquote`,
  `json_value`, `json_type` and `json_quote` in `utf8mb4_bin`, whose BINARY
  flag made them `VARBINARY`; the character set decides now, as it already did
  for the value.

**Behaviour changes**, each to what the vendor's driver answers:

| Where | What | Was | Now |
|---|---|---|---|
| PostgreSQL | `bool` type code | `BOOLEAN` | `BIT` |
| PostgreSQL | `timestamptz` type code | `TIMESTAMP_WITH_TIMEZONE` | `TIMESTAMP` |
| MySQL | `getObject` on `datetime` | `Timestamp` | `LocalDateTime` |
| MySQL | `year` | `SMALLINT`, `2024` | `DATE`, `2024-01-01` |
| SQL Server | `bit` type code | `BOOLEAN` | `BIT` |
| SQL Server | `xml` type code | `SQLXML` | `LONGNVARCHAR` (`getSQLXML` still reads it) |
| SQL Server | `getObject` on `tinyint`, `smallint` | `Integer` | `Short` |
| Oracle | `getObject` on `NUMBER` | `Long` for whole numbers | `BigDecimal` always |
| Oracle | `NUMBER(p≤9)` type code | `INTEGER` | `NUMERIC` |
| Oracle | `TIMESTAMP WITH LOCAL TIME ZONE` type code | `TIMESTAMP_WITH_TIMEZONE` | `TIMESTAMP` |

### The same statement over a table that changed

Each driver keeps something per statement text - Oracle the cursor, PostgreSQL
a named plan - and a table dropped and re-created with other column types, or
given another column, leaves that describing a table that is gone. Oracle
answered `ORA-00932` (a `LONG RAW` where a `VARCHAR2` had been), PostgreSQL
`cached plan must not change result type`. Both now drop what they kept and
parse again, once: Oracle always, as a failed query changed nothing and Oracle
rolls back only the statement; PostgreSQL in auto-commit, while inside a
transaction the error goes out and the retry after the rollback parses afresh.
`StaleStatementTest` runs a chain of types through one column on all four.

### The session starts in the JVM's time zone, as with the vendor's driver

PostgreSQL and Oracle sessions used to start in UTC, while pgjdbc and ojdbc
start them in the JVM's zone. Anything the session zone decides then read
differently through the two drivers: `timestamptz::date`, `date_trunc`, the
text of a `timestamptz`, Oracle's `TIMESTAMP WITH LOCAL TIME ZONE`. Both now
follow the vendor. PostgreSQL gets the zone in the startup message, a
`GMT+05:00` with its sign turned round the way POSIX reads it; Oracle gets it
at login, as the region name where the JVM has one - so daylight saving
follows - and as the offset otherwise. MySQL and SQL Server drivers leave the
zone to the server, and so does seclume.

`SessionTimeZoneTest` holds all four against the vendor's driver, with the
JVM in `Pacific/Auckland`, `GMT+05:00` and `UTC`.

**Behaviour change:** an application whose JVM does not run in UTC now sees
session-zone results in its own zone, as it would with pgjdbc or ojdbc. To
keep UTC, run the JVM with `-Duser.timezone=UTC`.

### The pool lets go of a connection, and takes one in

`SeclumePool.detach(handle)` gives up the connection behind a borrowed handle
without closing it: the handle is closed, the pool's cached statements for it
are closed, and the slot is free at once. `SeclumePool.adopt(connection)`
takes a connection the pool did not open, as borrowed by the caller; the handle
knows what differs from the pool's defaults, so returning it rolls an open
transaction back and resets auto-commit and isolation like any other borrow.
A full pool refuses to adopt rather than grow. `report()` names both when they
happened. `PoolHandOnSeamTest` holds the seam.

### A JDBC connection taken apart at the seam, and put back on the other side

`detach()` and `resume()` hand a driver *session* on. What applications hold
is a `java.sql.Connection`, and it keeps facts of its own that the server
session does not say. The seam now covers that layer on all four drivers:
`XxxConnection.facts()` reads them - auto-commit, read-only, isolation, and the
counters statements and savepoints are named by - and
`XxxConnection.resume(session, facts)` puts a connection on a resumed session
with them (`ConnectionFacts` in `space.seclume.internal.jdbc`). Found by using
it, each with a test at the seam:

- **Without the facts the resumed connection lied.** It reported the default
  isolation where another was in force; and on PostgreSQL its first prepared
  statement was named `seclume_1`, which the server still held - "prepared
  statement seclume_1 already exists".
- **A setting waiting to ride along was lost at the hand-over** on PostgreSQL
  and MySQL: `setAutoCommit(false)` and nothing after it, then `detach()` - the
  BEGIN (or `autocommit=0`) stayed in the object that gave the session up, and
  the other side ran in auto-commit while its connection said it did not.
  `detach()` now sends what is waiting first - one round trip, only when
  something waits. SQL Server refused the hand-over in that case; it sends it
  too now, so the four behave alike.
- **On SQL Server and Oracle a connection whose session had been handed over
  still believed itself open** and reached into buffers already given back:
  `IllegalStateException: Already closed` instead of JDBC's "closed" (08003).
  The channel reports itself closed once released, as on the other two.

### Fixed: Oracle's `releaseCursors()` rolled back the open transaction

`releaseCursors()` - what a session calls before `detach()` - returns cursors
as a piggyback, which needs a call to ride on. The call was a rollback, picked
as the one call that opens no cursor of its own. It also ended the transaction
the session was in: a session detached with an uncommitted row lost it without
a word. Found by handing over a session inside a transaction; every hand-over
tested before had been made between transactions. The piggyback rides on a
ping now (TTC function 147), which changes nothing on the server.
`LocalReleaseCursorsTest` holds it: the same transaction id afterwards, the row
still there, and still invisible to a second connection. Against the old code
it fails.

### A fetch size on every statement

Spring's `JdbcTemplate.setFetchSize`, Hibernate's `hibernate.jdbc.fetch_size`
and MyBatis' `defaultFetchSize` put a fetch size on *every* statement, writes
included. Two drivers did not survive that:

- **SQL Server** opened a server-side cursor for any prepared statement with a
  fetch size, and SQL Server refuses a cursor over an insert, update or delete
  (error 16938) - every write failed. A cursor is now opened only for a
  statement that returns rows (`select`, `with`).
- **MySQL** executed the write with a cursor - the row *was* written - and then
  failed fetching from a cursor that did not exist: an error reported after the
  change had happened. The prepare says how many columns a statement has; one
  with none is executed without a cursor.

And the gap named in the roadmap since 10.09. is closed: **on SQL Server a fetch
size now works with bind values.** It used to read the whole result - an
attempt with `sp_cursorprepexec` had failed with "procedure expects parameter
'params'", and the procedure number used then was 13, which is `sp_prepexec`.
`sp_cursoropen` takes the declaration and the values itself once
`PARAMETERIZED` (0x1000) is in scrollopt, and leaves no prepared handle to give
back. `FetchSizeEverywhereTest` holds all four to it: inserts with and without
bind values, update, delete and a bound query in blocks of three, under
auto-commit and in a transaction.

### No password at all: the client certificate is the login

`provider=none` says, in the configuration, that there is no password - for
PostgreSQL's `cert` method in `pg_hba.conf` and for a MySQL account created
with an empty password and `REQUIRE SUBJECT ... AND ISSUER ...`. Together with
`clientCert`/`clientKey-*`, or `clientCertThumbprint` on Windows, that is a
login in which no secret exists anywhere but the key, and the key does not
have to be in the process either. It is the SPIFFE case: an X.509-SVID the
agent rotates, and nothing else.

It is a word rather than a missing setting, because a missing setting is what
a mistake looks like: a URL that merely forgot the password still fails with
"no secret provider configured". PostgreSQL refuses locally, before anything
is sent, when the server asks for a password anyway - a server that asks has
not been set up for `cert` - and reports `cert` as the authentication method
when it did not ask. MySQL sends the empty answer, because an empty password
is how a certificate-only account is written there.

**A refused certificate now says so.** A server that does not accept the
client certificate sends an alert and closes, but it closes with the client's
Finished unread, the TCP stack answers with a reset, and the reset discards
the alert on the client side. What was left was "connection reset by peer",
which sends everyone looking at the network. Whether the reset meets the end
of the handshake, the first write or the first read is a matter of timing -
the test saw all of them - so all three now add that it came right after the
client certificate was sent and what to check.

Tested against PostgreSQL 16 and MySQL 8.4 in containers of their own, with a
test CA: the right certificate logs in, and the server is asked which one it
saw (`pg_stat_ssl.client_dn`, `current_user()`, `Ssl_version`); a valid
certificate for another name, the right name from a CA the server does not
trust, and no certificate at all are each refused; and `provider=none` where
PostgreSQL wants a password fails here with nothing sent. Repeated three times
for the timing above.

### Picking the server by what was measured about it

Every connection attempt through a host list is now measured, per server and
shared by the whole process: connect time and failure rate as moving
averages, consecutive failures with a back-off (1 s, doubling, at most 30 s),
and the role the server last reported. With `hostSelection=quality` the next
connection goes to the best of them: servers in back-off last - never
skipped, they are still the last resort - the rest by connect time weighted
by failure rate, a server whose last role is not the one asked for behind the
others, and ties in the order written.

A policy that always takes the best-known server never learns that another
one got better, so a figure older than a minute counts as none: that server
is asked once, first, and its new figure **replaces** the old one rather than
being averaged into it. The cost is one connect a minute to a slow or dead
server; the gain is that a node that was slow during a restart gets its
traffic back.

The default stays `ordered`, exactly what a list did before. Measured against
all four databases through `DriverManager`, which parses the URL afresh on
every call, with a dead server first in the list: `ordered` asked the dead
server on both connections, `quality` on the first only.

The figures are readable through `HostQuality.snapshot()`. **Not done:** query
latency (only the open is timed - a statement's time says as much about the
statement as about the server), and weighting by load rather than choosing
the best; `quality` sends every new connection to the best server, which for a
pool is what is wanted and for a fleet of short-lived clients may not be.

### A client key that never leaves Windows - or the TPM

`clientCertThumbprint` (and `clientCertStore=CurrentUser|LocalMachine`) names
a certificate in the Windows certificate store. Its key is used through
**NCrypt, by handle**: the identity asks for a signature and gets one, and
there is no call in it - nor one Windows would answer - that returns the key.
With a non-exportable key in the software provider it cannot be read out even
by the account that owns it; enrolled with the Microsoft Platform Crypto
Provider it is generated inside the TPM and never leaves it.

It needed nothing from the handshake: `ClientIdentity` signs rather than
holding a key, and always has.

Tested by enrolling a non-exportable ECDSA P-256 certificate with PowerShell,
running a real mutual TLS handshake against a JSSE server that trusts exactly
that certificate, asking Windows to export the key (refused), and removing
certificate and key again. The TPM case runs where a TPM is usable and is
skipped where it is not - including on the machine this was written on.

**Not covered:** PKCS#11 tokens and TPM2 on Linux (the same interface, a
different native API, and no hardware here to prove it on); intermediate
certificates from the store (only the leaf is sent); a renewed certificate,
which has a new thumbprint. And **GraalVM native image on Windows**: the
signatures are registered (see "All four in a native image" above), but no
Windows image has been built.

### A rotated client certificate, without a restart

A client identity configured with `clientCert` and `clientKey-*` now follows
its certificate file. When the file changes, the next handshake that is asked
for a client certificate loads the new certificate and key and presents them -
no restart, no new data source, nothing for the application to do.
cert-manager renewals, hourly SPIFFE SVIDs and a replaced Kubernetes secret
all take effect on the next connection.

- **The certificate is the signal.** It is public, so it is compared on every
  handshake that needs it; the key is read through its provider only when the
  certificate has changed.
- **A half-finished rotation breaks nothing.** The certificate often lands a
  moment before its key. That pair cannot sign for each other, the load is
  refused, and the identity that worked goes on working; the refusal is logged
  and recorded as a `space.seclume.CertificateReload` event, and the load is
  tried again a few seconds later.
- **One version per handshake.** The certificate sent and the key signing
  must belong together, so a handshake keeps the version it started with even
  if a rotation lands halfway through (`ClientIdentity.forHandshake()`).
- **The old key is released.** A replaced version is closed after a grace
  period for handshakes still under way, and its key leaves native memory then
  rather than at the next rotation.

Shown with two certificate authorities and a server that trusts only the
second: the handshake with the old certificate is refused, the files are
replaced, and the next handshake on the same identity is accepted.

**Not covered:** the server trust anchors are read from the JVM's trust store
on every handshake, so whether a changed trust store is picked up is the JDK's
behaviour and has not been tested here.

### A commit whose outcome is unknown says so

A commit has three outcomes, and most drivers report two. It succeeded; the
server refused it; or **the answer never came back** - the connection was lost
while the COMMIT was in flight, and the server may have applied it a
microsecond before the network failed.

That third case used to arrive as an ordinary connection failure, which
invites the worst response to it: run the transaction again. It is now
`TransactionResolutionUnknownException`, with SQLState **`08007`** - the state
SQL reserves for exactly this, *transaction resolution unknown* - so code and
frameworks can branch on it by type or by state. `Retry` never repeats one.

All four drivers raise it from `commit()` and from `setAutoCommit(true)` with
a transaction open, which JDBC defines as a commit. A commit the server
**answered** keeps the server's own state: a deferred constraint that fails at
commit is still `23505`, because that outcome is known.

Proven rather than inferred, on all four: a relay in front of the server lets
the COMMIT through and drops the answer, the client gets `08007` - and a
second connection then finds the row. The transaction reported as unknown had
been committed, which is the whole reason it must not be reported as a plain
failure. With the classification switched off the same test fails on all four.

**And a write in auto-commit mode is the same case.** There every statement
commits itself, so a write whose answer is lost is a commit whose outcome is
unknown with the COMMIT left implicit - `08007` as well, from single statements
and from batches alike. Two things are deliberately left alone:

- **A read.** A lost answer to a `select` changed nothing. Whether a statement
  reads is decided by its first keyword, and every doubt goes towards "it may
  write": `select ... into` writes (a table, or a file on MySQL), a `with`
  whose body inserts, updates, deletes or merges writes, and `call`, `exec`, a
  block or anything unrecognised may write. So does **any call to a function
  that is not a known pure built-in** - `select create_order(42)`, which is how
  PostgreSQL code calls a function that does something, and
  `select archive(id) from orders` alike. The built-ins that compute and write
  nothing (aggregates, string, number, date and window functions) stay reads;
  `nextval`, advisory locks and every function somebody wrote do not. The rule
  can only err towards "may write", which costs a needless check.
- **A write inside a transaction.** The transaction dies with the connection
  and the server rolls it back, so that outcome is known.

`ChaosBenchmark` now reports what the client was told as well as what the
server has. On all four, the one write the cut left in doubt was reported as
unknown, and *in doubt and not told so* - the number that has to be zero - is
zero.

### Fixed: MySQL lost a transaction on `setAutoCommit(true)` and `close()`

JDBC says switching auto-commit on during a transaction commits it. The MySQL
driver announced the switch and sent it with the next statement, to save a
round trip - which is right as long as there is a next statement. When there
was not, the server saw the connection go away with a transaction open and
**rolled it back**: `setAutoCommit(false)`, an insert, `setAutoCommit(true)`,
`close()` left zero rows, and nothing anywhere said so.

It commits now, on the spot, whenever the server's own status flags say a
transaction is open, and that commit is classified like any other - a lost
answer is `08007`. With nothing open the switch is still deferred, because
then it has nothing to lose. PostgreSQL, SQL Server and Oracle already sent it;
all four are now checked by the same test.

Found while working out what the deferred switch meant for the outcome of a
commit. The question was about a classification; the answer was a data loss.

### What a credential rotation costs, measured

`RotationBenchmark` in `seclume-bench`: a pool under continuous load across a
lease ending and the next one beginning, with two numbers out the other end -
how long the pool took to turn over, and **how many requests failed while it
did**. The second is what the README claims, and a claim about a rotation
that has never been measured under traffic is a sentence.

| | requests in flight | failed | turnover | first retirement, ahead of the lease |
|---|---|---|---|---|
| PostgreSQL | 4488 | **0** | 475 ms | 2437 ms |
| MySQL | 3822 | **0** | 411 ms | 2437 ms |
| SQL Server | 3570 | **0** | 410 ms | 2459 ms |
| Oracle | 3944 | **0** | 458 ms | 2438 ms |

Six connections, margin two seconds, spread narrowed to 500 ms for the
measurement (the production default is a minute, which is deliberate and
would make the run describe the width of a random window instead of the cost
of a rotation). What is rotated is the **expiry the pool is told about** -
the signal a Vault lease or an IAM token gives it - and not the password in
the database, which no line of the mechanism depends on.

### Fixed: a lapsed credential on a busy pool

Found by that benchmark on its first honest run: six threads on six
connections across an expiry, **four retirements out of six and then nothing
for thirty seconds**.

Every retirement happened in the idle sweep, and the sweep can only retire a
connection it finds sitting in the pool. A pool under load has none sitting -
a returned connection is claimed again long before housekeeping's next round.
So the case where an expired credential matters most, a busy application, was
the one where nothing retired it, and the connection went out again until the
server refused it.

Housekeeping now marks a borrowed connection whose credential has lapsed, and
the mark is honoured where the connection comes back - the same mark a secret
rotation already used, so nothing was added to the return path. Prewarming
counts those connections too, so their replacements are opened before they
go, as it already did for idle ones.

### What a failover costs, not how often one happened

`space.seclume.Failover` is now a **timed** event, and carries the attempt
number. It used to be a bare count, and a count cannot answer the question an
operator has after a switchover: where did the twenty seconds go? A server
that refuses a connection costs a millisecond; a server whose packets are
dropped silently costs the whole connect timeout, spent inside
`getConnection` with nothing to show for it. In a count those two are the
same number.

The clock starts before the attempt rather than when it fails, so what is
recorded is how long that server took to not answer. An attempt that works is
not a failover and commits nothing.

`seclume.failover` in Micrometer changed with it, from a counter to a timer -
a timer carries the count too, so nothing is lost and the distribution is
gained.

### The login, timed on its own

A new Flight Recorder event, `space.seclume.Authentication`, around the login
and nothing else - not the connect in front of it and not the TLS handshake
between them. All four drivers raise it; the seam is different in each
(PostgreSQL's startup message, MySQL's handshake response once the plugin is
known, TDS's LOGIN7, Oracle's second O5LOGON).

**Why it is worth a separate event.** The three phases of an open are slow for
three different reasons - the network, a certificate chain and whatever the
JVM has to look up to trust it, and the directory behind the database - and
`ConnectionOpen` gives an operator one number covering all three. Against the
four local servers here the split is not the same twice:

| | login | whole open |
|---|---|---|
| PostgreSQL (`tls=off`) | 134 ms | 145 ms |
| MySQL (`tls=off`) | 2.8 ms | 5.0 ms |
| SQL Server (TLS) | 4.8 ms | 68 ms |
| Oracle | 160 ms | 177 ms |

Three of them spend most of an open logging in. SQL Server spends most of it
on the handshake. That is the difference between tuning the database's
authentication and tuning the certificate path, and it was not visible before.

The event carries the kind, the server, whether it succeeded, and the method
by the server's own name - `scram-sha-256`, `caching_sha2_password`,
`login7`, `o5logon`. Nothing derived from what was sent back: not the
secret, not its length, not a hash. A test asserts the field list, so a
fifth field added later fails until somebody has thought about it.

### A preflight check a pipeline can read

`seclume-verify` takes `--json` in front of the URL and prints the same report
as one JSON object on stdout and nothing else - for a build step, or for a
readiness probe that wants a field rather than a paragraph.

```
java -jar seclume-verify.jar --json "jdbc:seclume:postgresql://db:5432/app?user=app&provider=file&path=/run/secrets/db"
```

```json
{
  "tool": "seclume-verify",
  "ok": false,
  "status": 1,
  "sections": {
    "seclume_verify": { "url": "...", "driver": "...", "secret": "file, path=/run/secrets/db  (not read here)" },
    "connect": { "failed": "after 4 ms", "state": "08001", "said": "..." }
  },
  "problems": ["..."]
}
```

The exit code does not change and remains the contract: **0** the connection
stands, **1** it does not, **2** the tool was called wrongly. `ok` is that
code said a second time, and it is deliberately **not** "are there problems":
a connection that stands with notes against it exits 0 and reports `ok: true`
with its notes beside it. A tool that turned a note red would teach people to
stop writing notes.

Keys are slugs of the labels in the text report - `round trips counted`
becomes `round_trips_counted` - and values stay the sentence a person would
have read. Typed fields per probe were the alternative and were declined: the
document would change shape every time a probe is added, and every consumer
with it.

And the same rule as everywhere else: **no secret reaches the document.** It
is built from the lines of the text report, which take a password out of the
URL - and that is a test rather than an inference.

### Fixed by reading that tool's own output

A URL carrying `password=` is refused by the driver before any server is
asked, and arrives as a connection failure with SQLState `08001`. Read by
state alone that produced the advice *"the server was not reached at all -
check host, port and firewall"*. All three were fine and nothing had been
dialled. `seclume-verify` now recognises a refused setting and says so: the
option in the URL is what to fix.

### Fixed, and it is what made the above possible

**Oracle reported every statement failure as SQLState 42000**, which means
*syntax error or access rule violation*. A deadlock said 42000. A unique
constraint said 42000. A statement the caller cancelled said 42000. Anything
reading the state - a retry, a duplicate-key branch, a framework's exception
translator - got the wrong answer and got it confidently.

Oracle sends no SQLState of its own, so the error numbers are now mapped the
way SQL Server's already were: the ones a caller branches on (ORA-00001,
ORA-00060, ORA-08177, ORA-01013, ORA-00942, ORA-12899 and the rest) become
their standard states, and anything unclassified is `HY000` - because an
unclassified error is not a syntax error, and saying so was the original
mistake.

### Added

- `Retry` - see above.
- `Secured` - `authenticationMethod()` and `tlsDescription()` for a live
  `Connection`, so an application can state how it authenticated rather than
  assume.
- `FRAMEWORKS.md` and `COMPATIBILITY.md`, generated from the surefire reports
  of an actual run. A server that was not reachable says so instead of
  counting as a pass.
- `BENCHMARKS.md`, recorded by `seclume-bench` from JMH's JSON together with
  the machine and JDK it ran on.
- Nightly workflows for the full fuzz corpus and for the benchmarks.
- `seclume-verify --json` - see above.
- `space.seclume.Authentication` - see above.
- `TransactionResolutionUnknownException` (`08007`) - see above.
- `ClientIdentity.forHandshake()`, and the `space.seclume.CertificateReload` event - see above.
- `azure-managed-identity` and `gcp-metadata` providers; `SecretFetch.sendLinkLocal` - see above.
- `WindowsStoreClientIdentity`, configured by `clientCertThumbprint` - see above.
- `provider=none` (`NoSecretProvider`) for a login by client certificate alone - see above.
- `hostSelection=ordered|quality`, `HostQuality` - see above.
- JDBC escape processing (`JdbcEscapes`); `prepareCall` with plain SQL
  (`QueryAsCallable`); savepoints on PostgreSQL; `DataSource.setUrl(url,
  properties)` on all four - see above.

### Changed

- `space.seclume.Failover` is timed and carries the attempt number, and the
  `seclume.failover` meter is a timer rather than a counter - see above.
- A PostgreSQL connection that fails during startup names the cause in its
  message rather than only in `getCause()`.
- `FRAMEWORKS.md` has rows for Hibernate's edges, Spring JDBC and its
  transactions, Spring Data JDBC, Liquibase, jOOQ and MyBatis, each from a test
  class per server; a class that was partly skipped says "n skipped" instead of
  counting as verified.

## [0.9.0] - 2026-09-22

The first published artifact, and the version number is the point: **0.9.0 is
not 1.0.0, deliberately.** Everything below works and is tested against real
servers, but three things a 1.0 should be able to claim are not true yet, and
they are listed under [Not yet](#not-yet-and-why-this-is-090) rather than
glossed over.

### What this is

Four JDBC drivers and a connection pool for PostgreSQL, MySQL, SQL Server and
Oracle, written from the wire protocol up, with one defining property:

> **A secret never becomes a `String` or a `char[]` on the Java heap.**

Credentials are read from a provider straight into off-heap memory, used where
the protocol needs them, and wiped. A heap dump of an application using these
drivers does not contain the database password, because the password was never
an object that a dump could find. `seclume-heapcheck` exists to prove that on a
running process rather than to assert it in a comment.

No runtime dependency beyond the JDK. Java 25.

### Modules

| | |
|---|---|
| `seclume-core` | secret providers, off-heap buffers, the TLS 1.3 client, the JDBC scaffolding |
| `seclume-postgresql`, `seclume-mysql`, `seclume-sqlserver`, `seclume-oracle` | the four drivers |
| `seclume-pool` | a connection pool that understands credential lifetimes |
| `seclume-spring-boot-starter` | auto-configuration, JFR-to-Micrometer metrics, tracing |
| `seclume-verify` | a preflight command: does this configuration actually connect, and how |
| `seclume-heapcheck` | reads a live heap and reports whether a secret is in it |
| `seclume-bom`, `seclume-tck`, `seclume-bench`, `seclume-diff`, `seclume-spring-test` | dependency management, the shared test kit, benchmarks, the differential harness against the vendor drivers |

### Secrets

- Providers for a file, an environment variable, a Unix domain socket, an
  encrypted file, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault and
  Google Secret Manager - **none of them through a vendor SDK**, so none of
  them drags a dependency or a `String` in with it.
- Vault leases and AWS temporary credentials are understood: a connection is
  retired before its credential expires rather than after it fails.
- `secret-uri` in a JDBC URL, and a guard that refuses a plaintext password in
  one.
- The wipe is proven on the failure paths, not only the happy one - a login
  that is rejected, a connection that dies mid-handshake, a server that is not
  there at all.

### TLS

- Two stacks, chosen per connection with `tlsStack`: the JDK's `SSLEngine`, or
  **seclume's own TLS 1.3 client**, where every traffic secret lives in native
  memory.
- mTLS with a client key that never becomes a Java object.
- Channel binding (SCRAM-SHA-256-PLUS) on both stacks.
- TDS 8.0 for SQL Server, which is the only route by which that driver reaches
  the own stack - and therefore the only route to a client certificate there.
- Oracle over TCPS.
- The own stack is checked against the RFC 8448 vectors, against JSSE, and
  against all four real servers.

### The drivers

- Every driver has `CallableStatement`, named parameters, XA, `DatabaseMetaData`,
  procedures that return rows, and a pipeline block that puts a unit of work in
  one round trip.
- Result rows are read **in place** out of the receive buffer - a thousand rows
  cost a handful of system calls and no copies.
- Statement caching per connection, with an eviction that gives the server its
  cursors back rather than leaking them.
- `targetServerType=primary|secondary` over a host list, with a per-engine probe
  for what a server says it is.
- A `QueryFingerprint` that names a statement's shape and carries none of its
  values.

### Observability

- JFR events for statements, the cache, failover and TLS, with no runtime
  dependency.
- The Spring Boot starter bridges those to Micrometer and to tracing spans.
- `StatementListener`, the one hook in the statement path, for a span that needs
  the caller's thread context.

### Testing

1695 tests. CI runs against PostgreSQL 15 and 18, MySQL 8.4, MariaDB 11.4,
SQL Server 2022 and 2025, Oracle Free 23ai, CockroachDB and YugabyteDB.

The vendor drivers are used as the oracle in a differential harness: the same
statement, the same server, both drivers, and any disagreement is a defect
here. It found eight.

### Also in this release

- **A session can be handed from one holder to another.** `detach()` gives up
  an authenticated stream and `resume()` picks one up, so a login can happen
  once, where the credential is, and whoever receives the stream never needs
  one. On seclume's own TLS stack the encryption goes along with it; on the
  JDK's it cannot, and the refusal says why. What anybody builds on that is
  their business - this library provides the join.
- **`OracleSession.releaseCursors()`.** `detach()` refuses while cursors are
  open and told callers to close them, and nothing here offered a way. Now it
  does, at the cost of one round trip.
- **Fixed:** `close()` on all four channels ignored a channel that had been
  given up, and so closed the socket it had just handed over.

### Not yet, and why this is 0.9.0

| | |
|---|---|
| **The wire parsers are not fuzzed.** | Four protocols are parsed here by hand, and every one of those parsers reads a length and then trusts it. The property tests are good at valid values and at edges; they are not an adversary. A 1.0 for a library whose argument is byte-level correctness should be able to say it has been attacked. |
| **The compatibility matrix is prose, not generated.** | The list of servers above is written by hand next to the run instead of produced by it, so it can drift from it. |
| **The benchmark numbers are not reproducible by a reader.** | The figures in the README are real and were measured, but without the hardware, the server configuration, the warm-up, the repetitions and the raw data beside them they ask to be taken on trust. |

The API may still change before 1.0.0. It changed on the day of this release.

### A note on this registry

GitHub Packages requires a token even to **read** a public package. That is a
property of the registry, not of this project. A dependency that should simply
resolve belongs on Maven Central, and that is where 1.0.0 will go.

[0.10.0]: https://github.com/Seclume/seclume/releases/tag/v0.10.0
[0.9.0]: https://github.com/Seclume/seclume/releases/tag/v0.9.0
