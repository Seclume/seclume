# Code reviews

What has been reviewed in seclume, what was found and where it was fixed - and what was looked
at and found sound. This is a record of **internal** reviews by the maintainers, done with an AI
assistant (Claude); it is not an external audit. seclume has had none yet - [AUDIT.md](AUDIT.md)
is the guide for one, and [SECURITY.md](SECURITY.md) says how to report what you find.

**How a review is done here.** A component is read against what it claims (its Javadoc,
[FEATURES.md](FEATURES.md), [THREAT-MODEL.md](THREAT-MODEL.md)) and against the protocol or
format it speaks: the RFC, the wire format, the server's documented behaviour. The questions
are always the same - where can a secret reach the heap, a log, a file, another server; what
does a hostile peer, a hostile value from the application's own users, or a heap dump in the
wrong hands get out of it; where are lengths and bounds believed rather than checked. Every
finding is fixed in a pull request of its own with a regression test, and where it can be
shown, that test fails on the code before the fix. What was looked at and found sound is
listed too, so that the next review knows what has been covered and how.

**Severity** is the reviewers' judgement, not a CVSS score:

- **high** - a secret reaches someone it must not, or an attacker gets something the threat
  model says they must not (a login, another tenant's data), with nothing but what they
  already control;
- **medium** - the same, but only with a further precondition (a heap dump, a misconfiguration,
  a hostile server); or a protection the documentation promises does not hold;
- **low** - robustness: a hostile or broken peer gets an exception instead of a refusal, a
  resource is held too long, a limit is missing;
- **process** - nothing wrong in the shipped code, but a check the documentation counts on
  does not run.

## Round 1 - 6 and 7 November 2026

Scope: the secret sources, the TLS client's record and handshake paths, the drivers' row
decoders, every module that writes a secret into another protocol in place of a placeholder,
the pool's reset, the heap-dump redaction, log masking, the admission webhook, checkpoints.

### Findings

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | LDAP | The placeholder JNDI holds was a counter (`...:1`) and was replaced in **any** simple bind. Typed into a Spring Security login form it bound as the service account; with `authentication=kerberos` the socket ran the service's bind and reported success for any user; one registration's password went to another registered server. | high | #233 |
| 2 | SMTP | Envelope addresses went into `MAIL FROM`/`RCPT TO` unchecked: a recipient with a line break sent further commands in the logged-in session (more recipients, a `DATA` of its own). | high | #237 |
| 3 | Heap-dump redaction | A password beyond ASCII lies in a compact `String` as Latin-1, which was not looked for - it stayed in the "redacted" copy, and the final check passed it. The tests' `NoSecretInHeap` had the same gap. | high | #247 |
| 4 | Pool | `setCatalog`/`setSchema` stayed where the last borrower took them; MySQL's reset keeps the database, a foreign driver resets nothing - the next borrower got another tenant's schema. | high | #239 |
| 5 | HTTP (JGit, Kubernetes, gRPC, Elasticsearch) | A placeholder's secret was written into a request to **any** host: a submodule's host from `.gitmodules`, a redirect's. | high | #243 |
| 6 | Checkpoints (CRaC, SnapStart) | Field key rings, the log masker and secret watches held keys for the application's lifetime: `seclume-crac` refused every checkpoint, and without it the image held the data keys and keyed tags that test password guesses offline. | high | #248 |
| 7 | Redis | The password was written in wherever the placeholder stood, not only in the password argument of `AUTH`/`HELLO` - a value the application stores could carry it into Redis. | medium | #220 |
| 8 | AWS | The session token likewise, outside its `X-Amz-Security-Token` header. | medium | #221 |
| 9 | HTTP | Credentials were written into the request target (path, query), where users' input goes and which servers log and echo. | medium | #222 |
| 10 | NATS | The password went into the first placeholder of the `CONNECT` line - the connection's `"name"`, which the server logs, if it held one. | medium | #234 |
| 11 | SCRAM | The iteration count is the server's to choose; a low one makes the client's proof cheap to brute-force. Now at least 4096 (RFC 7677), configurable. Before that, a count of more than eight digits wrapped. | medium | #223, #213 |
| 12 | JWT | A token was accepted in a form other than the one it is signed in (padded or non-canonical base64url), and an unknown `crit` header was not refused (RFC 7515). | medium | #228 |
| 13 | TLS | A decrypted record stayed in its buffer after it was read; the server's `CertificateRequest` was read leniently. | medium | #216, #217 |
| 14 | MySQL, Oracle | A row's cells (MySQL) and a row (Oracle) were not held to the bounds of the answer they are in. | medium | #219, #225 |
| 15 | Secret sources | `SecretFetch` did not check a chunk's CRLF and took other transfer codings; `HostnameMatch` resolved an IPv6 literal through DNS; Vault transit refused a secret of exactly its maximum length. | medium | #211, #212, #210 |
| 16 | Local secret sources | `provider=process` in its standard-output form deadlocked; a helper or agent that never answered blocked for ever. | medium | #230 |
| 17 | R2DBC | The placeholder rewriting read past PostgreSQL `E'...'` and Oracle `q'[...]'` literals and into identifiers such as `col$1`. | medium | #236 |
| 18 | Admission webhook | Its `JAVA_TOOL_OPTIONS` replaced what a container took from a ConfigMap through `envFrom`. | medium | #238 |
| 19 | Log masking | A secret was found only as itself and its padded Base64 - not in a Basic header, percent-encoded, JSON-escaped or unpadded. | medium | #246 |
| 20 | OAuth | A token's announced lifetime was believed up to overflow; now at most a day. | low | #229 |
| 21 | RabbitMQ | The lengths in `Connection.Start-Ok` were believed: an index exception instead of a refusal, and the socket left open. | low | #232 |
| 22 | SSH | Asked for another key type's algorithm, the JSch identity threw instead of declining. | low | #235 |
| 23 | PostgreSQL | A `DataRow` with more or fewer values than its `RowDescription` has columns was read as far as it went. | low | #252 |

### Reviewed, nothing found

- **Kafka**: the SASL rewriter's framing and its placeholder slot.
- **MongoDB**: `BsonReader` against hostile documents; the handshake's SCRAM.
- **Field encryption**: AES-GCM-SIV with the key commitment, the HKDF derivation per column.
- **OAuth**: the client assertion (`private_key_jwt`).
- **SQL Server**: TDS encryption negotiation - tolerable as documented.
- **Windows**: DPAPI and Credential Manager zero before they free.
- **Mail**: IMAP, POP3 and SMTP login - STARTTLS refuses bytes sent ahead of the handshake, the
  password goes as an IMAP literal, SASL PLAIN and XOAUTH2 are built in native memory.
- **NATS**: NKey seed decoding, CRC and signing.
- **Admission webhook**: its JSON parser and the JSON patch it answers with.
- **Heap dumps**: `DumpFolder` - finished dumps only, the original deleted only after a clean
  copy.

### Accepted residuals

- **macOS Keychain**: the `CFData` holding a secret is released without being zeroed: writing
  through Apple's `const` pointer risks a crash. The copy seclume makes is wiped.
- **LDAP**: whoever has the placeholder (from a heap dump) and can make the application bind as
  the service account's own DN still gets that bind; the wire cannot tell the two apart.
- **Log masking**: in a Basic header, the one or two Base64 characters the password shares with
  its neighbours stay visible.

## Round 2 - 7 November 2026

Scope: the tools around the drivers (`seclume-verify`: the report, `--print-pin`, `--migrate`,
`--split`), the framework integrations' password checks (Spring Boot, Micronaut, Helidon,
Quarkus), `seclume-gcp`, `seclume-azure`, `seclume-opentelemetry`, and the question left open
in round 1: what the drivers send under the default `tls=prefer`.

### Findings

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | `seclume-verify --print-pin` | It connects without checking the certificate, because the key is what it wants to find out - and then logged in: the secret was read and sent to whoever had answered. | high | #256 |
| 2 | PostgreSQL, MySQL | The password itself - PostgreSQL's `password` method (and `ldap`, `pam`, `radius`), MySQL's `caching_sha2_password` full path, `sha256_password`, `mysql_clear_password` - went over TLS that checked no certificate, the default `tls=prefer`; PostgreSQL's even without TLS. A server in the middle asked and got it. Now only with `verify-full` or `tlsPin`; MySQL has an opt-out. | high | #258 |
| 3 | `seclume-verify --migrate` | Printed passwords: Connector/J's `user:password@host` and key-value hosts, a braced mssql-jdbc value split at its `;`, an Oracle password with an `@`, the first 30 characters of an unknown URL. mssql-jdbc property names in another case were not recognised, so `TrustServerCertificate=true` was not called unsafe. The report's URL line kept nested secret settings (`token-value=`). | medium | #253 |
| 4 | Spring Boot, Micronaut, Helidon | The password checks matched property names only; a password in an environment variable (`SPRING_DATASOURCE_PASSWORD`, `DATASOURCES_DEFAULT_PASSWORD`, `JAVAX_SQL_DATASOURCE_..._PASSWORD`) - how containers pass one - was never named. Micronaut's also missed Hikari's `data-source-properties.password`. | medium | #254 |
| 5 | Quarkus | The datasource password was refused only at build time, but it is a runtime property: the environment, a `config/application.properties`, a mounted secret were never checked. | medium | #255 |
| 6 | `seclume-verify --split` | A split that failed at a later file left the earlier shares on disk while saying "no shares written"; on Windows a share took its directory's ACL; the shares were held in memory that is neither locked nor kept out of core dumps. | medium | #257 |
| 7 | `seclume-crac` | Private keys in OpenSSL's or CNG's memory - a TLS server's or client's, a service account's, SSH and JWT signing keys - stayed for the life of the application and were not counted: a checkpoint was taken with them in the image while FEATURES.md said nothing secret was left. | medium | #261 |

### Open

None. The question left here - private keys in a checkpoint image - was decided on
8 November 2026: a key that can be read again from its source is freed before the checkpoint
and read again on first use after the restore; one that cannot makes `seclume-crac` refuse the
checkpoint (#261).

### Reviewed, nothing found

- **GCP**: the service account file is read by a provider into native memory, `private_key`
  unescaped there and decoded by OpenSSL at once; the public fields are bounded.
- **Azure**: the Shared Key policy decodes the account key into native memory per request and
  wipes it; the string to sign matches the SDK's (tested request by request).
- **OpenTelemetry**: the access log exporter and the metrics carry facts, statement shapes and
  counts, never a value.
- **`seclume-keys`**: `SeclumeKeys.privateKey` reads a key once and closes its provider.

## Round 3 - 8 to 12 November 2026

Property and model tests of the parsers that decide where a secret goes, then the modules
the last round named and the rest of the network-facing ones: `seclume-keys`, `seclume-jwt`,
the admission webhook's server, the access log, `seclume-diff`, `seclume-http`,
`seclume-mail`, `seclume-ldap`, `seclume-r2dbc`, `seclume-redis`, `seclume-kafka`,
`seclume-nats`, `seclume-rabbitmq`, `seclume-ssh`, `seclume-elasticsearch`, `seclume-grpc`,
`seclume-jgit`, the cloud providers (`seclume-aws`, `seclume-azure`, `seclume-gcp`), and of
MongoDB the URL, the SRV lookup and the logins, and of its driver the wire, the sessions,
the topology, cursors, change streams and bulk writes. A finding was reproduced by a test
that failed before its fix, with these exceptions, which have a test that passes with the
fix and was not run against the code before it - there are no MongoDB libraries where the
fixes were written: #19 and #20 (#299), #21 and #22 (#300), #26 (#304). #17, #23 and #24
are about time, and were measured before and after.

The first run of the differential tests in CI (#286, run 42982946717) found no difference
between seclume and pgjdbc, mssql-jdbc or ojdbc; MySQL's two failures were a test's own URL.

### Findings

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | `seclume-http` | A chunked body was recognised by `transfer-encoding: chunked` with exactly one space. `chunked` without one, after a tab, or after `gzip,` was taken for no body - and a request-like text in the body for the next head, with the secret written into it: into a document the server stores. Found by a model test. | high | #273 |
| 2 | URLs in messages | `JdbcUrl.redact` hid only `?key=value`: a password in the authority (`app:pw@db`), Oracle's `scott/pw@`, SQL Server's `;password=`, MySQL's `(password=...)` came back verbatim in every "not a seclume URL" message and Spring Boot's diagnosis; `parse` took `user:pw@host` for a host. Found by a property test. | medium | #266 |
| 3 | Admission webhook | The JDK's HTTP server has no request timeout and served on a fixed pool: a few connections that send nothing held every thread, the API server's calls timed out, and with `failurePolicy: Ignore` pods went in unchecked. | medium | #282 |
| 4 | Access log | A log opened again continues its chain, and its next checkpoint signed over entries someone had appended, correctly chained, while the application was down; the verifier called them vouched for. `log.opened` now names the last signed entry and the verifier the ones after it. | medium | #284 |
| 5 | `seclume-keys` | A Vault PKI or SPIFFE key replaced by a renewal was freed by a timer a minute later - and not at all by a checkpoint or a close in that minute: in the image, and in OpenSSL's memory after close. | medium | #263 |
| 6 | `seclume-keys` | A pair pushed by the SPIFFE agent, or renewed on its timer, between a checkpoint and the first use after the restore was installed with its key; the restore then installed another and forgot that one without freeing it. Found by a flaky CI run. | low | #285 |
| 7 | `seclume-jwt` | An EC key on another curve than the algorithm names (P-384 for `ES256`) signed tokens RFC 7518 forbids. | low | #283 |
| 8 | Oracle | `getColumns` said `Y`/`N` for `IS_NULLABLE` and gave a character column's size in bytes. | low | #287 |
| 9 | `seclume-http` | A request head whose secrets came to more than twice the head and 64 KB ended in an `IndexOutOfBoundsException` out of the socket's `write` (bounds-checked; nothing overwritten). | low | #288 |
| 10 | `seclume-r2dbc` | On PostgreSQL a bind index was the i-th placeholder present, so in `$1 ... $3` index 1 bound `$3`, and `$01` and `$1` were two parameters. | low | #289 |
| 11 | PostgreSQL | The application's own `DISCARD ALL` or `DEALLOCATE ALL` dropped every prepared statement on the server, and the driver went on using its cached plans and those of open statements: each failed with `prepared statement "seclume_1" does not exist` until the connection was closed. | low | #291 |
| 12 | `seclume-redis` | A server that does not know a command answers with its arguments: Redis 5 has no `HELLO`, and gave the password of Lettuce's `HELLO 3 AUTH user password` - written in from native memory - back in its error. Lettuce made a `String` of that line, the message of an exception; so did the login for Jedis of a server without `AUTH`. Errors that follow a password are now searched for it before the client reads them. | medium | #293 |
| 13 | `seclume-kafka` | The CA certificates of a JKS or PKCS12 trust store were written to a file in the temporary directory and read again at every connection: a cleaner that removed it ended every reconnect, and a file someone else wrote under that name decided whom the client trusts. | low | #294 |
| 14 | `seclume-nats` | Over `nats://` without TLS the `CONNECT` line, the password written into it in native memory, went to the socket's stream through a heap array that was left as it was. | low | #295 |
| 15 | `seclume-diff` | The differential tests against pgjdbc, Connector/J, mssql-jdbc and ojdbc skip without a server, and no CI job started one: of the module CI ran `PgBouncerTest` alone, while TESTING.md and SECURITY-QUALITY.md said every pull request. Oracle's `getColumns` was never compared, in addition (#8). | process | #286 |
| 16 | `seclume-aws` | A source that answered with temporary credentials already within five minutes of their end - the instance metadata service, until it has the next - was asked again for every request. Each answer was a new generation, three are kept, and the fourth request closed the credentials the first had just been signed with: its head was refused, "credentials are gone". The core's `AwsInstanceRole` asked the metadata service for every use under its lock. | low | #296 |
| 17 | `seclume-aws` | `SessionTokenSocket` copied a request's whole head for each byte of it (241 µs of CPU for 1500 bytes, 4.4 µs now) and wrote a chunked body's framing a TLS record per byte. | low | #296 |
| 18 | `seclume-mail` | The same as #12 for SMTP, POP3 and IMAP: a server that answers a line it did not understand with that line gave the password back, and every reply line became a `String`, a refusal the message of an exception. Lines that follow a credential are now searched for it in native memory, as it was sent and as it is, until the login is over. | medium | #298 |
| 19 | `seclume-mongodb-driver` | The largest reply was whatever the `hello` named as `maxMessageSizeBytes` - answered before the login - and a reply's announced length is allocated once it is below that: a server naming 2 GB had the client allocate 2 GB for a 16-byte header. Capped at the 48 MB of every server. | low | #299 |
| 20 | `seclume-mongodb-driver` | A document named `cursor` inside the application's data was read like the reply's cursor: its `firstBatch` documents came back immutable. | low | #299 |
| 21 | `seclume-mongodb-driver` | The monitor - one thread for all servers - read a `hello` outside its `try`: one with a field of an unexpected type (`tags`, `hosts`, `electionId`, a member that is no address) threw through the thread and ended it. No server was looked at again for the life of the client. | medium | #300 |
| 22 | `seclume-mongodb-driver` | `close()` waited `serverSelectionTimeoutMS` for a server to end its sessions on, when none was known. | low | #300 |
| 23 | `seclume-http` | The same as #17 where every HTTP client goes through: the head collected so far was copied for each byte of it (316 µs for a head of 1491 bytes, 15 µs now), chunk framing went a TLS record per byte. | low | #301 |
| 24 | `seclume-redis` | The follower that finds the password's place looked at every byte a connection writes, a value's too: 351 µs of its own for a `SET` of 64 KiB, 0.5 µs now. | low | #302 |
| 25 | `seclume-mongodb-driver` | A client `bulkWrite` without a session of the application's ran in a server session that was given back with the command's reply; a `getMore` for results that did not fit that reply named no session, and the server refused it (error 13, in the CI with the test alone). | low | #303 |
| 26 | `seclume-mongodb-driver` | A batch too large for one message was encoded whole to find that out, halved, and encoded again - from the limit for every part. | low | #304 |
| 27 | `seclume-mongodb-driver` | `hasNext()` of a change stream looped on a cursor the server had closed - after the `invalidate` that follows a dropped collection - and never returned: a thread spinning on a CPU (the CI jobs with the test alone did not end). | medium | #305 |
| 28 | `seclume-diff`, `seclume-oracle` | The differential run's comparison of the catalogue looked columns up in lower case; Oracle has them in upper case, neither driver had a row, and that counted as agreement. Compared at last, `getColumns` said `VARCHAR` for an `NVARCHAR2` column where the result set's metadata and ojdbc say `NVARCHAR`. | low | #309 |
| 29 | `seclume-mongodb-driver` | Every failed `getMore` was taken as the server's refusal and the cursor's id forgotten. After a lost connection or a timeout on this side the server still held the cursor, and `close()` did nothing: it stayed open there until the idle timeout. | low | #311 |
| 30 | `seclume-mongodb-driver` | An aggregation ending in `{ $merge: "name" }` - the short form - wrote, and then failed reading its results back: only the document form was expected. | low | #311 |
| 31 | `seclume-mongodb-driver` | `dropIndex` and `dropIndexes` passed on the server's NamespaceNotFound for a collection that is not there, where `drop()` does not. | low | #311 |

### Open

- Making `differential.yml` a required check once it has been green for a while (#286).

### Reviewed, nothing found

- **Key files** (`seclume-keys`): OpenSSL's decoder is given no passphrase callback that
  could fall back to a prompt; `NativeKey` wipes what it decoded; the PEM and DER readers are
  fuzzed (`KeyFilesFuzzTest`).
- **JWT verification** (HMAC tokens only - a public key needs no secret handling): the
  header's `alg` must be the key's own, so `none` and another algorithm are refused; `crit`
  is refused; every part must be base64url as RFC 7515 writes it, so one token has one
  spelling; the MAC is compared in constant time (`MessageDigest.isEqual`).
- **Mail**: SMTP, IMAP and POP3 refuse a server without STARTTLS, and bytes it sent after its
  answer to STARTTLS and before the handshake; a login over `tls=none` is refused at
  configuration. Envelope addresses refuse line breaks and angle brackets; DATA makes every
  line end CRLF and doubles a leading dot, so no message ends early (SMTP smuggling). IMAP's
  `LOGIN` sends the password as a literal; POP3's `PASS` refuses one with a line break.
- **LDAP**: StartTLS refuses a refusal and bytes before the handshake; the bind is rewritten
  only for the placeholder's own bind DN on its own server, its BER lengths computed again and
  any length JNDI does not write refused.
- **HTTP**: a placeholder is bound to the certificate-checked `host:port` of its connection;
  the request line and HTTP/2's pseudo-headers are never rewritten; HTTP/2 header blocks are
  encoded again without indexing - a secret never indexed - so the server's dynamic table
  stays empty and cannot drift from the client's; Huffman-coded strings are refused.
- **Redis**: the password is written only into the password argument of `AUTH` or
  `HELLO ... AUTH`, the commands followed from the connection's first byte and stricter than
  the server reads them; a placeholder that comes back as data is never replaced; anything
  that cannot be followed ends the replacing for the connection.
- **Kafka**: a placeholder is replaced only inside the auth bytes of a SaslAuthenticate
  request that is whole in one buffer, both lengths written again, and taken once; PLAIN and
  OAUTHBEARER refuse to run without seclume's TLS; the check of the broker's host name
  cannot be switched off.
- **NATS**: the placeholder is replaced only as the value of `"pass"` or `"auth_token"`
  right after `{` or `,`, JSON-escaped in native memory; a password the application set
  itself is refused; with TLS configured nothing is sent before the handshake.
- **RabbitMQ**: always TLS; the PLAIN response has to be exactly `\0user\0placeholder` or
  nothing is sent; both lengths are written again in native memory.
- **SSH**: signatures are made in OpenSSL; SHA-1 `ssh-rsa` is not offered; the ECDSA
  signature is converted correctly, P-521's long form included.
- **MongoDB**: SCRAM-SHA-256 only, the server's signature checked, proof and command wiped
  once sent; an SRV target has to lie within the URL's domain and be a plain host name, a
  TXT record may set three options and plain values only; TLS and the host name check cannot
  be switched off, however the option is spelled.
- **Elasticsearch, gRPC, JGit**: `https://` only; a placeholder's secret goes to the nodes
  named, or to the first server it is written for - a redirect's host gets the placeholder.
- **AWS**: the secret key is read for one signature and wiped; the session token is hashed
  into the canonical request from native memory and written by the socket into the value of
  the one `X-Amz-Security-Token` header of a request head, never into a body, a trailer, the
  request target or another header; two such headers are refused. The container endpoint is
  asked without TLS only at a link-local or loopback address; STS's refusal is reported by
  its status, not its body. A presigned URL with temporary credentials is refused.
- **Azure**: the account key is decoded and used in native memory for one signature; the
  string to sign is compared with the SDK's by a test.
- **GCP**: the service account file is read into native memory, the key decoded by OpenSSL
  from there; only its public fields become strings.
- **R2DBC**: the `password` option is refused; the SQL lexer leaves literals, comments,
  E-strings, dollar quotes and Oracle's `q'...'` alone.

### Accepted residuals

- `seclume-http`: only the first placeholder in one HTTP/2 field value or one Basic credential
  is replaced; a second goes out as the placeholder, which the server refuses.
- `seclume-http`: a placeholder in any header line is replaced, so a header an application
  fills from user input could carry one a user had seen - a placeholder is not a secret, but
  it is bound to one server and has a random 96-bit nonce per process.
- `seclume-redis`: `redis://` sends `AUTH` without TLS, as Redis does; `rediss://` is for
  anything beyond the loopback.
- MongoDB: a login reply may be 48 MB before it is refused - from a server whose certificate
  was checked; and the wire headers are written in the machine's byte order, right on x86 and
  ARM only.
- `mongodb+srv://`: a host of three labels under a public suffix (`db.co.uk`) lets any name
  under that suffix be a target, as the specification has it; the target's certificate is
  still checked.
- `seclume-aws`: `SeclumeS3Presigner` puts the bucket name into the host unchecked; a name
  with a `/` or `#` gives a URL signed for another host, which S3 never sees. The name comes
  from the application.
- `AwsInstanceRole.use` holds its lock while the caller works with the credentials - a KMS
  or Secrets Manager call - so those calls of one role run one after another.
- `seclume-r2dbc`: the factory provider puts the host and database name into the JDBC URL
  unencoded; both come from the application's configuration.

## Round 4 - 13 November 2026

Scope: the TLS client's trust path again (`ClientHandshake`, `Tls12Handshake`,
`CertificateTrust`, `HostnameMatch` with `PublicSuffixes`, `HandshakeSignature`, `Finished`,
`RecordProtection`, `TrustChoice` and the pin), siblings of earlier fixes in other modules -
the HTTP/1.1 framing of `seclume-http` (#273) against `seclume-aws`'s, the quoting of session
values against that of the catalogue queries - the field encryption's decryption path, the
JWT and webhook HMAC checks, the access log's verifier, the admission webhook's injection,
the heap-dump endpoint and folder, `ProcessSecretProvider`, SCRAM in all its users, and the
drivers' result paths for values that are hard to read. Done with an AI assistant (Claude).
Maven Central could not be reached where it was done: each fix was compiled with `javac
--release 25 -Xlint:all,-restricted -Werror`, and its new tests were run with a minimal
JUnit-API shim, against the fix and - where the API allowed - against the code before it,
where they failed. The database tests added are for CI.

### Findings

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | `seclume-aws` | `SessionTokenSocket` recognised a chunked body only by `transfer-encoding: chunked` with one space - the gap round 3 closed in `seclume-http` (#273). Written `Transfer-Encoding:chunked`, with a tab, `gzip, chunked`, on two lines or next to a `Content-Length`, the chunks were taken for the next head, and the session token was written into an `X-Amz-Security-Token` line in the body and the trailer: into the object S3 stores. | medium | #322 |
| 2 | PostgreSQL | `DatabaseMetaData` quoted names and patterns as `'...'` with the quotes doubled. With `standard_conforming_strings` off, `\'` is an escaped quote, and a pattern `\' or true --` ended its literal: SQL injection through `getTables`, `getColumns` and the rest. | medium | #323 |
| 3 | PostgreSQL | A session value ending in `$seclume` made a dollar-quote tag with the closing tag's first `$`: the quote closed early, and `setSessionContext` failed with a syntax error. Not an injection - the leftover is fixed text. | low | #324 |
| 4 | MySQL, Oracle | Temporal text of the binary protocol, MySQL's `YEAR` as a date, Oracle's zoned timestamp and interval text and the `ORA-nnnnn` numbers were written with `String.format`'s `%d` in the default locale: under `ar-EG` or `th-TH-u-nu-thai` the digits were not ASCII, and `Timestamp.valueOf` refused them. The MySQL text was also ten times slower than it needs to be. | low | #326 |
| 5 | JDBC (all four) | The temporal getters and `getObject(i, Class)` let `IllegalArgumentException` and `DateTimeParseException` out for MySQL zero dates, PostgreSQL's `infinity` and years past 9999, and `UUID.fromString`'s for an unreadable UUID - past `catch (SQLException e)`. | low | #327 |

### Open

- **MD5 and `mysql_native_password` over an unauthenticated connection** (decided and fixed
  in #PR: refused unless `allowLegacyHashOverUnverifiedTls=true`, row 81). TLS.md said these
  send "a proof, not the password, and are not affected". But under the default `tls=prefer`
  (or `require`), a server in the middle can answer a SCRAM-configured login by asking for
  `md5`. It then gets `md5(md5(password || user) || salt)` for a salt it chose: one fast hash
  per guess, cheaper to brute-force offline than the SCRAM proof with one iteration that round
  1 refused (#223). `mysql_native_password` is the same with SHA-1. `requireAuth=!md5`
  closes it per URL. Whether `md5` and `mysql_native_password` should, like the cleartext
  methods since #258, need `verify-full` or `tlsPin` unless opted out is a decision with
  compatibility cost (YugabyteDB's default is md5), so it is left here and not changed.

### Reviewed, nothing found

- **TLS 1.3 and 1.2 client**: the flight order is enforced message by message, and
  `requireAuthenticatedServer` holds on both paths. CertificateVerify is checked whether or
  not a trust store is set, with `rsa_pss_rsae`/`rsa_pss_pss` kept to their key types and no
  PKCS#1 in TLS 1.3. The Finished is compared in constant time over the right transcript. The
  downgrade sentinel is checked whenever TLS 1.3 was offered. TLS 1.2 needs secure
  renegotiation, verifies the ServerKeyExchange over both randoms, and refuses a
  HelloRequest. A record's tag is checked before its type is read, and a sequence number
  never wraps.
- **Trust**: `CertificateTrust` uses the JDK's PKIX (EKU included) with the TLS 1.3 key-usage
  type, then `HostnameMatch`. That match uses SAN only, one leftmost whole-label wildcard,
  never over an ICANN public suffix, IP literals only against iPAddress, and nothing
  resolved. A pin replaces chain and name for the connection that names it, on both stacks;
  `--print-pin` stops after the handshake.
- **Field encryption**: the commitment is checked before AES-GCM-SIV, mode and key are taken
  from the header and checked, and a failed tag zeroes the output.
- **JWT and webhook HMACs**: `alg` must match, `crit` is refused, every part is canonical
  base64url, and MACs are compared with `MessageDigest.isEqual`. Stripe's tolerance check
  cannot be passed without a valid signature for the timestamp.
- **Access log verifier**: chain, sequence, the hash as last field, checkpoint signatures by
  the expected key, `vouched` on reopening; the reopening log verifies the last checkpoint's
  signature before it vouches.
- **`ProcessSecretProvider`**: an owner-only temporary directory, `mkfifo -m 600` by
  absolute path, the read end opened first, and the watchdog's timeouts.
- **SCRAM** in PostgreSQL, Kafka and MongoDB: the server nonce must extend ours, at least
  4096 iterations, the server signature is checked before success is believed, and
  PostgreSQL refuses an `AuthenticationOk` that skipped it - and, since the audit, a
  `ReadyForQuery` in place of it (Audit, finding 8).
- **SPIFFE trust manager**: the chain must lead to the bundle of the trust domain the SVID
  names, and exactly one URI SAN is allowed.
- **HTTP/2 rewriting**: padding and priority are bounded, Huffman is refused, every block
  is re-encoded without indexing, and pseudo-headers are never rewritten.
- **Redis password slot** after the skip-ahead of bulk strings: the command name and the
  third element are still read byte by byte, and only `AUTH`'s and `HELLO ... AUTH`'s slot
  is replaced.
- **Pool reset**: the borrow is marked used through `unwrap` too, and catalog, schema,
  network timeout and the driver's session reset are put back at the return.
- **Identifiers in SQL text**: savepoint, schema and catalog names are checked against plain
  identifier patterns on all four drivers. SQL Server and Oracle catalogue literals double
  their quotes (neither has backslash escapes), and MySQL's escape both.

## Round 5 - 13 November 2026 (test quality)

Scope: not a reading of the code against its claims, but of the tests against the code - the
surviving mutants PIT listed for `pool`, `internal`, `secret` and `tls` (run 43416680859), and
for each the question what a test would have to check to notice it. Where that test found the
code wrong, it is a finding here. Done with an AI assistant (Claude). Maven Central and a
JDK 25 could not be reached where it was done: new tests were compiled against the core
built with JDK 21 (`--enable-preview`, the four JDK 22 FFM renames patched in a copy), run on
a minimal JUnit-API shim, and each targeted mutant was applied to a copy of the source to see
the new tests fail on it. PIT in this pull request's CI is the measure.

### Findings

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | JDBC URL redaction | `JdbcUrl.redact` took an `@` before the first `//` for Oracle's `user/password@` and stopped when no `/` came before it, also when it had hidden nothing: `jdbc:oracle:thin:@//app:secret@db:1521/svc` - EZConnect with a login typed into its authority - came back with the password in it, in the message that names a wrong URL. `JdbcUrlPropertyTest` had no such family; it has now, and fails on the code before. | medium | #340 |
| 2 | SCRAM | The class promises an arena "zeroed on close". The `c=` value's source - the GS2 header and the channel binding data, the server certificate's hash - was copied into a buffer no field held, so `close()` could not wipe it and the arena was freed with it in it. Not a credential; the promise did not hold. | low | #340 |

### Reviewed, nothing found

- **Pool return path** (`PooledConnection.restore`/`close`, `adopted`): rollback before
  auto-commit is put back, warnings cleared after a use, leaked statements closed, the statement
  cache emptied by a session reset, the driver told to forget the handle; an adopted session
  keeps its transaction while borrowed (AGENTS.md) and is reset on return, and is not renewed
  under an open transaction. Each now checked to the call with a recording driver.
- **Statement cache**: no statement is handed to two borrowers, and maxRows, query timeout,
  fetch size and direction, max field size, parameters, warnings and batch are put back to the
  driver's defaults - never run before without a server, as the stub's statements refuse every
  getter.
- **`WireBuffer`**: `clear()` wipes the content written or read and not a byte more; growth
  wipes what it leaves.
- **`HostnameMatch`**: an address matches only an iPAddress entry; IPv4-mapped addresses
  compare as what they are; entries that are no name are skipped.

## Audit - November 2026

Scope: the whole repository, read against its claims (THREAT-MODEL.md, FEATURES.md,
ENCRYPTION.md, DIAGNOSTICS.md, the Javadoc), with an AI assistant (Claude). Every finding was
shown with a proof of concept using decoy secrets and stand-in servers that only answer
protocol text or dribble bytes.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | CI security gate | A gated test passed when any single case passed, and the gate read its manifest from the change under review (GHSA-r2cr-rj9g-qrhc). | process | #PR |
| 2 | Build inputs | Container images by tag, the Maven wrapper without `distributionSha256Sum`; a wrong dependency checksum was a warning. | process | #PR |
| 3 | `ForbiddenApiTest` | None of eight evasions was found (double space, fully qualified name, `Charset.decode`, `clone()`, `Scanner`, an allow comment inside a literal or on the line before, a line break). The check reads code now, comments and literals out across lines; seven are reported. A marker on a comment line of its own still frees the line under it - it is as plain in a diff as one at the end of the line. | process | #PR |
| 4 | `ErrorMessageTest` | One of five ways to put a secret into an exception message was found. `apiKey`, `pw`, `bearer` and a message built in a local variable are found now; `key` and `auth` are left out, as they name options far more often than secrets. | process | #PR |
| 5 | Secret providers | `provider=process` in a JDBC URL ran a program; an application that takes URLs or properties from its users ran their commands. | high | #PR |
| 6 | Pool statement cache | A cached statement kept the result set of its last execution: the next borrower read the previous borrower's (tenant's) rows through `getResultSet()`. | low | #PR |
| 7 | Pool renewal | A borrow that had handed out a statement could still be renewed; a session change the driver did not see (`select app.enter_tenant(42)`) was lost and the next statement ran as the login role. | medium | #PR |
| 8 | PostgreSQL | A `ReadyForQuery` during the login ended it as a success: no `AuthenticationOk`, so neither `requireAuth`, nor SCRAM's server signature, nor Kerberos' mutual authentication was checked. Under `tls=prefer`/`require` anybody in the middle was taken for the database with `requireAuth=scram-sha-256` set. Round 4 listed the SCRAM check as sound; it held for `AuthenticationOk` only. | medium | #PR |
| 9 | MySQL quoting | In GBK, Big5 or SJIS a lead byte took the escaping backslash, and a literal became SQL; values beyond ASCII now go as `_utf8mb4 X'...'`. | medium | #PR |
| 10 | Heap dump endpoint | A secret that could not be read was skipped, and the dump went out as redacted with it inside. | high | #PR |
| 11 | HTTP credential placeholders | A placeholder was replaced in every header line; typed into a query, a cookie or `X-Opaque-Id` it went out as the secret. | high | #PR |
| 12 | R2DBC | Host, port and database went into the URL unchecked: a database with a query of its own set the login, the STS endpoint and any other option. | high | #PR |
| 13 | JWT | `crit`, `exp` and `nbf` were looked up in a way that answered "absent" for JSON that could not be read up to the field: an expired token with such a payload passed. | low | #PR |
| 14 | OpenSSL signing key | `close()` freed the key while another thread signed: a use after free (SIGSEGV, heap corruption). | medium | #PR |
| 15 | Pool rotation | A login under way during `rotateSecret()` was kept and lent with the old secret. | medium | #PR |
| 16 | Pool session context | A resolver that threw lost the connection; two such requests emptied a pool of two. | medium | #PR |
| 17 | PostgreSQL startup | A zero byte in user, database or `applicationName` began a startup parameter of its own (`options=-c search_path=...`). | medium | #PR |
| 18 | MySQL handshake | A zero byte in user or database shifted the fields of the HandshakeResponse. | medium | #PR |
| 19 | Oracle descriptor | Service and host went into `(DESCRIPTION=...)` unchecked: a service name added `SERVICE_NAME` or `INSTANCE_NAME` of its own. | medium | #PR |
| 20 | Numbers (PostgreSQL, MySQL, Oracle) | Values beyond a long wrapped silently: 18446744073709551621 read as 5. | medium | #PR |
| 21 | Vault KV | A KV secret without a lease was read once and never again; a rotation in Vault never arrived. | medium | #PR |
| 22 | HTTP placeholders | Placeholders were a shared nonce and a counter: one seen in a log named all others. | medium | #PR |
| 23 | Log masker refresh | A secret that could not be read on refresh was dropped from the masker until the next one. | medium | #PR |
| 24 | AWS temporary credentials | The secret key and session token were not wiped before a CRaC or SnapStart checkpoint. | medium | #PR |
| 25 | Field encryption shredding | A shred while the subject's key was being read let the reader cache the shredded key and read on. | medium | #PR |
| 26 | Access log verify | With a key, a log without a single signed checkpoint passed; anyone who can write the file rebuilds the chain. The library's `Result.vouched()` asks what `seclume-verify audit` asks. | medium | #PR |
| 27 | `seclume-verify migrate` | Option values from the source URL were written unencoded: `applicationName=billing&tls=off` turned TLS off. | medium | #PR |
| 28 | Patroni topology | A member not in the URL, named by the REST answer over plain HTTP, was connected to with the password. The drivers pass the URL's hosts; an answer may reorder them, not add one. | medium | #PR |
| 29 | Redis codec | A ciphertext copied to another key opened there; `encodeValueFor`/`decodeValueFor` bind it to the key, and ENCRYPTION.md says what the codec alone does not. | medium | #PR |
| 30 | SPIFFE trust | Without `peer-ids` any workload of any federated trust domain was trusted as a server (as FEATURES.md said). Only the workload's own trust domain is, now. | medium | #PR |
| 31 | Driver login | A server dribbling bytes held a login, and the pool's thread and permit, without end. | low | #PR |
| 32 | Query timeout | A server that ignores the cancellation held a statement without end; a kill stage closes the connection after a grace, in all four drivers. | low | #PR |
| 33 | Pool probes | The capacity and idle-limit probes had no timeout; a connection closed by the probe's deadline was lent. | low | #PR |
| 34 | Pool error paths | An `Error` (`StackOverflowError`) kept the permit; housekeeping died on one. | low | #PR |
| 35 | Patroni nesting | A nested answer was a `StackOverflowError` out of connect. | low | #PR |
| 36 | PostgreSQL arrays | `{{{{...` was a `StackOverflowError` out of `getArray()`. | low | #PR |
| 37 | SQL Server `sql_variant` | A `sql_variant` holding a `sql_variant` recursed; 8016 bytes were a `StackOverflowError`. | low | #PR |
| 38 | Oracle JSON | Cycles and shared nodes: 17 bytes a `StackOverflowError`, 206 bytes an `OutOfMemoryError`. | medium | #PR |
| 39 | Oracle DH | The server's DH group and an exponent as long as the prime: years of CPU in connect. | low | #PR |
| 40 | PostgreSQL statement | A break while rows arrived swapped released buffers; a `DataRow` without `RowDescription` was taken. | low | #PR |
| 41 | Result set values | Unreadable values of a hostile server escaped as `IllegalStateException` and the like. | low | #PR |
| 42 | Connection assessment | `tls=prefer` and `require` - encrypted, server not authenticated - gave no warning. `Secured.serverAuthenticated()` says which it is, and the grade asks it. | low | #PR |
| 43 | Driver login | A secret provider's `RuntimeException` during the login left the driver as an unchecked exception, past callers that catch `SQLException`. | low | #PR |
| 44 | LDAP | `SeclumeLdap.register` compared the trust choice through `String.valueOf`; with a pin (a `byte[]`) the same registration was refused as different. A functional bug that fails safe. | low | #PR |
| 45 | Result set values | A short Oracle ROWID or DATE, and a SQL Server value cut short, left the getter as an index or state exception. | low | #PR |
| 46 | JDBC URL | A key given twice took its last value: `tls=verify-full&...&tls=off` was off. A key given twice is refused. | medium | #PR |
| 47 | Kafka encryption | A value is bound to its topic, not to its record's key; within a topic it can be copied under another key. Documented, and pinned by a test. | medium | #PR |
| 48 | JGit credentials | The placeholder was bound to the first server that asked, a submodule's host among them. `SeclumeGit.credentials(user, spec, remoteUrl)` binds it to the remote. | medium | #PR |
| 49 | Spring result limit | Whether the URL set a limit was a text search: the word in another option's value meant no limit. | low | #PR |
| 50 | TLS handshake | The handshake had a per-read timeout only; it has a deadline of its own, wherever it runs. | low | #PR |
| 51 | Secret providers' JSON | Vault, Azure Key Vault, the metadata endpoints, SPIFFE, OAuth and Google Cloud read an expiry, a lease or a flag as absent from an answer that could not be read up to it. | low | #PR |
| 52 | LDAP | The service account's placeholder, typed into a login form whose user name maps to the service account's DN, bound as the service account: a user's bind looks like the context source's own. `serviceBindsOnly()` and `asService`; the starter's context source uses them. | medium | #PR |
| 53 | `SensitiveParameters` | A value bound with `setSensitive` came back in the server's error - PostgreSQL's DETAIL, MySQL's and SQL Server's messages - as a String. The receive buffer is masked before it is decoded. Oracle's errors quote no values. | medium | #PR |
| 54 | CNG signing key | Closing a Windows CNG key while another thread signed was an access violation in `ncrypt.dll`; finding 14's fix covered OpenSSL only. | medium | #PR |
| 55 | Log masker | A secret never read left an empty entry, and the next failed refresh took it for one read before: no early retry, the secret never masked. | low | #PR |
| 56 | Pool statements | `statement.getConnection()` answered the driver's connection behind the handle: closed there, it closed under the pool; kept, it outlived the borrow as the next borrower's session. Every statement the pool lends answers the handle. | low | #PR |
| 57 | Redis discovery | Every node a cluster redirect, a topology refresh or a Sentinel named got the password: one forged `-MOVED` or Sentinel answer sent it where it pointed. Discovered nodes need the URL or `cluster-hosts=` / `master-hosts=`; others get the placeholder. | high | #PR |
| 58 | PostgreSQL | A RowDescription claiming binary for a column asked for as text was believed, and the bytes decoded by the binary reader. A format the driver never asks for is refused. | low | #PR |
| 59 | Oracle native encryption | FEATURES.md did not say that its Diffie-Hellman exchange authenticates nobody: a party in the middle reads the session. It does now. | doc | #PR |
| 60 | Keychain | The CFData the keychain returned was freed with the password in it. Zeroed before CFRelease. | low | #PR |
| 61 | DPAPI | CryptUnprotectData ran without CRYPTPROTECT_UI_FORBIDDEN: a blob protected with a prompt waited on a server for nobody. | low | #PR |
| 62 | R2DBC | A borrow cancelled while it waited for a connection got it later and dropped it unclosed: maximumPoolSize cancels - clients hanging up under load - emptied the pool. | medium | #PR |
| 63 | R2DBC | setStatementTimeout and setLockWaitTimeout answered success and set nothing. They take effect now; Oracle's lock timeout is refused. | low | #PR |
| 64 | CRaC | Wiping, the wait for secrets, the hold and OpenSSL's reseed after a restore ran only in a pool's resource: without a seclume pool, clones of an image drew the same TLS key shares and kept keys in the image. A process resource does them now. | high | #PR |
| 65 | CRaC | TLS connections outside the pool - MongoDB, HTTP keep-alive, Redis, Kafka - were not counted before a checkpoint, and their traffic keys went into the image. Open connections of the own stack are counted and refuse the checkpoint. | medium | #PR |
| 66 | TLS | In TLS 1.3 an ECDSA scheme names its curve; a P-384 key's CertificateVerify under `ecdsa_secp256r1_sha256` was accepted. The 1.3 path checks the curve; TLS 1.2, where the code point names only the hash, does not. | low | #PR |
| 67 | SQL Server | A MAX value's announced total was never compared with the chunks that followed; ten bytes announced and four sent read as four. A known total has to match. | note | #PR |
| 68 | R2DBC | The session context was asked on the borrowing thread, which under R2DBC is an event loop or a thread of the pool's; a tenant held in the Reactor context was never seen, and the same request ran with its tenant at low load and without it under load. A ReactiveSessionContext is resolved on the subscriber and handed to the pool by name (`BorrowContext`); the starter wires the bean and warns when only a blocking one is there. | medium | #PR |
| 69 | PostgreSQL | A DataRow before any RowDescription was read against the columns of nothing, or of the statement before. It is a protocol violation now, and a malformed answer is reported as `08P01` rather than as a broken line. | low | #PR |
| 70 | SPIFFE | A CA certificate with a SPIFFE URI, issued by the trust domain's CA, passed as a peer's leaf: the trust manager is seclume's own and checked no key usage. The leaf has to be no CA and, where it says, for digital signatures only (X509-SVID). | medium | #PR |
| 71 | SCRAM | The server's nonce had to be at least as long as the client's and start with it: one that sent the client's nonce back unchanged, with nothing of its own, passed (PostgreSQL, Kafka, MongoDB). It has to extend it now (RFC 5802). Found by the mutation test. | low | #PR |
| 72 | SQL Server | `getBoolean` on a column whose type byte was not what it read as let a `NumberFormatException` out past `catch (SQLException e)`. Found by a new fuzz test that runs every getter over every column of a hostile answer (PostgreSQL and SQL Server). | low | #PR |
| 73 | MySQL cancel | `KILL QUERY <id>` runs on a second connection to the configured host. Behind a load balancer or a router it could reach another backend, where the same id may be another session of the same user, and stop their statement. The session now learns which server it is on (`@@hostname`, `@@port`, `@@server_id`, asked after the login without a round trip of its own) and kills nothing where the second connection says otherwise. | medium | #PR |
| 74 | MongoDB discovery | Every member a hello named got a connection, and with it the SCRAM proof, the AWS signature or the OIDC token; one compromised member or an `rs.reconfig` could bring in a host with a valid public certificate. Members are now held to the seeds' domains and configured suffixes, in seclume's own driver and in the socket the official driver uses. | medium | #PR |
| 75 | Client identities | `ClientIdentities.closeAll()` was documented as safe only while no handshake runs, and did not check: a handshake signing at that moment lost its key half way. Handshakes with an identity are counted, and `closeAll()` waits for them (ten seconds, then a warning). | low | #PR |
| 76 | Heap check report | The Markdown report escaped only `\|` and line breaks; class and field names from the dump, and what the examined JVM said about itself, could form links, images or HTML. All Markdown characters are escaped; a backtick cannot end a code span. | low | #PR |
| 77 | HTTP placeholders | A placeholder this process did not hand out points at an attack and was only refused and logged, sparsely. It is a `space.seclume.PlaceholderRefused` JFR event now, each time, with the count so far. | low | #PR |
| 78 | CRaC | A checkpoint refused for open secrets named no one in the pool's message - the case #58 had nobody to point at. It names where they were opened (`-Dseclume.debug.scopes=true`) or how to find out, as the process's does. | low | #PR |
| 79 | CRaC | `SeclumeCrac.register` took a pool only; the MongoDB, HTTP and Redis clients on seclume's TLS could not be told of a checkpoint. `register(Suspendable)` and `closeBeforeCheckpoint(client)` take any client; one left open still refuses the checkpoint, naming who opened it. | low | #PR |
| 80 | Checkpoint coverage | Nothing caught a class that kept a secret in a field and did not register a wipe for a checkpoint (#58). A source scan now holds every class with a `SecretScope` field to `Checkpoint.register`, or to a list naming why it needs none (per connection, per handshake, covered by `FieldKeys`); a stale entry on the list fails too. | process | #PR |
| 81 | md5, mysql_native_password | Under `tls=prefer` or `require` a server in the middle could ask for `md5` or `mysql_native_password` and take a fast hash of the password for a salt it chose, to guess against offline. Both are answered only to a server that proved who it is (`verify-full`, `tlsPin`); a MySQL login offers `caching_sha2_password` first. Opt-out: `allowLegacyHashOverUnverifiedTls=true`. | medium | #PR |
| 82 | Secret providers | Any provider could be chosen from a URL or Properties - `provider=file&path=...` had the machine read a file of the URL writer's choosing and send it, as the password, to the host the same URL named. Providers that read this machine are chosen from settings only where `-Dseclume.secret.providers` names them. | medium | #PR |
| 83 | Kafka field encryption | A value was bound to its topic, not to its record's key: whoever could write to the broker moved account-17's value under account-99 and the consumer read it there. The key's (de)serializer, wrapped in `KeyBinding`, hands the digest of the key actually sent or received to the value's, which binds the value to it; a header claiming a digest is not read. Unbound writing and the migration read are explicit settings. | medium | #PR |
| 84 | Log masker | Reading character references searched up to 32 characters from every `&`, so lines of many `&` cost far more than others. A length cap was considered and rejected: a line past it would go out unmasked. The search is one pass now (`MarkupReadingTest` holds it to the old reading). | low | #PR |
| 85 | JGit credentials | `SeclumeGit.credentials(user, spec)` named no remote, and its secret went to whichever server asked first - a submodule's host among them. It is refused, pointing to the variant that names the remote. | medium | #PR |
| 86 | LDAP Kerberos | The bind response passed on to JNDI wrote the server's result code into one byte: a result of 256 reached the application as 0, success. It is BER-encoded at its length now (`BindResultCodeTest`). | medium | #PR |
| 87 | Heap dump links | The sidecar took a link named `*.hprof` for a dump and read, redacted and deleted what it pointed to; heapcheck reading a container's dump through `/proc/<pid>/root` followed the container's absolute links into the host's file system. The sidecar skips links; heapcheck resolves each link inside the process's root, as `openat2(RESOLVE_IN_ROOT)` does, and refuses a dump that is no regular file. | medium | #PR |
| 88 | Secret guard | `${DB_PASSWORD:SuperSecret}` - a plain default inside a placeholder - was not reported, nor names ending in `secret-key`, `api-key`, `pwd` or `credentials`. Both are now. | low | #PR |
| 89 | Kafka brokers | The PLAIN password or bearer token went to every broker the cluster's metadata named. It goes only to brokers in the domains of `bootstrap.servers` or under `seclume.kafka.allowed-brokers` now - the rule MongoDB's members follow, one rule in core (`SeedDomains`). | medium | #PR |
| 90 | Login budget | `loggedIn()` only cancelled the budget's task; one already running closed the connection just handed to the driver. Login and task now race for one entry, and the loser does nothing (`LoginBudgetRaceTest`). | low | #PR |
| 91 | CI secrets | Test passwords were written into the scripts as `"${{ secrets.X }}"`: the runner put the value into the script's text before the shell read it, where a quote in it would have been shell syntax. They come in through the step's `env` now and are read as variables. | process | #PR |
| 92 | Terminal output | The Doctor's text report, `--print-pin`'s subject and issuer, and heapcheck's holder names were printed raw; a server's or a dump's control characters drove the terminal. They go through `ServerText.printable` now. | low | #PR |
| 93 | Log masker | A match overlapping one found before was dropped, so the part of a second secret beyond the first stayed in the line. Only matches wholly inside a found one are skipped now; the mask takes the union. | low | #PR |
| 94 | R2DBC threads | The driver's lane and borrow threads were started for one subscriber's task and inherited its `InheritableThreadLocal`s, which then went with every later task they ran. They inherit none now (`LaneTest`). | low | #PR |
| 95 | Migration output | `--migrate` copied pool values and the TNS alias into its output unchecked, listed `sslpassword` as handled, and never checked that the URL it wrote parsed back as meant. Pool values must have their setting's shape, the alias is checked like a host, `sslpassword` is unsafe, and every URL is re-parsed and compared (exit 2 on a mismatch) | `MigrateEncodingTest` | #PR |
| 96 | Azure SharedKey | The finding asked for header values to be trimmed and their whitespace folded, as the REST documentation describes. The Azure SDK's credential, the reference that works against the service, does neither, so neither do we. Comparing with it showed a real defect instead: names were sorted by code point, the SDK and service use a `Collator`, so metadata names with `-` or `_` produced a rejected signature. Sorted as the SDK sorts now; a value with a control character is refused | `SharedKeyEquivalenceTest` | #PR |
| 97 | SPIFFE peers | Without `peer-ids` any workload of the own trust domain was accepted without a word. The trust stays domain-wide, as SPIFFE authorizes by default, and a warning at start names it | `SpiffeTest.withoutPeerIdsTheWideTrustIsWarnedOf` | #PR |
| 98 | Field context | Every column accepted `encrypt` and `decrypt` without a context, and a value written that way opened in any row. `Context.REQUIRED` columns refuse it; Kafka and Redis use them, and Elasticsearch documents can be bound to their id | `RequiredContextTest`, `EncryptedDocumentTest.aFieldWrittenWithItsIdOpensInNoOtherDocument` | #PR |
| 99 | NATS options | `configure()` followed by the builder's own `build()` named seclume's data port without registering it, and the port then connected without pin, root CA or filled login. An unregistered port is refused | `UnregisteredOptionsTest` | #PR |
| 100 | Kerberos budget | A bind that outlived its budget reported the broken write, not the budget. Mapped to "did not finish within N s" as StartTLS is | `LdapBindTest.aKerberosBindPastItsBudgetSaysSo` | #PR |
| 101 | Login budget message | A login the budget stopped was reported as the broken read. The budget now notes the login's thread, and each driver's `openOne` reports a transient 08001 naming the budget, the factor and the connect timeout | `LoginBudgetMessageTest` in all four drivers (`DribblingServer`) | #PR |
| 102 | heapcheck dump-dir | A `--dump-dir` not shared with the process gave a generic missing-file error and deleted the dump there without a word. It now names the cause and the fix, and says the dump was deleted | `DumpDirNotSharedTest` | #PR |
| 103 | Pool health | Every probe borrowed with the pool's full timeout, on a saturated pool too, and reported a busy pool as `DOWN`. A saturated pool is not borrowed from, a pool timeout without a cause is `UNKNOWN`, and the answer is cached for 2 s | `PoolMetricsAndHealthTest` | #PR |
| 104 | Log masker restore | After a restore the secrets were read on the logging thread inside the lock, and a secret missing at start stayed unmasked for the 5-minute interval. Reading runs on its own thread with a 2 s bounded wait (the line is withheld after it), missing secrets are retried every 5 s, and a throwing refresh no longer stops the schedule | `RestoreOffTheLogThreadTest`, `LogRedactionRetryTest` | #PR |
| 105 | TLS key memory | `RecordProtection` kept traffic secret, IV and nonce in a plain arena, and `next()` freed the updated secret unwiped. Both now use `SecretScope`. Counting the keys exposed `TdsChannel.close()` never closing its TLS layer, so the keys of every closed SQL Server connection leaked. Fixed, along with a test that left a detached layer open | `LoginFailureWipeTest`, `TlsNeverFallsBackTest` (SQL Server), `CheckpointCoverageGateTest` | #PR |
| 106 | Deadlines | Direct `nanoTime` comparisons in the pool and the MongoDB topology, and unbounded `millis * 1_000_000` on configured waits. `Deadlines` helper; a source rule (direct comparison, `currentTimeMillis`) in `ForbiddenApiTest` | `DeadlinesTest`, `ClockRuleTest` | #PR |
| 107 | Gate files in PRs | A PR that changed a workflow, the build or a scan test looked like any other. `gates.yml` lists such files in the run summary and labels the PR `touches-gates`; it reads the file list from the API and checks out nothing | `.github/workflows/gates.yml` | #PR |

### Mutation testing of the security paths

PIT was unavailable in the review sandbox, so the unchanged core tests (2,398, incl.
Wycheproof; Jazzer fuzz tests excluded) ran under a JUnit-subset shim against source mutants
(negated and boundary comparisons, `&&`/`||`, flipped boolean returns, removed guards, removed
negations).

Score: 357 of 425 mutants killed (84 %). Per class: `AesGcmSiv`, `Base64Off`,
`ChannelBinding` 100 %; `HostnameMatch` 92 %; `AesGcm` 89 % (the survivor is equivalent below
2^24 blocks); `JsonOff` 85 %; `Scram` 83 %; `ShamirShares` 79 %; `SessionState` 68 %;
`ConstantTime` 60 %.

Test gaps to close: SCRAM server nonce not starting with or equal to the client nonce;
channel-binding data in client-final; `ConstantTime.equals` with different lengths;
share-file permissions (POSIX/ACL); share MAGIC, CRC boundary, mixed thresholds; share-count
bounds; `JsonOff` truncated object, raw NUL in strings, zero length; `HostnameMatch` empty
inputs, `"1.2.3."`, `"[]"`; `SessionState` pre-filter negatives; SCRAM iteration-count digit
boundary. CI: pitest-maven on the security packages with `mutationThreshold=85`.

#### Part 2: TLS handshake and pool

Guard-focused mutants (checks followed by throw / return false / close / BROKEN); pool exhaustively, TLS as a fixed random sample of 25 per file. Tests: 37 TLS test classes of seclume-core, 36 of seclume-pool (+ seclume-tck), Jazzer fuzz tests excluded. Pool: 49 of 53 killed (92 %). TLS sample: 53 of 78 killed (68 %)

- ClientHandshake 76 %, RecordProtection 68 %, Tls12Handshake 64 %, Finished 33 %. Most important gap: Finished.verify's length check - a mutant that accepts a Finished of the wrong length survives every test, i.e. nothing pins the one check that proves the handshake was not altered. Gaps to close: Finished of wrong length; unoffered TLS 1.3 suite; unoffered ALPN; HRR session-id echo and version; handshake bytes in a non-handshake record; non-empty renegotiation_info (RFC 5746); missing CCS; compressed/short ECDHE po ints; client-certificate scheme not requested; record_overflow after decryption; tag-only record; all-zero TLS 1.3 inner plaintext; null trust; isClosed() failing during renew; schema set where none was.

#### Part 3: closing TLS gaps

Five new test classes (FinishedLengthTest, RecordLimitsTest, HelloRetryGapsTest, ServerHelloGapsTest, ServerKeyExchangePointTest; all green on the unchanged code) close the gaps they were written for. TLS sample score: 53/78 (68 %) -> 68/78 (87 % ). Finished 100 %, RecordProtection 96 % (remaining mutant equivalent), ClientHandshake 88 %, Tls12Handshake 76 %. Still open then: an unoffered ALPN, record types in the flight and a missing CCS, the client-certificate scheme, and the core gaps listed above.

- repeat the check in open() as defence in depth. Method note: a mutant run is only counted after a baseline run of the same tests on the original code; a test class that fails to load is an error, not a kill.


### Open

- None left from round 4: MD5 and `mysql_native_password` over an unauthenticated connection
  are refused now (row 81).

### Looked at and found sound

- **Logins**: SQL Server refuses a login without LOGINACK, needs the Kerberos context completed
  and refuses a server without encryption; an access token goes only to a server whose
  certificate was checked. Oracle's O5LOGON requires and checks AUTH_SVR_RESPONSE; native
  encryption is AES and SHA-2 only, its checksum compared in constant time. MySQL refuses a
  server without TLS under require and verify-full. No driver but PostgreSQL had a second way
  out of its login.
- **LDAP**: the StartTLS answer is read, plaintext sent after it refused, TLS always verified,
  placeholders random.
- **JWT**: the structure is parsed, not searched; alg must match, crit is refused, only canonical
  base64url, the MAC compared in constant time.
- **Field encryption**, MongoDB's EncryptedFields included: header and context in the AAD, one
  key per column, the commitment checked before GCM-SIV.

The reports the audit grew out of, as they were written; the numbers in them (#37, #53...)
are those reports' finding numbers, not the rows of the table above, and every finding they
name as fixed is fixed in #PR.

### Initial audit: login and value decoding

Scope: the TLS client (1.3 and the 1.2 profile), record layer, certificate and host-name checks, AES-GCM / AES-GCM-SIV / HKDF / Shamir against known answers and the JDK, FFM bounds; the login state machines of PostgreSQL, MySQL, SQL Server, Oracle, MongoDB, Kafka and LDAP; JWT; field encryption.

#### Findings

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | PostgreSQL | A `ReadyForQuery` during the login ended it as a success: no `AuthenticationOk`, so neither `requireAuth`, nor SCRAM's server signature, nor Kerberos' mutual authentication was checked. Under `tls=prefer`/`require` anybody in the middle was taken for the database with `requireAuth=scram-sha-256` set. Review round 4 listed the SCRAM check as sound; it held for `AuthenticationOk` only. | medium | #PR |

#### Looked at and found sound
- **Native secret stores** (read, not run on the platform): DPAPI and Credential Manager zero the OS buffer before freeing it; CNG's authenticated-cipher struct matches the x64 layout and a failed tag zeroes the output; PKCS#11 function indices 0-4 3 match the standard, Windows is refused for its 32-bit CK_ULONG; Keychain and libsecret check the length against the target.
- **SecretFetch and the cloud sources** (not run against live endpoints): no line break reaches a request line; chunks and lengths are bounded; plain HTTP only to a resolved link-local or loopback address; Azure Arc reads a challenge only from the agent's token directory, `.key`, 4 KiB at most; Vault refuses http, KMS takes https only.
- **Redis, SSH, HTTP credentials, the heap-dump endpoint, the pool, the admission webhook**: credentials are bound to the host:port the (verified) socket reached; SSH signs with SHA-2 only; an unredacted dump is always deleted; the pool marks unwrap and getMetaData as used; the webhook builds its patch as structured JSON with escaped point ers.

#### The parsers, attacked

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | PostgreSQL, MySQL, Oracle | `getLong`/`getInt` wrapped numbers beyond a long modulo 2^64 (`TextNumber.decimal`, `OracleNumber.toLong`'s first loop, MySQL `BIGINT UNSIGNED` in binary): 18446744073709551621 read as 5. Whoever can write a value chose what the application read. | medium | #PR |
| 2 | Pool | A `java.lang.Error` while opening kept the permit, and killed housekeeping: after `maximumPoolSize` of them the pool never opened a connection again. | medium | #PR |
| 3 | Patroni, PostgreSQL arrays, SQL Server `sql_variant` | Recursion as deep as the answer said: a StackOverflowError out of `connect()` (Patroni over plain HTTP), `getArray()`, `getString()`. | medium/low | #PR |
| 4 | JDBC getters | `IllegalStateException`, `Truncated`, `NumberFormatException` out of `getString`/`getBytes`/`getObject`; Oracle rowid/date cells trusted their inner lengths. | low | #PR |
| 5 | PostgreSQL | The buffer swap in `finally` read a closed buffer after a broken connection and replaced the real `SQLException`; a `DataRow` with no `RowDescription` was an NPE. | low | #PR |

#### The parsers, attacked again

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | Oracle | Native encryption took the server's Diffie-Hellman group at any size up to 65535 bytes, with a private exponent as long as the prime: 2048 bits cost 2.5 s, 4096 bits 21 s, the maximum years of CPU in connect - before any login, and no timeout stops a computation. Now at most 4096 bits and a 256-bit exponent. | medium | #PR |
| 2 | MySQL | `MyRow.parseDigits`, a copy of the `TextNumber` loop above, wrapped modulo 2^64 as well (18446744073709551621 read as 5); it now uses `TextNumber.decimal`. | medium | #PR |
| 3 | TLS | The curve an ECDSA scheme names was not checked against the key's (noted in the code). | low | #PR |

#### Looked at and found sound

- BSON reader of the MongoDB login (2 million mutated documents), the heap-dump redactor on mutated HPROF files (never served one with the secret left), TDS PLP chunks (measured before moved), LDAP BER and Redis RESP lengths, every digit loop outside `TextNumber.decimal`/`OracleNumber.toLong`/`MyRow.parseDigits`.

### Code review: quoting, placeholders, field encryption, JWT, pool

#### quoting, placeholders, field encryption, JWT
- **MY-QUOTE-MB (Medium, conditional, CWE-89/838)** – `MyQuoting.literal` and `MyDatabaseMetaData.literal` escaped for UTF-8 only. With a GBK/Big5/SJIS/CP932/ GB18030 `character_set_client` (SET NAMES, init_connect, skip-character-set-client-handshake) the lead byte of a multibyte character swallowed the escaping backslash: `中\' OR 1=1 -- ` ran as SQL. Values with non-ASCII characters are now written as `_utf8mb4 X'..'`; `enquoteNCharLiteral` no longer prefixes those with `N`. Regression: lexer simulation per client charset.
- **JWT-FAILOPEN (Low, conditional, CWE-636/613)** – `SeclumeJwt.verify` applied exp/nbf/crit only when `JsonOff.has` found them, and `has` answered false for documents it could not read (nesting > 512, non-object payload, missing comma, control ch aracter). A correctly MAC'd token with such a payload never expired. `JsonOff.present` now tells an absent field (`JsonOff.Absent`) from an unreadable document; the verifier refuses the latter.
- Checked without finding: identifier/XID/context quoting (PG, MySQL, TDS, Oracle), IMAP/POP3/SMTP user handling, Redis RESP and HTTP placeholder rewriters, OAuth token reader, EncryptedColumn/BlindIndex/Kafka decryption, AccessLogVerifier (head-truncation and checkpoint-less logs are documented via `first()` / `signedUpTo()`), AMQP Start-Ok rewriting.

- **URL-CFG-EXEC (High, conditional, CWE-78/15)** – every JDBC URL / Properties option reached `SecretProviders.of`, so `provider=process&command=...` in a URL ran a program at login. Applications that accept connection URLs from their users (BI, data-integration, admin tools) were exposed, as with pgjdbc's socketFactory (CVE-2022-21724). `process` now needs `-Dseclume.secret.process.allowed=true`; the check sits in the provider switch, so nested providers are covered too. Follow-up: an allowlist of providers for URL/Properties-sourced settings.
- **DRV-RTE (Low, CWE-248)** – a secret provider's `SecretUnavailableException` left `Driver.connect` unwrapped; it should be a `SQLException` (08001).
- Checked without finding: SPIFFE HTTP/2 and protobuf reader, own Ed25519 (RFC 8032 vector, 3000-case differential test against the JDK), NATS CONNECT rewriting and NKey decoding, admission webhook, SecretMasker, sink search (XXE, deserialization, JNDI, class loading).

- **AUDIT-EXIT (Medium, CWE-347/354)** – `--audit-verify <log> <key>` exited 0 ("the access log holds") for a log rewritten without the signing key: all checkpoints dropped, an entry changed, the SHA-256 chain recomputed. With a key, a log with entries but no checkpoint that holds now exits 1; entries after the last held checkpoint exit 3 instead of 0 (behaviour change, see README).
- Checked without finding: hostname matching and PKIX trust, tlsPin bound to CertificateVerify / ServerKeyExchange in both stacks, no session resumption, MySQL parameter binding and deferred SET, R2DBC placeholders, AWS session-token socket framing , MongoDB OP_COMPRESSED limits, the seclume actuator endpoint (hardening: no exception text, no connection per call).

- **ORA-OSON (Medium, conditional, CWE-674/409/400)** – `OracleJson` followed OSON child offsets recursively with neither a depth limit nor a visit count: a 17-byte value whose array names itself as its child was a StackOverflowError, and 206 bytes of arrays sharing their next level an OutOfMemoryError. Node visits are now limited to the value's length in bytes (a tree visits each node once) and nesting to 256; both raise SQLException 22000. Regression: cycle, doubling DAG, valid tree, scalar.
- Checked without finding: VECTOR decoding, Oracle verifier selection (10g refused, 11g opt-in) and PBKDF2 count limits, seclume-keys rotation (key use and destroy under one lock, chain and key chosen together). Functional, not security: `SeclumeKeyManager.fits` expects "EdDSA" while `NativeKey` reports "Ed25519", so Ed25519 keys are never chosen.

- **POOL-RENEW (Medium, conditional, CWE-269/863)** – after a connection failure (08xxx) the pool silently renewed the connection and repeated the call when SessionState judged the session unchanged. That judgement reads SQL text only: `select app.enter_tenant(42)` or a DO block that sets a role or tenant was not seen, and the borrower's next statement ran as the login role. A borrow that has had any statement handed out is no longer renewed; renewal stays for borrows that have run nothing (a connection dead before first use). Regression: RenewPoc (function-set role, SET ROLE, dead-on-borrow).
- Checked without finding: SeclumeHmac (constant-time compare, Stripe timestamp bound to the MAC), SCRAM channel binding and the 'y' downgrade guard, OAUTHBEARER only to verified servers, reset on every used return (DISCARD ALL / COM_RESET_CONNECTION).

- **POOL-STMT-CACHE (Low, conditional, CWE-226)** – StatementCache.give kept the statement's open result: with a driver that has no SessionReset (the cache then lives across borrows) the next borrower's prepareStatement of the same SQL returned that statement, and getResultSet() before its own execute handed it the previous borrower's unread rows. give() now closes the result and calls getMoreResults(CLOSE_ALL_RESULTS) first, and does not cache a statement for which that fails.
- Checked without finding: no renewal after work since the transaction boundary, savepoints or a previous renewal; seclume drivers' cache emptied on every used return; ReadWriteSplit routes on setReadOnly, binds GTID/LSN.

- **R2DBC-URL-INJ (Medium, conditional, CWE-88/74)** – jdbcUrl() encoded user and every passed-on option but appended HOST, PORT and DATABASE as they were. JdbcUrl splits at the first '?' and the last duplicate wins, so a database option of "tenant_a?user=postgres&x" turned "?user=app" into the key "x?user" and logged in as postgres with the application's secret; any option the application did not set could be added the same way. Host (incl. IPv6 and lists), port and database are now validated before the URL is built. Regression test: JdbcUrlInjectionTest.
- Checked without finding: MongoDB SDAM (members only from this set's primary, stale primaries by electionId/setVersion, topologyVersion), R2DBC refuses a password option.

### Code review: protocol injection, trust and credentials

#### #37 PG-STARTUP-NUL — Medium (CWE-158/CWE-93)

`PgSession.startup()` wrote `user`, `database` and `application_name` with `WireBuffer.putCString()`, which does not refuse an embedded zero byte. JdbcUrl decodes `%00`, so `applicationName=x%00database%00tenant_b` added a second `database` parameter. The server takes the last one, while `getCatalog()` still reported the URL's database. `options` (any `-c` GUC such as `search_path`) and `replication` could be added the same way. Fix: `startupValue()` refuses a zero byte with SQLState 08001. Verified with a local stand-in that only reads the StartupMessage: the injected pairs no longer arrive; normal values are unchanged. Follow-ups: (refuse NUL in `putCString` itself, which also covers the MySQL handshake) (control characters refused in Settings before a socket opens). Checked without finding: heapcheck sidecar write path (O_EXCL temp file, link-based publish refuses a planted name, deletes remove the link only); setClientInfo (refused in every driver); TDS Login7 strings (length-prefixed). The sidecar no longer follows symlinks when reading (row 87).

#### #38 MY-HANDSHAKE-NUL — Medium (CWE-158/CWE-93)

`MySession.writeHandshakeResponse()` wrote `user` and `database` with `putCString()`. A decoded `%00` in `user` ended the field early, so the server read attacker-chosen bytes as auth length, database and plugin: `user=app%00%00tenant_b%00x%00` gave `database=tenant_b`, `plugin=x`; the unknown plugin triggered an AuthSwitchRequest that the driver answered with the real login. With `user=app%00` the scramble landed in the database field, which servers echo into errors and logs. Fix: `handshakeValue()` refuses a zero byte (08001) before the packet is written. Verified against a protocol-faithful local stand-in (no auth bytes printed, decoy secret); not run against a real mysqld.

#### #39 ORA-DESC-INJ — Low (CWE-74)

`OracleSession.Settings.connectString()` placed `host` and `service` into the TNS descriptor verbatim; `a)(SERVICE_NAME=b` or `x)(INSTANCE_NAME=…)` added entries. Listener behaviour on such entries was not verifiable here. Fix: compact constructor of `Settings` whitelists service (`[A-Za-z0-9_.$#-]+`) and host; `OraDataSource.getConnection` maps the refusal to SQLException 08001.

#### #40 SPIFFE-FED-DEFAULT — Low–Medium (CWE-1188/863)

SpiffeTrustManager took the trust domain from the peer's URI SAN and accepted any SPIFFE ID whose chain led to that domain's bundle — federated domains included — when no peer-ids were configured (the default). The public doc of spiffeSslContext reads as "the bundle the agent gave". A federation set up for one partner service thus admitted every workload of the partner as mTLS client or server. Shown with two local test CAs (a.org own, b.org federated): both leaves accepted. Fix: without peer-ids only the workload's own trust domain; federated domains only where peer-ids (or trust-domains=) name them. Verified.

#### #41 REDIS-AAD-NOKEY — Medium (CWE-345/639)

EncryptedCodec used one associated-data value ("redis:" + name) for every value, so a ciphertext stored under one key opened under any other: whoever can write to Redis — the party client-side encryption is meant to defend against — copied role:alice's "admin" over role:mallory's "viewer" without a key (local PoC, a map standing in for the server). Lettuce's RedisCodec never passes the key to encodeValue, so the fix is an API beside it: encodeValueFor/decodeValueFor bind the key's bytes into the associated data; a copied value then fails with FieldEncryptionException. Verified. The same column-not-row binding exists by construction in the Kafka serializer (topic) and the JPA converters (column) — documented as C, hardening H56/. Checked without finding: RespPasswordRewriter (replaces only the AUTH/HELLO password slot, fails closed on anything it cannot follow), RespReplyGuard, the Jedis socket factory.

#### #42 KAFKA-AAD-NOKEY — Medium (CWE-345/639)

EncryptingSerializer bound a value only to its topic ("kafka-topic:" + topic, column kafka.<topic>.value). Anyone who can write to the broker assembled a record from one record's key ciphertext and another's value ciphertext; the consumer decrypted both (local PoC: account-99 -> "credit 5000", taken from account-17). Kafka's value Serializer never sees the key, so the fix is an interceptor pair: the producer adds the SHA-256 of the serialized key as a header bound into the value's associated data; on the consumer the key deserializer records the digest of the key bytes actually received, and the value deserializer uses that, never the header as sent. 

#### #43 SHRED-RACE — Medium (CWE-362/459)

SubjectKeys.ring() read the wrapped key from the store and unwrapped it outside the lock, then cached the ring without asking whether the subject had been shredded meanwhile; shred() removed only the ring cached at that moment. A read in flight across shred() put the deleted key back: shred() returned true, the store held no key, and the subject's values still decrypted through the cache (local PoC with a store whose load() is held once). Fix: a per-subject shred counter, raised before deletion, compared before caching; a ring opened across a shred is closed and refused. Verified. Open: other instances keep their cached ring until it is evicted. Also: the field format itself checked without finding (GCM-SIV , header in AAD, key commitment before decryption, HKDF separation per mode and for blind indexes); #41/#42 come from integrations passing a constant context — lets a column require one.

#### #44 HTTP-HEADER-ANY — Medium (CWE-201/532)

HttpFraming kept the request line out of the rewrite — the placeholder is no secret, and the target holds what users type — but replaced the placeholder with the secret in every header line; Http2Requests in every non-pseudo header. An application that copies user input into a header (Elasticsearch's X-Opaque-Id, tracing ids, Referer, cookies) sent the real API key there when the input was the placeholder, which is designed to be safe to log. Shown locally with a decoy token: Authorization carried it, as wanted, and so did X-Opaque-Id. Fix: only credential header lines (authorization, proxy-authorization, x-api-key, api-key, x-auth-token, plus a configurable list such as x-vault-token); verified for HTTP/1.1, HTTP/2 to follow. Checked without finding: request line and bodies untouched, digit-only lengths, per-server placeholder binding (sniffed nodes fail closed), SearchUrl.

#### #45 PLACEHOLDER-TOFU — Medium (CWE-522/346)

SeclumeGit.credentials() and SeclumeGrpc.header() registered their placeholder without a server list, so CredentialPlaceholders bound the secret to the first server it was written for. An application that also fetches user-chosen URLs with the same provider sent the real token to whichever host answered 401 first after a start (local check of the binding: the first server gets the secret, the intended one only the placeholder). seclume-kubernetes already binds to its API server; JGit and gRPC get a servers argument, the unbound variants are deprecated.

#### #46 RESULT-LIMIT-SPOOF — Low (CWE-1284/400)

SeclumeDataSources.withResultLimit() skipped the default result limit when the URL text contained "maxResultBytes=" or "maxResultRows=" anywhere — in a database name or an applicationName too (verbatim copy of the method). Fix: look at parsed option keys. Hypotheses checked without finding: #36 does not reach provider=process (the application's provider comes later and wins); TDS Login7 and Oracle AUTH are length-prefixed; RespReplyGuard's 64 KiB bound is moot against Redis's 128-character echo. EncryptedFields: binding exists, the documented example omits it. Note for #44: bind the placeholder to the header it was registered for instead of a fixed allowlist.

#### #47 LDAP-SVC-LOGIN — Medium (CWE-287/1390)

LdapSocket replaced the placeholder in any simple bind whose DN equals the registration's user() on its server (madeFor). On the wire a bind by the context source and an end user's bind with the same DN look alike: with Spring Security's BindAuthenticator on seclume's socket factory (as the Javadoc recommends) and an AD UPN pattern, typing the service account's name and the placeholder — known to whoever read a heap dump, the case the class names — signed in as the service account (with auth entication=kerberos: as the OS ticket's identity). Fix: refuse typed credentials starting with the placeholder prefix (guard registered by the starter) and honour the placeholder only for binds the context source makes for user().

#### #36 addendum

The injected database name sets every option the application does not set itself — TLS options and secret provider options alike (an injected sts-endpoint reaches the web-identity credential source; checked by parsing only, nothing sent). H75: security options parsed once, from trusted parts only; duplicates refused. Also (container credential URI host rules as in the AWS SDKs). seclume-mail checked without finding (own login against the configured host, STARTTLS mandatory).

#### #48 CRAC-TLS-UNCOUNTED — Low–Medium (CWE-226/316)

SeclumeCrac.quiesce() calls the process quiet when registered pools have no borrowed connection, SecretScope.open() is 0 and no unreloadable private key is held. TLS traffic keys and AES-GCM contexts live in plain shared arenas (RecordProtection, RecordStream, TlsConnection, OpenSslAesGcm), not in SecretScopes, and no Checkpoint registration covers live connections — so the MongoDB driver's own pool, SeclumeHttp keep-alives, Lettuce, Kafka, JNDI and R2DBC pools keep their session keys through a checkpoint. On SnapStart, which does not refuse open sockets, the image then holds them. Fix: count live TLS connections (as LiveKeys counts keys), refuse the checkpoint while any is open, and hold new handshakes with new secrets; moves tra ffic keys into SecretScopes. Checked without finding: kernel entropy for nonces, OpenSSL reseed before release, the recount under hold(). catalogue of security-relevant secret provider options added (endpoints, audiences, paths, command, trust).

#### #49 SENSITIVE-ERROR-ECHO — Low–Medium (CWE-209/226)

SensitiveParameters promises a value written "without it becoming a String". On the error path it becomes one: PgSession.readError() decodes every ErrorResponse field with readCString() — message into getMessage(), DETAIL into PgException.detail — and MySQL's error text goes into MyException as it is. PostgreSQL echoes bound values in DETAIL ("Key (k)=(...) already exists", "Failing row contains (...)" — every column of the row) and in type errors; MySQL in ER_DUP_ENTRY's message. A secret bound from native memory then sits on the heap and in every log of the exception. Fix: before decoding, overwrite the bytes of each bound sensitive segment in the native receive buffer; skip, don't decode, fields that are discarded. Cross-check of error messages otherwise without finding: no connection secret reaches an exception (MySQL scramble masked, Redis readLine masked, mail and HTTP name host/user only); server text is quoted unfiltered for control characters, DETAIL carries row data into logs.

#### #50 AUDIT-HOLDS-NOCHECKPOINT — Medium (CWE-354/345)

#32 made the AuditVerify command refuse a signed log without checkpoints; the library underneath did not change: AccessLogVerifier.verify(file, key).holds() is true for a log someone rewrote, stripped of every checkpoint line, renumbered and re-hashed — although its log.opened line announces signing and the caller passes the key (local reproduction: holds=true, checkpoints=0, no problems). Fix: with signing announced or a key given, every entry must be covered by a valid checkpoint (an uncovered tail is not "holds", or a separate vouched() callers must check), the opened line's fingerprint must match the key, and an "unsigned" opened line under a key is a downgrade.

#### G2, continued

AccessLogTest's "re-hashed entry is found" holds while a later checkpoint is still in the file; FieldEncryptionTest's "copied" means copied to another column or context. HeapDumpTest's negative control is the model the text-scanning tests lack.

#### #51 PATRONI-REDIRECT — High with http Patroni and public-CA trust, else Medium (CWE-941/319/346)

PatroniTopology took the members of GET /cluster as they came, and HostList.current() used them instead of the URL's hosts; the request goes over plain HTTP whenever the option says http:// — as the Javadoc's example does. Whoever can shape that answer (on the path to port 8008, a compromised member, write access to the DCS) names their own host as leader; verify-full then checks the certificate against that name, which a certificate for the attacker's own domain passes, and refuseUnlessAuth enticated releases a cleartext password to it; with SCRAM the attacker picks salt and iterations; either way the application writes to their database. Local reproduction with a stand-in Patroni: [db.attacker.example:5432, db2:5432]. Fix: an answer may reorder the URL's servers, never add one (members outside the URL's hosts or a patroni-hosts allowlist are ignored; TLS names come from the URL), warn on or refuse plain-HTTP Patroni. Verified: [db2:5432]. H100: the same rule for every ClusterTopology. Root-cause sweep of earlier fixes otherwise clean (#28 quoting, #37/#38 C-strings, #33 depth limits); (JdbcEscapes and NO_BACKSLASH_ESCAPES) (CbomReader limits).

#### #52 REDIS-DISCOVERY-PASSWORD — High for plain or Sentinel discovery, Medium with TLS (CWE-522/941)

SeclumeLettuce builds a RespPasswordRewriter for whatever host each new channel connects to; its Javadoc says so: every node found on topology refresh or redirect, and the master or replica a Sentinel names, "receives the password from native memory". Only that node's own certificate is checked. A MOVED/ASK injected on a redis:// path, a forged Sentinel answer, or a compromised node naming a host with a valid certificate for its own domain, receives the real password. Elasticsearch (placeholder bound to the configured nodes) and Kubernetes (bound to the API server) already do it the safe way. Fix: discovered targets outside the URL's hosts or an explicit cluster-hosts/master-hosts allowlist get the placeholder only, and plain discovery needs an explicit opt-in.

#### Runtime-discovered connection targets — sweep

Aurora (instance id restricted, fixed AWS domain suffix), SecretFetch and SeclumeHttp (no redirects followed), Elasticsearch sniffing (placeholder bound) checked without finding. Same class as #51/#52, kept as hardening: MongoDB hello.hosts, Kafka advertised listeners; one shared "discovery may reorder, never extend" rule with a contract test.

### Process: gates and tests

#### G1 — process: a pull request is judged by its own gates

security_gate.py and coverage_gate.py are careful (DTD/entities refused, "did not run" is a failure, a skipped security test never passes, renamed modules are noticed) — but both read their manifest and floors from the pull request's own checkout, and the surefire reports its own build wrote; ci.yml even takes the -Dtest list from it. A PR can drop an entry, lower a floor, or cut a security test to one empty case, and stay green: locally, one empty case for each of the 40 core entries gave " 40 of 40 through". "The floors only ever move up" is a comment, not a check. Fix: load gate files and scripts from the base branch, a ratchet job against main (entries, floors, min_cases per entry), mutation testing of changed security-test co de as a gate, a visible "touches gates" label, CODEOWNERS.

#### G2 — two gate tests prove less than the manifest says

ForbiddenApiTest ("no production code puts a secret on the heap without a marked reason") matches source text line by line: run through its own check(), a plain `new String(s)` is found, eight equivalents are not (`new String(`, `new java.lang.String(`, a constructor split over two lines, Charset.decode(...).toString(), ByteBuffer.wrap(byte[]), Scanner, an allow marker inside a string literal, a marker on the line above covering any next line). productionSources() only walks <root>/*/src/main/java, so seclume-quarkus/runtime and /deployment are never scanned (clean today). ErrorMessageTest ("no exception message carries a secret") flags only identifiers named password/secret/passphrase/credential/token placed directly in a throw: 1 of 5 samples caught; runtime echoes (#49)

are out of its reach. Fix: bytecode-level forbidden-call scan with an annotation for exceptions, module list from the reactor, a decoy-secret runtime test over error paths, and manifest wording that matches wh at each test shows until then.

### Cross-cutting reviews

#### Start-up and shutdown failure paths — two findings fixed (#53, #54)

#53 SecretMasker.refresh() rebuilt its index from the secrets readable at that moment: a provider that failed for one refresh (Vault restarting, a network blip) dropped that secret's fingerprints, and log lines carried it in the clear until the next successful refresh — five minutes by default. Fingerprints are now kept per label and reused when a read fails; a secret never read yet (cold start, after a restore) is repo rted by complete() so the refresher retries early. #54 RedactionSecrets.open() skipped a secret it could not read, so a heap dump was redacted without it, reported as redacted, and the original deleted — a dump taken under memory pressure, when a provider call is most likely to fail, could ship with the password in it. An unreadable secret now refuses the redaction and the existing failure path applies. Checked without finding: no silent fallback when a provider is missing or Windows-only; field keys abort start-up on a provider error and are wiped under the write lock before their providers close; JPA without a ring refuses; Checkpoint.wipeAll co ntinues past a failing holder.

#### Secret rotation and concurrency — two findings fixed (#55, #56)

#55 SeclumePool.rotateSecret() marked the entries in a snapshot of the pool; a login under way at that moment — the secret read at its start, the entry added at its end — was not in it, so a connection opened with the old password was lent again until maxLifetime. newEntry() now notes the rotation count before the login and retires the entry on return if it changed by the time the entry is added (the same added-then-checked order close() uses); the count is an AtomicLong. #56 VaultSecretProvider treated a KV secret — no lease — as never stale and served it from its cache until a restart. A password rotated in Vault was not taken up, and a SecretWatch on the same provider, the starter's wiring, never saw the change it is documented to report. A KV secret is now read again after a maximum age (60 s by default). Checked without finding: the AWS, Azure and GCP providers do not cache; the file provider reopens on every read and refuses an empty file; OAuthToken copies the token under its lock; renew() keeps the rotation mark.

#### Tenant separation — isolation holds; one borrow-path finding fixed (#57)

#57 SeclumePool.lend() marked the entry in use and then asked the session context supplier outside the try that hands a failed borrow back: a supplier that threw — a tena nt header that does not parse, an anonymous request — left the connection in use for good, with no borrow counted and no trace, so leak detection saw nothing. As many such requests as the pool has connections, unauthenticated, emptied it until a re start. The supplier is now asked inside its own try; on failure the untouched connection is returned, not retired. Checked without finding: a used session is reset unconditionally; a context not yet sent is dropped before the reset; the deferred DI SCARD ALL is answered before the next borrower's first message and a refusal closes the connection; a failing restore retires; unwrap and adopt count as use; Statement/DatabaseMetaData.getConnection name the pool's handle; the statement cache is cleared with the reset; values are dollar-quoted, hex or N'' and names allow-listed; PostgreSQL refuses a session value behind a transaction pooler.

#### Time and clocks — two checkpoint findings (#58 fixed, #59 designed)

#58 seclume-aws's TemporaryCredentials kept up to three generations of secret key and session token in SecretScopes without registering with Checkpoint. With a pool registered , quiesce() saw them open and refused every checkpoint — SnapStart with seclume-aws could not be used; without one they went into the image. The class now registers and forgets every generation before a checkpoint; a request signed with one fails rather than sends it. #59 seclume-crac's only CRaC resource is the pool's: wiping the registered caches, the open-secret check, the hold and the reseed of OpenSSL's DRBG all run only when a pool is registered. An application using seclume's TLS with out a pool — seclume-keys, -http, -kafka, -jwt — got none of them, and every instance restored from one image drew the same ephemeral key shares. A process-wide resource, registered whenever seclume-crac is present, is to take these over; pools keep suspend and resume. Checked without finding: no TLS resumption; credential deadlines are relative to one local clock and on the nanoTime scale; OAuthToken is invalidated at checkpoints; SeclumeJwt checks exp/nbf with leeway, canonical encoding and crit, and escapes claims correctly.

#### Side channels — timing closed; one placeholder finding fixed (#60)

#60 Credential placeholders were seclume-cred-<nonce>-<n>: one random nonce per process and a counter. Placeholders are public by design and end up in client configuration and debug logs; one seen there named every other one. With a placeholder bound to the first server it is written for (#45) and rewritten in any header (#44), a derived placeholder not yet used could be bound to a server of an attacker's choosing. Each placeholder is now 128 bits of its own randomness, with no shared part; the same for the Kafka SASL and AWS session-token placeholders. Checked without finding: SCRAM compares nonce and server signature in constant time and refuses fewer than 4096 iterations (Kafka included); SeclumeJwt compares MACs in constant time and checks claims only after the signature; HTTP/2 writes secrets never-indexed and refuses Huffman input; bodies are never rewritten; MySQL public-key retrieval is opt-in; the length and equality field encryption reveals are documented.

#### Configuration as attack surface — one finding fixed (#61)

an inventory of quiet switches #61 The assessment behind /actuator/seclume and the crypto policy graded a connection by "in the clear" and "TLS 1.2" only: Secured reported the TLS version and suite, not whether the server was authenticated, so the default tls=prefer — and require — looked exactly like verify-full. A session a man in the middle could read, and under prefer with TLS stripped relay the login of, showed no finding. Secured is to report serverAuthenticated(); the assessment now warns when it is false, and a policy rule tls.require-authenticated (default warn) lets on-start=fail refuse it. Checked without finding: the password itself and OAuth tokens go only to a verified or pinned server; SCRAM over unverified TLS signals channel-binding support, so a relay to a server offering -PLUS fails; the Java AES-GCM fallback is constant time and announces itself; secret fetches use no proxy; tnsnames.ora contributes addresses only and TCPS forces verify-full.

#### Supply chain, build and native libraries — checked, no finding

Native libraries cannot be swapped without rights that would allow anything anyway: libcrypto is looked up by soname through the dynamic loader on Linux and by fixed absolute paths on macOS (Apple's /usr/lib stub refused, the override absolute only) and must report OpenSSL 3 or later; every Windows DLL seclume loads is a System32 one. The repository holds no binaries; the wrapper jar is checked against its SHA-256 in mvnw and in the CI retry script, cache included; workflows are read-only, actions pinned by SHA, no pull_request_target; the OpenSSL tarball for the hybrid test is pinned by SHA-256; builds set outputTimestamp.

#### A hostile server on the receiving side — parsers hold; one timeout finding fixed (#62)

#62 Every bound on waiting counted silence only: the network timeout's watch is armed per read call, a query timeout sent a cancellation and nothing more, and a login was watched like a network timeout. A server that ignored the cancellation and se nt a byte now and then — hung, hostile, or a proxy in between — held a statement past its query timeout (2 s set, 60 s taken) and a login past its connect timeout (3 s set, 37 s taken, no upper bound), and with it a pool's thread and permit. A query timeout now closes the connection when the cancellation has not ended the statement within a grace; a login has a budget of its own, lifted by loggedIn(). Checked without finding: the PostgreSQL buffer grows with the bytes that arrive, not with an announced length; notifications are bounded; an unrequested CopyInResponse is answered with CopyFail; MySQL packets are bounded and split payloads refused; TDS PLP chunks must be there before they are used; quoting does not depend on server parameters.

#### R2DBC — three findings at the seam between Reactor and blocking JDBC (#63–#65)

R2DBC borrows from SeclumePool, so the reset on return, credential expiry, rotation and the fixes for #55, #57 and #62 hold there as well. #63 A borrow that had to wait ran as fromCallable on a virtual thread; a subscriber that cancelled — a client that hung up while the pool was busy — left the thread waiting, and the connection it then got was discarded by Reactor and never closed: one connection lost per such cancellation. The borrow now closes a discarded connection. #64 The session context supplier is asked on the borrowing thread: under R2DBC that is the subscriber's for a free connection and a new virtual thread when the pool has to wait, and Reactor's Context — where a reactive application keeps its tenant — cannot be read at all. A tenant was set under light load and not under load. A reactive context source, resolved on the subscriber and passed to the pool explicitly, is to replace it there. #65 setStatementTimeout and setLockWaitTimeout reported success and set nothing; they are to map to the JDBC query timeout and each database's lock timeout, and to fail where there is none. Checked without finding: closing returns and resets the pooled connection; lanes serialise a connection's calls and refuse work once closed; borrows never run on the shared platform threads; a cancelled login still wipes its secrets; placeholder re writing copies literals, comments and dollar-quoted bodies and never inlines a value.

#### Admin and diagnostic tools — one finding fixed (#66)

#66 seclume-verify --migrate decoded the values of the URL it translates and wrote them into the seclume URL and the properties lines as they were: an application name of billing%26tls%3Doff became a second option tls=off — the one JdbcUrl reads, since a repeated option takes the last value — and %0A started a properties line of its own; SQL Server's {...} values the same. The output ran without TLS while the tool reported nothing unsafe (exit 0). Option names and values are now percent-encoded, the database name too, and host list and user name refused when they hold control or delimiter characters. Checked without finding: no form of a password in a source URL — query, user info, Oracle's user/password@, SQL Server's PWD and braces, sslpassword, password1/2, pwd, the wallet password, percent-encoded — appears in the output; heapcheck starts jcmd by absolute path with an argument array, the dump is written 0600 under a random name, reports name findings by number only; --print-pin does not log in; no Java deserialization in the tools.

#### Cross-check of the fixes #53–#66 — one new finding (#67)

one fix corrected All twelve fixed files compile together and every proof of concept shows the fixed behaviour on the combined tree. A query killed by the deadline's new kill stage reports TransactionResolutionUnknownException (08007) for a write and the pool retires the connection; a login over its budget gives the pool's permit back. #67 The pool's capacity and idle-limit probe ran on the first connection after login, with no query timeout: a server that did not answer it held that connection, its borrower — often the warm-up at start-up — and a permit for good. The probe now has a timeout of its own (seclume.pool.probeSeconds, 5 s), and a connection the probe cost is refused, not lent. #62, corrected: the first version of the kill stage was cancelled with cancel(false), which does not stop a kill already running, and could close a connection after its statement had returned (19 of 40 timed races); kill and close() now exclude each other.

- Checked without finding: mongodb+srv resolution (targets below the host's domain, strict host/port, TXT limited to authSource/replicaSet/loadBalanced), OP_COMPRESSED via aircompressor-v3 (exact announced size), reactive demand handling, Encrypted SecretProvider (AES-GCM verifies before decrypting), Shamir combine (x in 1..255, duplicates and foreign splits refused, embedded SHA-256 check), heapcheck jcmd invocation and JSON/SARIF output.

- Checked without finding: SeclumeJschIdentity (no SHA-1 signatures, ECDSA DER-to-SSH conversion incl. P-521), SearchUrl (https only, no password in the URL, placeholder bound to the listed nodes), EncryptedDocument decryption, SeclumeGit transport (https only, trust not overridable by JGit), Quarkus/ Micronaut/Helidon guards (report names, never values).

- Checked without finding: socket timeouts and truncated messages close the session (no desynchronised stream reaches a pool); PG/MySQL cancel only while an answer is awaited; Oracle break; TDS attention counted before it is written and drained bef ore the next request; MySQL cleartext paths (clear_password, sha256_password, caching_sha2 full auth) only to verified servers, public-key retrieval off by default; Flight records names and lengths only. - Open (needs a real server): TDS cancel while rows are streaming - drainAttention reads one more message per ATTENTION even when the response already carried DONE_ATTN; add a LocalCancelTest case that cancels a large result mid-read.

- Checked without finding: TLS downgrade sentinel (RFC 8446 4.1.3), HRR rules, no renegotiation or resumption, ECDHE+AES-GCM only, EMS and renegotiation_info offered, no IP in SNI, handshake size limits; X25519MLKEM768 share and secret lengths, OpenSSL failures turned into a handshake abort. - New fuzzing: MySQL result-set parser via a fake server, 300,000 mutations over three seeds (LONGLONG unsigned, utf8mb4 strings, DECIMAL, DATETIME(6), JSON, BLOB, BIT through all getters) - only SQLException; mutated handshake/auth-switch/more-data/ERR/OK packets - only SQLException. - Login against a silent server: all four drivers honour connectTimeout during the handshake (2.0-2.2 s for 2 s).

#### Native resources closed while in use — checked, no finding

seclume holds no raw descriptors (NIO SocketChannel throughout), and TLS frees its cipher contexts only under both the read and the write lock. The native crypto primitives themselves (OpenSslSigningKey, OpenSslAesGcm, CNG counterparts) do not guard close() against a concurrent use; every production caller found does (EcdsaSigner synchronized, RenewingClientIdentity and ReloadableSigningKey read/write locks, the JWT SigningKey monitor). Measured what misuse would cost: a sign/close race on the raw key, 3000 rounds × 3, gave glibc "free(): corrupted unsorted chunks" once and two hangs; with a read/write lock in the primitive, 5 of 5 runs clean at the same speed. H51: guard the primitives themselves. H52: enforce closeAll()'s "no handsh ake running" instead of documenting it.

#### ColumnRotation, BlindIndex — checked, no finding

ColumnRotation validates every identifier before building SQL, binds all values, writes back only where the value is unchanged (conflicts counted), one transaction per batch, resumable and idempotent; Context.ROW_ID gives JDBC the per-row binding the Redis/Kafka integrations lacked (#41/#42)

BlindIndex derives one key per transform, width and name, so indexes of one column do not correlate; terms are truncated HMAC-SHA-256, matches() compares in constant time and wipes.

#### OAuth/JWT bearer sources, MongoDB driver — checked, no finding

OAuthToken: https-only token URL from java.net.URI (no header injection), client secret assembled and encoded in native memory, bounded answers, Bearer only, access tokens with spaces or control characters refused, expires_in bounded with a renewal margin; RFC 7523 assertions with aud, jti, 5 min. MongoDB driver: SCRAM-SHA-256/X.509/AWS/OIDC only, refused before anything is sent; BSON depth and bounds checked; decompressed size checked before inflating; SRV targets within the URL's domain, TXT limited to three options.

#### Time and clocks — checked, no finding

Security-relevant timing uses monotonic time or epochs: OAuthToken renewal (nanoTime, invalidated before a checkpoint), the TLS client offers no PSK, resumes nothing and drops NewSessionTickets, so there is no ticket to expire, snapshot or replay; caches with nanoTime deadlines are all registered for wiping before a checkpoint.

#### Concurrency on shared state — checked, no new finding

H88/ FieldKeys guards every use with a read lock and wipe/reload/close with the write lock, re-checking "forgotten" after locking; a half-failed reload wipes again. SecretWatch is synchronized throughout. The pool sends each reset on return and reads its answer before lending; a refused reset closes the connection. Resets: PostgreSQL DISCARD ALL after rollback, Oracle a fresh login (application contexts cannot survive), My SQL COM_RESET_CONNECTION plus the current database, SQL Server RESETCONNECTION on the next request. Open against real servers: whether EXECUTE AS / sp_setapprole survive sp_reset_connection (P8) and whether SET ROLE / user variables survive COM_RESET_CONNECTION (P9) — a Testcontainers reset matrix that gates releases. Placeholder first-binding is race-free (the issue is the design, #45).

#### Build, CI, release — checked, no finding

No pull_request_target, workflow_run or comment triggers; fork PRs get no secrets; tokens are read-only (id-token only for the OpenSSF upload, no PR trigger); every third-party action is pinned to a commit SHA; the only event data in scripts are a base SHA and a PR number; composite actions pass inputs through env. Releases are OpenPGP-signed, the key published three ways; outputTimestamp set.

### Reviewed, nothing found: seclume as a server

#### seclume as a server — checked, no finding

The admission webhook serves POST /mutate and GET /healthz only, bounds the request body, sets request/response time limits and parses with a depth limit (earlier round); an anonymous /mutate computes a patch and returns it, nothing else. The patch never replaces or repeats a pod value and is idempotent; the SPIFFE hostPath option is judged by Pod Security admission on the mutated pod, so it grants nothing a namespace's policy would not. The Spring endpoints are read-only and exposed only by configuration.

## Rounds 6 to 16 - November 2026

How these were done: each round read one area against its claims, as above, with an AI
assistant (Claude). Maven Central could not be reached where they were done: fixes were
compiled with `javac -Xlint:all -Werror` against the modules built from this repository, and
new tests were run with a minimal JUnit-API shim, against the fix and against the code before
it, where they failed unless said otherwise. Where a library was needed and not at hand it was
built from its own source (Logback 1.6.6, Spring Boot 4.1.2's two Logback converters, the
Jakarta Persistence `AttributeConverter`). Slow or silent servers were stand-ins that dribble
or answer protocol text; every secret was a decoy. The tests that need a database, a broker or
a library not at hand are for CI. "Fixed in" names the pull request.

## Round 6 - November 2026

Scope: `seclume-heapcheck` - the recording check, `ProcessHeap`'s dump of another process.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | heapcheck | A recording that names no secret, with nothing named and no discovery, searched for nothing and exited 0. | medium | #PR |
| 2 | heapcheck | `ProcessHeap` started the target's local management agent for every dump, falling back to `jcmd` only when JMX failed. The agent stays open (RMI, no authentication, local peers) until the process ends. | medium | #PR |
| 3 | heapcheck | A process in another mount namespace, checked without `--in-target`, wrote the dump into its own `/tmp`: the check did not find it and failed, and the dump of everything in the heap stayed there. | medium | #PR |

## Round 7 - November 2026

Scope: the logins of `seclume-mail` (SMTP, IMAP, POP3) and `seclume-ldap`.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | Mail, LDAP | The read timeout was per read. A server - or anyone on the path before STARTTLS - that sends one byte just before each read would time out held a login, and LDAP's StartTLS and handshake inside JNDI's connect, without end (1 s timeout, still blocked after 20 s). The login now has `seclume.loginBudgetFactor` (3) times the read timeout as a whole. | low | #PR |

### Open

None. The deadline for the TLS handshake itself, wherever it runs, came with the audit
(finding 50).

## Round 8 - November 2026

Scope: `SecretFetch` (Vault, AWS, Azure, GCP, their KMS, the metadata services) and the Redis
socket factory.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | Secret providers | `SecretFetch` passed its timeout to the connect only: a server that took the connection and said nothing held the handshake and the answer for good (`timeoutMillis=1000`, still blocked after 15 s), and every login waiting for that secret with it. | low | #PR |
| 2 | Redis | `SeclumeRedisSocketFactory` set its read timeout after the TLS handshake: a silent `rediss://` server held Jedis's `createSocket` for good. | low | #PR |

## Round 9 - November 2026

Scope: `SeclumeSslSocketFactory` of `seclume-http`.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | HTTP | `createSocket(host, port)` opens the connection and runs seclume's TLS at once; `connectTimeout` bounded the connect only, so a silent server held the handshake for good. The layered `createSocket(socket, ...)` was not affected. | low | #PR |

## Round 10 - November 2026

Scope: `SeclumeS3Presigner` of `seclume-aws`.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | AWS | The bucket went into the host of a virtual-host style URL unchecked: a bucket `evil.example#` made a presigned "link to S3" whose host is `evil.example`. An application that takes the bucket from its user handed out links to wherever the user chose. | medium | #PR |

## Round 11 - November 2026

Scope: `QueryFingerprint` in every dialect.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | Fingerprints | A backslash was taken for an escape in every dialect and quoting form. A run masked too long ends at the quote that opens the next literal, whose contents were then read as words: `VALUES ('C:\data\', 'secret')` gave `values (?secret?`, and a quoted identifier ending in a backslash copied the rest of the statement verbatim - into JFR events, OpenTelemetry spans, Micrometer tags and `lastFingerprint`. About 37,000 leaks in 100,000 random statements before, none in 300,000 after. | high | #PR |

## Round 12 - November 2026

Scope: `JdbcUrl.redact`, the log masker's encodings, `PgSqlRewriter`.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | JDBC URL redaction | Before the query a value ended at any of `; , ( )` - wrong for SQL Server's `;`-separated values, which hold `, ( )`, and the other way round for a `;` in a MySQL key-value password; an Oracle password in quotes with a `//` in it was printed whole. 2,875 of 60,000 random passwords had a half shown before, none of 240,000 after. | medium | #PR |
| 2 | Log masker | A secret was looked for percent-encoded only as RFC 3986 strictly or `URLEncoder` encode it, and JSON-escaped only for `"` `\` and line breaks. `java.net.URI`, Spring and OkHttp encode only what their part of a URL does not allow, and Gson escapes `= ' < > &` as backslash-u: of 2,000 random passwords, 925 and 1,191 went unmasked. | medium | #PR |
| 3 | PostgreSQL | `PgSqlRewriter` did not tell `E'...'` apart: in `E'it\'s ?'` the `?` became `$1` and a real one after it stayed `?`. A refused statement, not an injection. | low | #PR |

## Round 13 - November 2026

Scope: what the heap dump redaction, heapcheck and the TCK look for.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | Heap dumps | A named secret was looked for as UTF-8, UTF-16, Latin-1 and its own Base64. In `Authorization: Basic base64(user:password)` its Base64 begins where the user name leaves it; URL-safe, percent-encoded and JSON-escaped forms were not looked for either. A redacted copy "passed its own check" with twelve Basic headers decoding to the password; heapcheck found nothing in a process that held it only in a header; `/actuator/heapdump` and the TCK's heap tests had the same patterns. One shared list (`SecretEncodings`) now. | high | #PR |

## Round 14 - November 2026

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | Heap dump discovery | Copies of a discovered credential were looked for as its own padded Base64 only: a discovered URL password also held in a Basic value `base64("app:" + pw)`, and a discovered token as URL-safe Base64, stayed in the redacted copy, which passed its own check. Echoes take the encodings list now. | medium | #PR |
| 2 | Discovery detector `http-authorization` | Only `Authorization: Basic <b64>` in one string was found. HTTP clients keep the value apart from its name (Apache `BasicHeader`, the JDK's `HttpClient`, Spring's `HttpHeaders`); `Basic <b64>` alone, in lower case, or the bare Base64 stayed in the copy, decodable. A second detector, `http-credential-value`, takes a bare `Basic` value that decodes to `user:password` and a `Bearer` token of twenty characters or more, in any case. | medium | #PR |

### Open

- Base64 of `user:password` held with neither `Authorization:` nor `Basic` before it is not
  found: without a word to anchor on, every Base64 run of a dump would have to be decoded, and
  most of what decodes to text with a colon in it is no credential (finding 2).

### Reviewed, nothing found

- With round 13's stricter scanner, the heap dump and `NoSecretInHeap` tests that run here
  (19 classes) found nothing they did not before. The module tests that need a database or a
  client library (mail, HTTP, AWS, Kafka, Redis, MongoDB, LDAP, ...) are for CI.

## Round 15 - November 2026

Scope: `seclume-logging`'s Logback, Log4j 2 and java.util.logging adapters.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | Logback | The documented rules replaced `%msg` and `%xEx` only, and a rule replaces the converter of its one word. Spring Boot's patterns write `%m` and `%wEx`, so with `logback-spring.xml` as documented neither message nor stack trace was masked; `%ex`, `%throwable`, `%rEx`, `%message`, the stack trace Logback adds to a pattern without one, and JSON encoders were not either. `redact-rules.xml` registers every word now, and `RedactingEncoder` masks a whole line. | high | #PR |
| 2 | Log masker | `java.util.logging`'s `XMLFormatter` writes `& < >` as entities: a secret with one of them went to the log unmasked, in the message and in the exception. A line with `&` is also read with its character references resolved now. | medium | #PR |

The round's own changes were reviewed once more before they were handed on: a
`RedactingEncoder` with neither a pattern nor an encoder threw out of Logback's configuration
(it reports an error and writes nothing now); `redact-rules.xml` included before Spring Boot's
`defaults.xml` lost `%wex` and `%wEx` without a word (Logback's status warns now); numeric
character references with leading zeros were not read, and non-ASCII digits were.

### Open, since closed (#PR)

- With `seclume.logging.redact=true` and no `logback-spring.xml`, nothing is masked by Logback:
  the starter says so at start, and `seclume.logging.redact.strict=true` refuses to start.
- A pattern that cuts the message (`%.20msg` inside `%redact{...}`, a precision in
  `SimpleFormatter`'s format) leaves the start of a secret that is cut through: documented in
  DIAGNOSTICS.md, with the order that works.
- Log4j 2's layout appends a stack trace unmasked where `%redact{...}` has no stack trace word
  in it: its status log says so.
- Spring Boot's structured logging in its own `base.xml` appenders cannot be wrapped in
  `RedactingEncoder`: DIAGNOSTICS.md shows the appender of the application's own.

### Reviewed, nothing found

- java.util.logging with `SimpleFormatter`; Log4j 2's `%redact` masks the whole inner pattern,
  Spring Boot's `%xwEx` included (read, not run - Log4j 2 was not at hand).

## Round 16 - November 2026

Scope: `seclume-kubernetes` and `seclume-jpa`.

| # | Area | Finding | Severity | Fixed in |
|---|------|---------|----------|----------|
| 1 | JPA | `EncryptedStringConverter` and `EncryptedBytesConverter` encrypt without a context - a converter is not told its entity - so whoever can write to the table can copy a value into another row of the same column, and it is read there as that row's own: one's own bank account, entered through the application, into another customer's row. ENCRYPTION.md promised the binding for the JDBC API and said nothing of the converters; it does now, with `Sealed` sealed with the row's id. | low | #PR (documentation) |

### Reviewed, nothing found

- **Kubernetes**: the token's placeholder is bound to the API server's `host:port`, compared
  in lower case with IPv6 in brackets; a client pointed elsewhere, or a redirect, sends the
  placeholder.
- **JPA converters**: the plaintext length is exact, the buffer of a `String` attribute is
  wiped, a value that does not authenticate leaves nothing in the target; the ring is taken
  at the first value and kept, as the documented rotation (a new key in the ring, then a
  restart) expects.

## The next review

`SeclumeCollection`, `Iterables` and `BatchCursor` of `seclume-mongodb-driver` have been
read line by line since (findings 29 to 31, each shown failing in the build by its test
before the fix), except the overloads of `find`, `aggregate`, `distinct` and `watch` that
only pass their arguments on. Not read line by line in this round: `Indexes`, `Bsons`,
`SeclumeDatabase` and `EncryptedFields` of that driver. A
round adds a section here, findings and the sound alike.

After round 16: the open items of rounds 7, 14 and 15 above, and the modules not read in any
round yet - `seclume-micronaut`, `seclume-helidon`, `seclume-mongodb-reactive`, the Spring
Boot starter as a whole, and most of the SQL Server and PostgreSQL drivers.
