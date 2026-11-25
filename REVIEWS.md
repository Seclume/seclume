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

- **MD5 and `mysql_native_password` over an unauthenticated connection.** TLS.md says these
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

### Open

- MD5 and `mysql_native_password` over an unauthenticated connection (round 4, "Open") are
  still a decision with compatibility cost.

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

### Open

- With `seclume.logging.redact=true` and no `logback-spring.xml`, nothing is masked by Logback;
  the starter could say so at start.
- A pattern that cuts the message (`%.20msg` inside `%redact{...}`, a precision in
  `SimpleFormatter`'s format) leaves the start of a secret that is cut through.
- Log4j 2's layout appends a stack trace unmasked where `%redact{...}` has no stack trace word
  in it; its status log could say so.
- Spring Boot's structured logging in its own `base.xml` appenders cannot be wrapped in
  `RedactingEncoder`; that takes an appender of the application's own.

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
