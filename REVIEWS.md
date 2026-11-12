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
| 19 | `seclume-mongodb-driver` | The largest reply was whatever the `hello` named as `maxMessageSizeBytes` - answered before the login - and a reply's announced length is allocated once it is below that: a server naming 2 GB had the client allocate 2 GB for a 16-byte header. Capped at the 48 MB of every server. | low | #299 |
| 20 | `seclume-mongodb-driver` | A document named `cursor` inside the application's data was read like the reply's cursor: its `firstBatch` documents came back immutable. | low | #299 |
| 21 | `seclume-mongodb-driver` | The monitor - one thread for all servers - read a `hello` outside its `try`: one with a field of an unexpected type (`tags`, `hosts`, `electionId`, a member that is no address) threw through the thread and ended it. No server was looked at again for the life of the client. | medium | #300 |
| 22 | `seclume-mongodb-driver` | `close()` waited `serverSelectionTimeoutMS` for a server to end its sessions on, when none was known. | low | #300 |
| 23 | `seclume-http` | The same as #17 where every HTTP client goes through: the head collected so far was copied for each byte of it (316 µs for a head of 1491 bytes, 15 µs now), chunk framing went a TLS record per byte. | low | #301 |
| 24 | `seclume-redis` | The follower that finds the password's place looked at every byte a connection writes, a value's too: 351 µs of its own for a `SET` of 64 KiB, 0.5 µs now. | low | #302 |
| 25 | `seclume-mongodb-driver` | A client `bulkWrite` without a session of the application's ran in a server session that was given back with the command's reply; a `getMore` for results that did not fit that reply named no session. Read in the code; the test is in the CI first, the fix follows it. | low | #303 |
| 26 | `seclume-mongodb-driver` | A batch too large for one message was encoded whole to find that out, halved, and encoded again - from the limit for every part. | low | #304 |
| 27 | `seclume-mongodb-driver` | `hasNext()` of a change stream looped on a cursor the server had closed - after the `invalidate` that follows a dropped collection - and never returned: a thread spinning on a CPU. Read in the code; the test is in the CI first, the fix follows it. | medium | #305 |

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

## Round 3 - 8 to 11 November 2026

Property and model tests of the parsers that decide where a secret goes, then the modules
the last round named and the rest of the network-facing ones: `seclume-keys`, `seclume-jwt`,
the admission webhook's server, the access log, `seclume-diff`, `seclume-http`,
`seclume-mail`, `seclume-ldap`, `seclume-r2dbc`, `seclume-redis`, `seclume-kafka`,
`seclume-nats`, `seclume-rabbitmq`, `seclume-ssh`, `seclume-elasticsearch`, `seclume-grpc`,
`seclume-jgit`, the cloud providers (`seclume-aws`, `seclume-azure`, `seclume-gcp`), and of
MongoDB the URL, the SRV lookup and the logins. Every finding was reproduced by a test that
failed before its fix.

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

### Open

- Making `differential.yml` a required check once it has been green for a while (#286).
- `Differential.compareCatalog` passes over a column neither driver lists without a word -
  on Oracle every column, the names being upper case there. To be made a finding once the
  workflow runs.

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

## The next review

Not yet read with the same care: of `seclume-mongodb-driver` the two largest API classes,
`SeclumeCollection` and `Iterables` (the options of each command, some 2800 lines); the
wire, the sessions, the topology, cursors, change streams and the bulk writes are read. A
round adds a section here, findings and the sound alike.
