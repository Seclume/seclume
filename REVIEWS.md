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

## Round 3 - 8 to 11 November 2026

Property and model tests of the parsers that decide where a secret goes, then the modules
the last round named and the rest of the network-facing ones: `seclume-keys`, `seclume-jwt`,
the admission webhook's server, the access log, `seclume-diff`, `seclume-http`,
`seclume-mail`, `seclume-ldap`, `seclume-r2dbc`. Every finding was reproduced by a test that
failed before its fix.

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
| 11 | `seclume-diff` | The differential tests against pgjdbc, Connector/J, mssql-jdbc and ojdbc skip without a server, and no CI job started one: of the module CI ran `PgBouncerTest` alone, while TESTING.md and SECURITY-QUALITY.md said every pull request. Oracle's `getColumns` was never compared, in addition (#8). | process | #286 |

### Open

- What `differential.yml` finds on its first runs, and making it a required check once it is
  green (#286).
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
- **R2DBC**: the `password` option is refused; the SQL lexer leaves literals, comments,
  E-strings, dollar quotes and Oracle's `q'...'` alone.

### Accepted residuals

- `seclume-http`: only the first placeholder in one HTTP/2 field value or one Basic credential
  is replaced; a second goes out as the placeholder, which the server refuses.
- `seclume-http`: a placeholder in any header line is replaced, so a header an application
  fills from user input could carry one a user had seen - a placeholder is not a secret, but
  it is bound to one server and has a random 96-bit nonce per process.
- `seclume-r2dbc`: the factory provider puts the host and database name into the JDBC URL
  unencoded; both come from the application's configuration.

## The next review

Not yet read with the same care: `seclume-ssh`, `seclume-jgit`, `seclume-grpc`, `seclume-kafka`,
`seclume-redis`, the MongoDB driver, and the pool's session reset once it is made cheaper. A
round adds a section here, findings and the sound alike.
