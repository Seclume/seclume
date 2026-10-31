# Seeing what happened, without seeing the values

Flight Recorder events, Micrometer meters, OpenTelemetry spans, an actuator endpoint and three
diagnostics for specific defects. One rule holds for all of them: bind values, SQL text,
secrets and anything derived from a secret are never recorded, not even a secret's length or
hash. The database user is not recorded either; it is not a secret, but nothing here needs it
for a diagnosis.

## Flight Recorder events

No runtime dependency: JFR is in the JDK, it is off until somebody starts a recording, and
while off it costs an `isEnabled()` the JIT folds away.

```
java -XX:StartFlightRecording=filename=app.jfr,settings=profile ...
```

| Event | What it answers |
|---|---|
| `space.seclume.ConnectionOpen` | how long a physical connect, TLS and login really take |
| `space.seclume.TlsHandshake` | whether the slow part is the handshake and which stack ran it |
| `space.seclume.Authentication` | the login on its own, and by what method the server asked for it — databases (MongoDB with its mechanism), mail (SMTP, IMAP, POP3), Redis through Jedis, Kafka's SCRAM |
| `space.seclume.Query` | which statements are slow — over 10 ms by default, lower it in the recording settings |
| `space.seclume.PoolWait` | the one an operator wants when the app is slow and the database is idle |
| `space.seclume.Failover` | which server was passed over, why, and **how long it took to not answer** |
| `space.seclume.CredentialRotation` | that a secret was fetched, how long it took, and when it expires |
| `space.seclume.StatementCache` | whether server-side plans are actually being reused |
| `space.seclume.SecretUse` | which credential seclume wrote into which request: HTTP (bearer, basic, API key, OAuth2, JWT), any client on `SeclumeSslSocketFactory` - Kubernetes, JGit, gRPC over HTTP/2 - AWS (SigV4, presign, session token), Azure Storage (Shared Key), LDAP bind, RabbitMQ login, Redis `AUTH` through Lettuce, Kafka's SASL PLAIN and OAUTHBEARER, the Elasticsearch and OpenSearch clients |
| `space.seclume.Signature` | a signature made or checked with a key held off the heap: TLS server keys, SSH, Google service accounts, JWTs, webhook HMACs — and whether a check matched |
| `space.seclume.SecretRotation` | a secret that changed at its source and was taken up without a restart, or refused |
| `space.seclume.CertificateRenewal` | a certificate from Vault's PKI for a key made off the heap - issued, renewed, or a renewal that failed, and until when the one in use holds |
| `space.seclume.RemoteSignature` | a signature made by a key in a key management service (`kms=`): which key, how long the round trip took - what each handshake now waits for - or why the service did not sign |
| `space.seclume.HeapDumpRedaction` | a heap dump redacted - by `--redact`, `/actuator/heapdump` or a watched dump folder - with what was overwritten, or why it could not be made clean |

**An open is three phases, and one number hides which of them is slow.** The connect is the
network. The handshake is certificates and whatever the JVM looks up to trust one. The login
is the directory *behind* the database: LDAP, PAM, Kerberos, an IAM token. Measured against
the four local servers in this repository, the split is different every time:

| | login | whole open |
|---|---|---|
| PostgreSQL (`tls=off`) | 134 ms | 145 ms |
| MySQL (`tls=off`) | 2.8 ms | 5.0 ms |
| SQL Server (TLS) | 4.8 ms | 68 ms |
| Oracle | 160 ms | 177 ms |

Three of the four spend most of an open logging in; SQL Server spends most of it on the
handshake. Nobody could have told that from `ConnectionOpen` alone, which is the argument for
the separate event.

## A statement is named by its shape, never by its text

```
select * from customer where id = 42 and name = 'alice'
select * from customer where id = ? and name = ?
```

That is `QueryFingerprint`, and it is the reason these events are safe to keep. A recording is
written to a file, kept for weeks and handed to whoever is debugging. That is a longer life and
a wider audience than a heap dump gets, and this library goes to some lengths about heap
dumps. So a value in a JFR event would be worse than one on the heap, not better.

The fingerprint replaces literals of every quoting form each dialect has, numbers, and every
placeholder spelling. `in (?, ?, ?)` collapses to `in (?)`, so one query stays one entry. Where
a dialect makes it ambiguous whether something is an identifier or a string (`"x"` in MySQL),
the fingerprint gives up the identifier rather than risk the value.

**MongoDB** records each command the same way, by its shape - seclume's own driver directly,
the official driver through a command listener `SeclumeMongo` installs:

```
find shop.orders filter {status: ?, total: {$gt: ?}}
aggregate shop.orders pipeline ({$match: {tags: {$in: ?}}}, {$group: {_id: ?, n: {$sum: ?}}})
```

The command, the namespace, and the field names and operators of its filter, sort, projection,
update or pipeline; every value is a `?`, and a field name that is not a name - a map keyed by
data - is masked too. The monitor's `hello`, which waits on the server on purpose, and the login
commands are not recorded as queries. A new primary, and a read or write retried on another
connection, are `Failover` events; the login is an `Authentication` event with the mechanism
(`SCRAM-SHA-256`, `MONGODB-X509`, `MONGODB-AWS`, `MONGODB-OIDC`, and an OIDC login again when the
server says the token expired). `LocalMongoEventsTest` plants a value in a document and a filter
and searches every field of every event for it.

## The same events as metrics

JFR makes the better recording, but almost nobody reads it: reading it takes somebody noticing
a problem, dumping a file and opening a tool. So the Spring Boot starter can turn those events
into Micrometer meters as they happen: `seclume.query.slow`, `seclume.statement.cache`,
`seclume.connection.open` and `seclume.failover` for the databases, and for every module:

| Meter | Tags |
|---|---|
| `seclume.authentications` (timer) | `kind` (postgresql, smtp …), `method`, `outcome` |
| `seclume.secret.uses` (counter) | `kind` (http, aws, azure-storage, ldap, rabbitmq …), `mechanism` |
| `seclume.signatures` (timer) | `algorithm`, `operation` (sign, verify), `outcome` |
| `seclume.secret.reads` (timer) | `provider` (file, vault …), `outcome` |
| `seclume.secret.rotations` (counter) | `watch`, `outcome` |
| `seclume.tls.handshakes` (timer) | `stack` |

No meter is tagged by a user, a target host or anything else that grows with traffic. The
drivers and modules need no second instrumentation, and a meter carries nothing the events do
not already carry.

```properties
seclume.metrics.queries=true              # or seclume.metrics.events=true without a database
seclume.metrics.query-threshold=10ms      # what counts as slow
seclume.metrics.query-fingerprints=100    # how many shapes get a tag of their own
```

Off by default, because it starts a Flight Recorder stream, which changes the state of the
process it runs in. The last line matters too. A tag per statement shape is what makes these
meters worth having, and it is also the classic way to bring a metrics backend down. Beyond
the bound, shapes are counted together under `other`: the totals stay right, and only the
attribution stops.

### The pool's meters

With Micrometer on the class path the starter registers each pool's numbers, tagged by
`pool`:

| Meter | Type | What |
|---|---|---|
| `seclume.pool.connections`, `.active`, `.idle`, `.pending` | gauge | connections held, in use, free; threads waiting |
| `seclume.pool.connections.max` | gauge | the configured maximum |
| `seclume.pool.acquire` | timer, histogram | from asking to holding a connection, opening one included |
| `seclume.pool.usage` | timer, histogram | how long the application held it |
| `seclume.pool.creation` | timer, histogram | opening a connection: TCP, TLS and login |
| `seclume.pool.borrowed`, `.created`, `.retired` | counter | handed out, opened, thrown away |
| `seclume.pool.timeouts`, `.leaks`, `.renewed` | counter | borrows that gave up, connections held too long, rebuilt under the application |
| `seclume.pool.resets.refused` | counter | session resets that failed; each closed its connection |
| `seclume.pool.secret.rotations` | counter | rotations the pool took up |

The three timers come from `PoolListener`, which the pool calls only when somebody listens: a
pool without one reads no extra clock. With `seclume.metrics.hikari-names=true` the same
numbers also appear as `hikaricp.connections.*`, timers included.

`demo/grafana` has a dashboard built on these and on the event meters above.

### OpenTelemetry metrics, without Micrometer

`seclume-opentelemetry` is the same bridge for an application that exports with OpenTelemetry
and has no Micrometer, Spring or not. It depends on `opentelemetry-api` alone, which the
application's SDK or agent brings:

```java
SeclumeMetrics metrics = SeclumeMetrics.start(openTelemetry);          // the events above
AutoCloseable pool = SeclumePoolInstruments.observe(openTelemetry, seclumePool);
...
pool.close();
metrics.close();
```

The event instruments have the starter's names and attributes, under the instrumentation scope
`space.seclume`; the timers are histograms in seconds. The pool follows OpenTelemetry's
semantic conventions for connection pools, so a dashboard built for those reads it as it is:

| Instrument | Type | What |
|---|---|---|
| `db.client.connection.count` | up-down counter, `state` = `idle`/`used` | connections the pool holds |
| `db.client.connection.max`, `.idle.min` | up-down counter | the configured limits |
| `db.client.connection.pending_requests` | up-down counter | threads waiting for a connection |
| `db.client.connection.timeouts` | counter | borrows that gave up waiting |
| `db.client.connection.wait_time`, `.use_time`, `.create_time` | histogram (s) | getting a connection, holding it, opening one |
| `seclume.pool.secret.rotations`, `seclume.pool.resets.refused` | counter | the two numbers only this pool has |
| `seclume.certificate.expiry` | gauge (s) | seconds until a self-renewing certificate ends, attributed `bundle` - see below |
| `seclume.certificate.renewal.failing` | gauge | 1 while that certificate's last renewal failed |

Every instrument carries `db.client.connection.pool.name`. Like the starter's meters, nothing
is measured until `start` is called: the stream is the application's decision.

In a Spring Boot application the starter does both with one property, through the application's
own `OpenTelemetry` bean, for every configured data source:

```properties
seclume.metrics.opentelemetry=true        # with seclume-opentelemetry and an OpenTelemetry bean
seclume.metrics.query-threshold=10ms      # shared with the Micrometer meters
seclume.metrics.query-fingerprints=100
```

## Tracing

**Tracing is the one thing that needed a hook.** A span belongs to the request that caused it,
and which request that is lives in the calling thread's context *while the statement runs*.
A span built afterwards from a recording would have the right duration and no parent, and
that is not a worse trace but no trace at all. So `StatementListener` exists: one interface in
the core, with no dependency, and a no-op until something installs one. With the
OpenTelemetry API on the class path, an `OpenTelemetry` bean to hang spans on, and
`seclume.tracing=true`, every statement becomes a CLIENT span on the request that ran it.

A span follows OpenTelemetry's stable database conventions:

- `db.system.name` and `db.operation.name`.
- `db.query.text`, which is the fingerprint. That is the only form the listener is ever
  given; the conventions ask for the text to be sanitised, and here it cannot be anything
  else.
- The span *name* is `db.query.summary`: the operation and its first table, such as
  `SELECT orders`. It is kept low in cardinality, since every backend that stores span names
  uses them as an index key.
- `error.type` on a failed statement.

`OTEL_SEMCONV_STABILITY_OPT_IN=database/dup` adds the old names (`db.system`, `db.statement`,
`db.operation`) for a backend that still reads them.

## `/actuator/seclume`: how every data source is secured

This is the question an audit asks and an application usually cannot answer. With the actuator
on the class path, the starter registers an endpoint. Expose it like any other:

```properties
management.endpoints.web.exposure.include=seclume
```

For each pool it reports:

- the login method, as the protocol names it (`scram-sha-256-plus`);
- the TLS protocol, suite and stack;
- the certificate the server showed: subject, issuer and **expiry**, which is the date that
  ends in an outage when nobody looks;
- how many connections the server allows and how many are in use;
- the pool's own numbers;
- the seclume version.

It never reports a password, a statement or a value. `Version.current()` gives the same
version to an application that wants to log it at start.

**An assessment per data source.** Facts need someone who knows which of them matter, so the
endpoint and the health details also grade each data source: `ok`, `note`, `warning` or
`critical`, the worst of its findings, and the findings themselves, worst first.

| Level | Finding |
|---|---|
| critical | no TLS; the server's certificate has expired or expires within 7 days |
| warning | the certificate expires within 30 days; a login that sends the password or a hash standing for it (`trust`, `password`, `md5`, `mysql_native_password`, `mysql_clear_password`); borrows that timed out; all connections in use with threads waiting; leaks; refused resets |
| note | TLS 1.2 where the server offers no 1.3; a SQL Server login with a password |

**The application's own certificates.** Certificates that seclume-keys keeps current appear
under `certificates`: one from Vault's PKI (`vault-pki`), a SPIFFE X.509-SVID (`spiffe`), or a
pair reloaded from disk (`reload-interval`). Each entry shows its subject, validity, next renewal, how many pairs it
has had, the last failure to replace it with its reason, and a grade of its own.

- **A certificate that renews itself** is judged by its own lifetime. A 24-hour Vault
  certificate is not critical just for expiring within a week. It gets a warning when a
  renewal fails or is overdue, and becomes critical when a tenth of its life is left and it
  still has not been replaced.
- **A certificate renewed on disk** by somebody else is judged in days, like a server's.

Two meters per such bundle, tagged `bundle`, make the same alert possible without polling the
endpoint:

- `seclume.certificate.expiry`: seconds until the certificate in use ends;
- `seclume.certificate.renewal.failing`: 1 while its last renewal failed.

With `seclume.metrics.opentelemetry=true` and seclume-opentelemetry on the class path the same
two are OpenTelemetry gauges, attributed `bundle`, through the application's `OpenTelemetry`
bean - for an application that exports with OpenTelemetry alone. Without the starter,
`SeclumeCertificateInstruments.observe(openTelemetry, names, reading)` does it for any
certificate the application can name. A certificate that is not there yet is left out of a
collection rather than reported as a number it does not have.

Each renewal, and each failed one, is a `space.seclume.CertificateRenewal` event in the Flight
Recorder.

The grade never takes the health status down. Health is what a load balancer acts on, and a
certificate expiring next week taking every instance out of service at once would turn a
warning into the outage it warns of. Whether the database can be reached stays the health
check's question alone; alert on the grade instead.

## `/actuator/heapdump`: a redacted copy, never the heap itself

Spring Boot's heap dump endpoint hands out everything the application holds - every password,
token and key on its heap - to whoever may call it, as a file that then lives on in a ticket or
on a laptop. With the actuator on the class path, the starter puts its own endpoint in that
place. It takes the dump the same way and serves a **redacted copy**:

- every credential of a known shape is overwritten - private keys, JWTs, cloud and platform
  tokens, passwords in URLs and URL parameters, `Authorization` values; the 17 detectors of
  [`seclume-heapcheck --discover`](DIAGNOSTICS.md#credentials-nobody-named---discover) - and so
  are their copies and parts where they have no shape: a URL's password in a field of its
  own, a JWT's payload, a token's body without its prefix;
- in place, with `*` or zeros, so the copy opens in any analyser, and the `hash` of every
  `String` whose text went is cleared;
- the copy is searched again before it is served, and the dump itself is deleted before the
  response starts.

It fails closed: if the copy cannot be made clean, or the dump cannot be read as HPROF
(OpenJ9 writes another format), the response is 500 and nothing is served. Exposing the
endpoint is still a decision of its own, and Boot leaves it off:

```properties
management.endpoint.heapdump.access=read-only
management.endpoints.web.exposure.include=heapdump
seclume.heapdump.ignore=jwt           # optional: detectors to leave out; a typo stops the start
seclume.heapdump.redact=false         # optional: Boot's endpoint, unredacted
```

**The dumps the JVM writes by itself.** With `-XX:+HeapDumpOnOutOfMemoryError` the starter
also watches where they land and redacts each one next to itself, deleting the original - see
[DIAGNOSTICS.md](DIAGNOSTICS.md#the-dumps-nobody-asked-for---redact-dir---watch)
(`seclume.heapdump.oom.*`).

**The application's own secrets, too, without a copy on the heap.** A password of no known
shape is invisible to discovery. The application knows its own secrets, though, and seclume
holds them in native memory. So the endpoint, and the redaction of OOM dumps, also look for
each data source's password and for whatever `seclume.heapdump.secrets.<label>.*` names, in a
secret provider's settings:

```properties
seclume.heapdump.secrets.payments-api.provider=file
seclume.heapdump.secrets.payments-api.path=/run/secrets/payments-api-key
```

How the search stays off the heap:

- **Reading the secret.** For each redaction every provider writes its secret into locked
  native memory.
- **Building the patterns.** The search patterns (UTF-16 both ways, Base64) are built there
  too, not in Java arrays.
- **Searching.** The dump is searched in native windows.
- **Afterwards.** All of it is zeroed when the redaction is over.

A secret that never left native memory is not in the dump at all. What the search finds is a
copy that did leave, in a log line, a configuration object or an exception message, and that
copy goes. A credential neither named nor of a known shape stays. Find those with
`seclume-heapcheck --secret-file` or `NoSecretInHeap`, and keep them off the heap. Redaction reads the dump a few times, at about
40 MB a second for discovery, so a large heap takes a while to come back.

## `/actuator/cbom`: the cryptography the application uses

A CycloneDX 1.6 cryptography bill of materials (CBOM) of what the application actually used,
recorded where seclume does the work - nothing has to be declared:

| Asset | Recorded when | What is in the CBOM |
|---|---|---|
| A secret | a provider is read (`SecretScope.fromProvider`) | the provider's kind and its own description (a path, a URL), how often and when, its expiry - `credential` or `token` |
| A field encryption key | a `FieldKeys` ring is built | AES-256-GCM-SIV, 256 bits, its number, whether primary, the provider it came from; gone when the ring is closed |
| A private key | OpenSSL, CNG or a KMS key is opened | its algorithm and size from the public half, and what holds it (`OpenSSL`, `CNG`, `AWS KMS key ...`) |
| A TLS session | a handshake finishes, on seclume's stack or JSSE | the peer, the version, the cipher suite and the key exchange - `X25519MLKEM768` or a classical group |
| A server certificate | the same handshake | subject, issuer, validity, signature algorithm, public key |
| An algorithm | used by any of the above | primitive, mode, parameters, classical security level and **NIST quantum security level** |

The quantum level is the point: 0 for RSA, ECDSA, ECDH and X25519, which a quantum computer
breaks; 1, 3 or 5 for AES-128, AES-192 and AES-256; 3 for ML-KEM-768 and the hybrid
X25519MLKEM768. `metadata.properties` carries `seclume:quantum-vulnerable`, the number of
keys, certificates and TLS key exchanges at level 0 - where a migration to post-quantum
cryptography starts.

```properties
management.endpoints.web.exposure.include=cbom
```

```bash
curl -s localhost:8080/actuator/cbom          # application/vnd.cyclonedx+json
java -jar seclume-verify.jar --cbom "jdbc:seclume:postgresql://db/app?provider=file&path=..."
```

Without Spring, `CycloneDxCbom.write("orders")` returns the same document and
`CryptoInventory.snapshot()` the assets themselves.

**Facts, never values.** A secret is in the CBOM as where it came from and when - never its
value, its length, a fingerprint or a hash. Providers and keys are held weakly: what the
application lets go of drops out. TLS sessions are kept per peer and suite, at most 512.

**Checked.** CI writes one CBOM with an asset of every kind and one from an application that
opened a field encryption key through Vault over TLS, and checks both against CycloneDX's own
JSON schema (`.github/ci-tools/validate-cbom.mjs`); the tests search both for the secrets the
application read (`CryptoInventoryTest`, `CycloneDxCbomTest`, `InventoryEndToEndTest`,
`CbomEndpointTest`).

## The access log: who read which secret, and proof that nobody changed it

`space.seclume.audit.AccessLog` writes an entry for every secret a provider is asked for
(`secret.read`: the provider's kind and description, the thread, `ok` or `failed` with the
exception's type), every field encryption key ring built (`data-key.ring`) and every private
key opened (`private-key.opened`) - facts, never the secret, its length or a hash of it.

```properties
seclume.audit.file=/var/log/orders/seclume-access.jsonl
seclume.audit.checkpoint-interval=1m
seclume.audit.signing-key.kms=aws-kms            # or vault-transit, gcp-kms, azure-key-vault
seclume.audit.signing-key.key=alias/orders-audit
seclume.audit.signing-key.region=eu-central-1
seclume.audit.signing-key.credentials=web-identity
```

One JSON object per line, ASCII only. Each entry carries `prev`, the hash of the one before,
and `hash`, SHA-256 of itself without that field; every `checkpoint-interval` and at shutdown a
`checkpoint` entry signs `"seclume-access-log-1" || seq || head` with the signing key - best a
KMS key, so that whoever can write the file cannot sign for it. One process writes a file (a
`.lock` file beside it says which); a restart continues the chain.

```bash
java -jar seclume-verify.jar --audit-verify seclume-access.jsonl audit-key.pem
```

finds an entry changed, removed, swapped or slipped in, and a chain re-hashed by someone without
the key - at its next checkpoint. **What it cannot find on its own** is entries cut off at the
end together with their checkpoints: the shorter log is valid. That is what a copy elsewhere is
for - `SeclumeAccessLogExporter` (`seclume-opentelemetry`, wired by the starter when there is an
`OpenTelemetry` bean) sends every entry as a log record whose body is the line itself, so the
copy verifies with the same tool, and its last head tells a cut log from a short one.

Tested by changing, removing, swapping and re-hashing entries, another key, a torn last line,
a cut tail (which holds, as documented), a reopened and a rotated log, a second writer, sinks
that fail, the timer, non-ASCII descriptions, a strict entry parser (`AccessLogTest`,
`AccessLogAutoConfigurationTest`, `SeclumeAccessLogExporterTest`, `AuditVerifyTest`); CI checks
a signed log with a second implementation - hashlib and the openssl command line,
`.github/scripts/verify_access_log.py` - and that it refuses a changed and a re-hashed copy.

## A crypto policy, checked at start-up, in the health check and in the pipeline

The inventory judged against rules - `space.seclume.inventory.CryptoPolicy`:

| Rule | Default | Fails |
|---|---|---|
| `rsa.min-bits` | 2048 | an RSA key, the server's or our own, below it |
| `ec.min-bits` | 256 | an elliptic curve key below it |
| `tls.min-version` | 1.2 | a session below it (`1.2` or `1.3`) |
| `tls.forward-secrecy` | true | a TLS 1.2 suite without (EC)DHE |
| `tls.require-hybrid` | false | a key exchange that is not the ML-KEM hybrid |
| `certificate.min-days` | 14 | a server certificate this close to its end, or past it |
| `signature.forbidden` | `SHA1,MD5` | a certificate signed with one of them |
| `algorithm.forbidden` | - | a key, cipher suite or key exchange that names one |
| `secret.forbidden-providers` | - | a secret from one of them, say `file,env-file` in production |
| `data-key.require-kms` | false | a field encryption key not from `kms-decrypt`, `vault-transit` or `shamir` |
| `data-key.forbidden-providers` | - | a field encryption key from one of them |
| `quantum` | `warn` | (`fail`) anything a quantum computer breaks; `off` says nothing |
| `warn-only` | - | nothing: the rules named only warn |

```properties
seclume.crypto-policy.rules.rsa.min-bits=3072
seclume.crypto-policy.rules.tls.require-hybrid=true
seclume.crypto-policy.rules.secret.forbidden-providers=file
seclume.crypto-policy.on-start=fail          # off, warn (default) or fail
```

At start-up, when the pools have made their first connections, `warn` logs every finding and
`fail` stops the application on a failing one. The `cryptoPolicy` health contributor is `DOWN`
while the policy fails - a session that fell back to a classical key exchange, a certificate
about to lapse - with the findings as details; warnings never decide it.
`seclume.crypto-policy.enabled=false` turns all of it off.

In a pipeline, against a CBOM the build kept, or the inventory of one connection:

```bash
java -jar seclume-verify.jar --policy policy.properties cbom.json           # exit 1: it fails
java -jar seclume-verify.jar --cbom-diff last-release.json cbom.json       # exit 1: a step back
java -jar seclume-verify.jar --quantum cbom.json                           # the readiness report
```

`--cbom-diff` matches assets by what they are, not by their `bom-ref`, and calls a step back a
new asset a quantum computer breaks, or one that changed to a lower TLS version, a smaller key,
fewer AES bits or lost its post-quantum level. As a GitHub Action, the report in the job
summary:

```yaml
- uses: Seclume/seclume/.github/actions/crypto-policy@main
  with:
    jar: seclume-verify.jar
    cbom: target/cbom.json
    policy: crypto-policy.properties
    baseline: cbom-of-the-last-release.json
```

CI runs the action on two releases of a fixture: the first meets a strict policy, the second -
the hybrid lost, an RSA-2048 key, a data key from a file - fails it and is a step back
(`crypto-policy-action`; `CryptoPolicyTest`, `CbomDiffTest`, `CbomReaderTest`, `PolicyTest`,
`CryptoPolicyAutoConfigurationTest`).

## `/actuator/quantum`: what a quantum computer would break, and in which order

`QuantumReadiness` reads the inventory, or a CBOM, and sorts by the threat:

- **High** - a TLS key exchange that is not post-quantum: traffic recorded today is opened the
  day it falls ("harvest now, decrypt later"). Instead: X25519MLKEM768, which seclume's own TLS
  stack offers where OpenSSL 3.5 or CNG has ML-KEM ([TLS.md](TLS.md)) - the report says whether
  the session ran on JSSE (`tlsStack=seclume`), on TLS 1.2 (the hybrid needs 1.3) or on a
  server that did not take it.
- **Medium** - signatures: server certificates and our own signing keys (RSA, ECDSA, Ed25519).
  Forged only while a quantum computer exists, but certificates and the keys behind tokens live
  for years. Instead: ML-DSA-65 (FIPS 204), ML-DSA-87 where CNSA 2.0 applies.
- **Low** - AES-128: Grover's search leaves about 64 bits, a margin, not a break. Instead:
  AES-256 (the field encryption already is).

With the share of assets that are ready. `management.endpoints.web.exposure.include=quantum`
serves it as JSON; `seclume-verify --quantum` as Markdown or `--json`.

## Diagnostics for specific defects

- **`Flight`**: the last messages a connection sent and received, in order, attached to the
  exception when it breaks. It is for the one defect class that is worse than a crash: a
  connection one message behind, which nothing that looks at a single statement can see. It
  records types and byte counts only, and not even the count for the message that carries the
  credential. Off unless `-Dseclume.flight` asks for it.
- **`QueryStorms`** finds the N+1: the same statement shape, repeated, on one thread, in one
  moment. It is reported once, with a stack trace, as a JFR event or a callback. Slow-query
  logging cannot see this, because two hundred statements of a millisecond each all look
  healthy on their own. It carries the fingerprint and nothing else, which is what lets it
  stay on.
- **Server capacity**: at its first connection, the pool asks how many connections the server
  allows and how many are open (`space.seclume.ServerCapacity`). It warns when the pool alone
  could fill what is left, or when there is room for only one instance of it. That is the
  arithmetic behind "too many clients already", done before a scale-out instead of during one.
- **A connection cut by something in between**: a connection that ends after more than 30 s
  without traffic says so, naming an idle timeout in a firewall, a NAT, a load balancer or the
  server. Otherwise it would end as a bare "communications link failure".

## `seclume-verify`

Connects once and prints a report on the server, the encryption, the secret's source, the
capabilities, the server's connection capacity and the round trips. It is something to paste
into a ticket. With `--json` it prints one JSON object and nothing else, for a build step or a
readiness probe. The exit code is the contract either way: 0 means the connection stands, 1
means it does not, and 2 means the tool was called wrongly. `--print-pin` prints the server's
key pin (see [TLS.md](TLS.md)).

`--migrate application.properties` (or a JDBC URL) translates an existing configuration
into seclume's. It reads pgjdbc, Connector/J, MariaDB, mssql-jdbc, Oracle thin, HikariCP
and Spring settings, and names every unsafe setting in it: `sslmode=require`,
`trustServerCertificate=true`, `allowPublicKeyRetrieval` without TLS, and passwords in the
file. Password values are never read.
