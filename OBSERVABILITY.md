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
