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
| `space.seclume.Authentication` | the login on its own, and by what method the server asked for it |
| `space.seclume.Query` | which statements are slow — over 10 ms by default, lower it in the recording settings |
| `space.seclume.PoolWait` | the one an operator wants when the app is slow and the database is idle |
| `space.seclume.Failover` | which server was passed over, why, and **how long it took to not answer** |
| `space.seclume.CredentialRotation` | that a secret was fetched, how long it took, and when it expires |
| `space.seclume.StatementCache` | whether server-side plans are actually being reused |

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

## The same events as metrics

JFR makes the better recording, but almost nobody reads it: reading it takes somebody noticing
a problem, dumping a file and opening a tool. So the Spring Boot starter can turn those events
into Micrometer meters as they happen: `seclume.query.slow`, `seclume.statement.cache`,
`seclume.connection.open` and `seclume.failover`. The drivers need no second instrumentation,
and a meter carries nothing the events do not already carry.

```properties
seclume.metrics.queries=true
seclume.metrics.query-threshold=10ms      # what counts as slow
seclume.metrics.query-fingerprints=100    # how many shapes get a tag of their own
```

Off by default, because it starts a Flight Recorder stream, which changes the state of the
process it runs in. The last line matters too. A tag per statement shape is what makes these
meters worth having, and it is also the classic way to bring a metrics backend down. Beyond
the bound, shapes are counted together under `other`: the totals stay right, and only the
attribution stops.

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
