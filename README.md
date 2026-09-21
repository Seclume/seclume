# seclume

**JDBC drivers for PostgreSQL, MySQL/MariaDB, Microsoft SQL Server and Oracle that keep
secrets off the Java heap.** Four wire protocols written from scratch — no vendor driver is
used, wrapped or delegated to.

A database password never becomes a `String` or a `char[]`. It goes from its source into
native memory, is used there, and is wiped. A heap dump — `jmap`, `-XX:+HeapDumpOnOutOfMemoryError`,
the Actuator's `/heapdump`, a support upload — has nothing in it to find, and the test suite
proves that by taking a real dump and searching it, with a negative control that must fail.

Java 25, Spring Boot 4.x / Spring Framework 7.x. No runtime dependency beyond the JDK.

---

## Quick start

```xml
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-postgresql</artifactId>
  <version>0.1.0</version>
</dependency>
```

```properties
seclume.datasources.main.url=jdbc:seclume:postgresql://db:5432/app?tls=verify-full
seclume.datasources.main.username=app
seclume.datasources.main.secret.provider=file
seclume.datasources.main.secret.path=/run/secrets/db-password
seclume.datasources.main.pool.maximum-pool-size=16
```

That is the whole integration. Spring gets a `DataSource`; Spring Data, Hibernate and Flyway
work on it as they would on any other.

Without Spring:

```java
String url = "jdbc:seclume:postgresql://db:5432/app"
           + "?user=app&provider=file&path=/run/secrets/db-password";
try (Connection c = DriverManager.getConnection(url);
     PreparedStatement s = c.prepareStatement("select name from customer where id = ?")) {
    s.setLong(1, 42);
    try (ResultSet rows = s.executeQuery()) {
        while (rows.next()) {
            System.out.println(rows.getString(1));
        }
    }
}
```

The URL prefix is `jdbc:seclume:`. One artifact per database — `seclume-postgresql`,
`seclume-mysql`, `seclume-sqlserver`, `seclume-oracle` — plus `seclume-pool` and
`seclume-spring-boot-starter`, which pulls what it needs. The groupId and the package root are
the same, `space.seclume`.

### Where the secret comes from

Never from the URL and never from a `String`. Pick a provider:

| Provider | Where it reads from |
|---|---|
| `file` | a mounted file, e.g. a Kubernetes or Docker secret |
| `env-file` | the file a `_FILE` environment variable points at |
| `process` | the standard output of a command |
| `unix-socket` | a local agent |
| `dpapi` | Windows DPAPI, bound to the executing account |
| `credential-manager` | the Windows Credential Manager |
| `rds-iam` | an AWS RDS IAM token, signed locally rather than fetched |
| `encrypted` | an AES-GCM ciphertext, decrypted straight into native memory; the key comes from another provider |
| `vault` | HashiCorp Vault over HTTPS, answer parsed in native memory; dynamic credentials with their lease |
| `aws-secrets-manager` | AWS Secrets Manager, request signed here, answer parsed in native memory |
| `azure-key-vault` | Azure Key Vault, bearer token from another provider |
| `gcp-secret-manager` | Google Secret Manager, Base64 payload decoded segment to segment |
| `callback` | your own code, handed native memory to write into |

**[PROVIDERS.md](PROVIDERS.md) is the full reference** — every setting of every provider, and
the three differences that actually decide which one you want: whether the credential
expires, whether it needs a second provider underneath, and what it costs per connection.

`encrypted` is for the case where the password may not stand in the configuration in the
clear but there is no secret store either. It is worth saying plainly what that buys: whoever
can read the ciphertext can usually read the key file beside it. The gain is against copying,
screenshots, backups and accidental commits - not against somebody who already has the
machine. Both halves are Base64; the ciphertext is `[12-byte nonce][ciphertext][16-byte tag]`,
the key is 16, 24 or 32 bytes, and **a nonce is used once**. The optional `aad` binds a
ciphertext to where it belongs, so the reporting database's secret cannot be pasted over the
production one and quietly work.

### Dynamic credentials, and the half that is usually missing

`vault` reads both engines — a static secret under `secret/data/...` and a **dynamic database
credential** under `database/creds/...`, where Vault creates a database user with a lease.
The HTTP and the JSON are seclume's own (`SecretFetch`, `JsonOff`), so the answer lands in
native memory and only the field asked for is copied out; every JSON library would have made
the password a `String` first.

```properties
seclume.datasources.main.secret.provider=vault
seclume.datasources.main.secret.address=https://vault.internal:8200
seclume.datasources.main.secret.path=database/creds/app
seclume.datasources.main.secret.token-provider=file
seclume.datasources.main.secret.token-path=/var/run/secrets/vault-token
```

Fetching the credential is the easy half and every client does it. The half that decides
whether dynamic credentials are usable is what happens an hour later, when the password a
pooled connection was opened with expires *while the connection is idle*. Normally nothing
happens — until an authentication error appears in a running application at an hour nobody
chose. The usual workaround is to set `maxLifetime` shorter than the TTL by hand, in a second
place, and to remember it when the TTL changes.

Here the credential says when it stops and the pool retires connections before that, one
minute early by default (`seclume.datasources.main.pool.credential-margin`). Each connection
carries the credential it was opened with, so a rotation does not empty the pool: the old
connections run out on their own schedule while new ones start on the new one.

### The three cloud vaults

Same idea, three different shapes, and each shape is where an SDK would have put the password
on the heap. AWS wraps a JSON document inside a JSON string; Azure puts the expiry in a
sibling object; Google Base64-encodes the payload. All three go through the same two pieces —
`SecretFetch` for the HTTPS, `JsonOff` for the answer — so nothing is ever a `String`, and
none of the three SDKs is a dependency.

```properties
# AWS: a field out of the secret's own JSON, request signed with SigV4
...secret.provider=aws-secrets-manager
...secret.region=eu-central-1
...secret.secret-id=prod/db
...secret.field=password
...secret.access-key-id=AKIA...
...secret.key-provider=file
...secret.key-path=/run/secrets/aws-secret-key

# Azure: a bearer token, itself from a provider
...secret.provider=azure-key-vault
...secret.vault-uri=https://my-vault.vault.azure.net
...secret.name=db-password
...secret.token-provider=file
...secret.token-path=/var/run/secrets/azure/token

# Google
...secret.provider=gcp-secret-manager
...secret.project=my-project
...secret.name=db-password
...secret.token-provider=file
...secret.token-path=/var/run/secrets/gcp/token
```

Azure reports `attributes.exp` when a secret has one, so a rotating secret feeds the same
pool machinery the Vault lease does.

**AWS temporary credentials** — IRSA, an instance role, `AssumeRole` — work through
`session-token-provider`, and getting there is worth a sentence because for a while this was
documented as a gap. A session token is not merely sent as `X-Amz-Security-Token`, it is
*signed*: it appears inside the canonical request, which was an ordinary concatenated
`String`. Supporting it that way would have put a credential on the heap in the one library
whose job is to keep it off, so the limitation was written down rather than quietly ignored.
The fix turned out to be small — assemble the canonical request in native memory, hash it
there, and everything above that line goes back to being text.

### One line instead of four

With the starter, `secret-uri` expands to the `secret.*` keys above - the same spelling the
JDBC URL has always taken, so a deployment needs one environment variable per data source
rather than four that have to agree:

```properties
seclume.datasources.main.secret-uri=file:/run/secrets/db
seclume.datasources.main.secret-uri=env-file:/run/secrets/app.env?key=DB_PASSWORD
seclume.datasources.main.secret-uri=credential-manager?target=AppDb
seclume.datasources.main.secret-uri=encrypted:/run/secrets/db.enc?key-provider=dpapi&key-path=/run/secrets/kek&aad=main
```

Giving both `secret-uri` and `secret.*` for the same data source is refused rather than
resolved by precedence.

### The guard

The starter also reads the whole `Environment` at startup and names the properties that hold a
password in plain text - `spring.mail.password` and whatever an application invented for
itself. It reports; it does not forbid, because for a good part of what it finds there is no
off-heap alternative yet, and a guard that blocks what cannot be fixed gets switched off.
**Names are logged, never values.**

```properties
seclume.secret-guard=warn                     # warn (default), fail, off
seclume.secret-guard-allow=spring.mail.password
```

The allow-list is the point: it turns "we have three plaintext passwords and nobody knows"
into three that are written down and decided on. It is meant to get shorter.

Where it can be followed, the recommendation that makes all of this unnecessary is
**operating-system integrated authentication** — Kerberos/SSPI, PostgreSQL `gss`, SQL Server
Integrated Security, Oracle NTS. Then there is no secret in the process at all. Password
authentication is the fallback for everything not in a domain.

---

## What it does

**The JDBC surface, on all four**

- `Statement`, `PreparedStatement`, `CallableStatement`; bind variables of every JDBC type,
  OUT parameters and parameters by name, generated keys, batches, `ParameterMetaData`,
  scrollable results, fetch size and block cursors, LOB streams, `setNull`, escape functions,
  query timeouts and row limits.
- **Procedures that return rows**, in the form each server has one: a `SYS_REFCURSOR` output
  on Oracle, read with `registerOutParameter(i, Types.REF_CURSOR)`; and on SQL Server the
  results a procedure selects, walked with `getResultSet` and `getMoreResults` — several of
  them, and without the driver's own bookkeeping showing up among them.
- Every Java type an application maps, old and new: `BigDecimal`, `UUID`, `LocalDate`,
  `LocalDateTime`, `OffsetDateTime`, `Instant`, `LocalTime`, `Duration`, `Year`, byte arrays,
  `Clob`/`Blob`, enums, booleans — each written and read back unchanged, on every server.
- `DatabaseMetaData` far enough for Hibernate's schema validation, Flyway and
  `SimpleJdbcCall` to work from the catalogue alone.
- **The types only PostgreSQL has**: `getArray` on any array column, including nested and
  including the difference between a null element and the word `NULL`; `getSQLXML` on `xml`;
  `getRowId` on `ctid`; and large objects, where `getBlob` on an `oid` column is a real
  locator that reads in chunks rather than the row's own bytes. `java.sql.Ref` stays refused,
  because none of the four servers has a type it could point at.
- **Distributed transactions (XA)** in all four, off by default.
- **Failover on connect** across a host list.
- **CockroachDB and YugabyteDB** on the PostgreSQL driver, each with a password: CockroachDB
  over TLS with SCRAM-SHA-256, YugabyteDB with md5. The tests assert which method the server
  asked for, so neither can quietly stop asking.

**Spring Data and JPA**

Entities may be shaped any way JPA allows, and are: inheritance in all three strategies,
`@EmbeddedId` and `@IdClass`, `@OneToMany`/`@ManyToMany`/`@ElementCollection` with `@OrderBy`,
`@MapsId`, `@SecondaryTable`, `@NaturalId`, every `@GeneratedValue` strategy, `@Version`,
auditing, converters, `@Lob`, projections, specifications, `@EntityGraph`, `@Lock`, paging and
streaming. Proven by a running Spring Boot application against all four servers, with
`ddl-auto=validate` — so the schema is compared against the driver's own metadata before a
single test runs.

**TLS, and the difference said out loud**

```properties
jdbc:seclume:postgresql://db:5432/app?tls=verify-full
```

| `tls` | What it does |
|---|---|
| `off` | no encryption |
| `prefer` | encrypt if offered — stops a listener, not a man in the middle |
| `require` | encrypt or refuse; still no certificate check |
| `verify-full` | encrypt **and** check the certificate against the trust store and the host dialled |

Only `verify-full` authenticates the server. A driver that offers the first three and calls
the result secure is lying by omission. On PostgreSQL the login is additionally bound to the
connection (SCRAM-SHA-256-PLUS), and when the server offers no binding the client says so
rather than staying silent.

**Which TLS carries it — a separate question**

```properties
jdbc:seclume:postgresql://db:5432/app?tls=require&tlsStack=seclume
```

| `tlsStack` | What provides the encryption |
|---|---|
| `jsse` | the JDK's `SSLEngine` — the default, and what every JDBC driver does |
| `seclume` | this project's own TLS 1.3 client |

Every mode above works on either, so this is not a security setting but a capability one. The
own stack gives up resumption, TLS 1.2 and every key exchange group but P-256, and gains two
things JSSE cannot offer at any price: **the traffic secrets never become Java objects**, and
the encryption state can be frozen and taken up elsewhere — which is what a connection that
survives moving host needs. The safe, boring one stays the default.

**All four drivers are proven on it against real servers** — PostgreSQL and MySQL with
channel binding, Oracle over a TCPS listener, SQL Server with `tds=8.0` below.

**SQL Server needs `tds=8.0` as well**, and that is not a detail. Its ordinary handshake runs
*inside* TDS packets and is TLS 1.2 by construction — TLS 1.3 moves handshake messages past
the point where that nesting would have to invert. TDS 8.0 (Microsoft calls it strict
encryption) puts TLS around the whole connection from the first byte instead:

```properties
jdbc:seclume:sqlserver://db:1433/app?tds=8.0&tlsStack=seclume
```

Proven against SQL Server 2025. **SQL Server 2022 on Linux does not accept strict encryption
at all** — Microsoft's own driver fails against it the same way — so `tds=7.4` stays the
default and nothing changes for anybody who does not ask.

**Mutual TLS, with the client key off the heap too**

A password held carefully while the private key that authenticates the *same* connection sits
in an unwipeable `PrivateKey` protects nothing — whoever has that key does not need the
password. So seclume signs the client `CertificateVerify` with a P-256 key that never becomes
a Java object: the key file goes through a secret provider into native memory,
`EcPrivateKeyFile` picks the scalar out of the PKCS#8 or SEC1 structure in place, and CNG or
OpenSSL keeps it from there. Only the certificate chain and the signature — both public —
are ordinary objects.

Two settings say it, in a URL or in `application.properties`:

```properties
jdbc:seclume:postgresql://db:5432/app?tls=verify-full&tlsStack=seclume  &clientCert=/etc/tls/client.crt&clientKey-provider=file&clientKey-path=/etc/tls/client.key
```

The certificate is a path because it is public. The key is a **provider** — the same
`clientKey-`-prefixed block accepts `vault`, `dpapi`, `encrypted` or anything else that works
for a password, so the key can arrive the way the rest of your secrets do. Or hand one in
directly, when the application builds it itself:

```java
try (ClientIdentity me = new P256ClientIdentity(Path.of("/etc/tls/client.crt"),
                                                SecretProviders.of(Map.of(
                                                    "provider", "file",
                                                    "path", "/etc/tls/client.key")))) {
    dataSource.setClientIdentity(me);
}
```

The identity is built **once per configuration** and shared. A pool of fifty connections
loads one key, because loading it is what puts it in native memory and there it stays until
the identity is closed.

Two things are refused rather than worked around. **P-256 only:** an RSA client certificate
would mean the JCA, and the JCA means the key on the heap. And **`tlsStack=seclume` is
required**, because presenting a certificate through the JDK's TLS needs a `KeyManager`,
which hands out a `PrivateKey` — so that combination fails with a message saying so, instead
of connecting quietly without the certificate the configuration asked for.

**Where this does not reach:** nowhere, now — all four drivers can present a client
certificate with the key off the heap. SQL Server needs `tds=8.0` with it, and Oracle a TCPS
listener, for the reasons above.

**Seeing what happened, without seeing the values**

Flight Recorder events, and no runtime dependency for them: JFR is in the JDK, it is off until
somebody starts a recording, and off it costs an `isEnabled()` the JIT folds away.

```
java -XX:StartFlightRecording=filename=app.jfr,settings=profile ...
```

| Event | What it answers |
|---|---|
| `space.seclume.ConnectionOpen` | how long a physical connect, TLS and login really take |
| `space.seclume.TlsHandshake` | whether the slow part is the handshake and which stack ran it |
| `space.seclume.Query` | which statements are slow — over 10 ms by default, lower it in the recording settings |
| `space.seclume.PoolWait` | the one an operator wants when the app is slow and the database is idle |
| `space.seclume.Failover` | which server stopped answering, and when |
| `space.seclume.CredentialRotation` | that a secret was fetched, how long it took, and when it expires |
| `space.seclume.StatementCache` | whether server-side plans are actually being reused |

**A statement is named by its shape, never by its text:**

```
select * from customer where id = 42 and name = 'alice'
select * from customer where id = ? and name = ?
```

That is `QueryFingerprint`, and it is the reason these events are safe to keep. A recording
is written to a file, kept for weeks and handed to whoever is debugging — a longer life and a
wider audience than a heap dump, which this library goes to some lengths about. So a value in
a JFR event would be worse than one on the heap, not better. Literals of every quoting form
each dialect has, numbers, and every placeholder spelling are replaced; `in (?, ?, ?)`
collapses to `in (?)` so one query stays one entry. Where a dialect makes it ambiguous whether
something is an identifier or a string — `"x"` in MySQL — the fingerprint gives up the
identifier rather than risk the value.

Not recorded anywhere: bind values, SQL text, secrets, or anything derived from a secret — not
its length and not a hash. Nor the database user, which is not a secret and is not needed to
diagnose anything here.

**Beside the drivers**

- `seclume-pool` — a connection pool with no third-party dependency, fit for virtual threads,
  with Micrometer metrics, a health indicator, a statement cache, leak detection, and a
  timeout message that names the oldest holders.
- `seclume-verify` — connects once and prints a report on the server, the encryption, the
  secret's source, the capabilities and the round trips. Something to paste into a ticket.
- `seclume-heapcheck` — proves for **any** running Java process whether a given secret is in
  its heap, including applications that do not use this library.

---

## What it does not do yet

- Moving a live session from one host to another. The drivers hold their own protocol and TLS
  state, which is what such a move needs; the transport it needs is developed separately and
  is not part of this distribution.

---

## Speed

The aim is not "fast enough" but faster than the established Java drivers.

| Measurement | seclume | vendor driver |
|---|---|---|
| batch of 500 rows, MySQL over LAN (604 µs RTT) | **18.7 ms** | 278.6 ms (Connector/J) |
| check out, query, return (8 threads, local) | **62.4 µs** | 70.9 µs (HikariCP + pgjdbc) |
| the same with `PreparedStatement` and a statement cache | **58.9 µs** | — (111.4 µs without a cache) |
| a `@Transactional` method with one query | **2 round trips** | 7 |
| batch of 200 rows, SQL Server | **1 round trip** | 200 |

---

## Building and testing

```
./mvnw clean test
```

Everything that needs no database runs; everything that needs one skips itself and says why.
How to bring the four databases up, and how to point the tests at servers elsewhere, is in
[TESTING.md](TESTING.md). CI runs the same suite against PostgreSQL 15 and 18, MySQL 8.4,
MariaDB 11.4, SQL Server 2022, Oracle Free 23ai, CockroachDB 24.1 and YugabyteDB 2024.1 on
every push.

## Where the protocol knowledge came from

Three of the four protocols have published specifications and were implemented from them. The
fourth, Oracle, has none — and the largest single source there is Oracle's own driver, under a
licence that permits reimplementation. No vendor source, no headers, nothing decompiled:
[PROVENANCE.md](PROVENANCE.md).

## Rules of honesty

- No placeholder that pretends to work. What is not implemented throws.
- No provisional delegation to a vendor driver, not even commented out.
- A protocol detail that cannot be established with certainty counts as unsupported rather
  than being guessed.
- Test results are reported with their output. "Should work" does not count.

## Support, and what you may rely on

seclume is written and maintained by one person, in the time that person has. It is used in
earnest, it is kept working, and issues do get read — but there is **no company behind it, no
support contract, and no promise that anything is answered within any particular time, or at
all**. Nor is there a promise of a next release. Please plan as though the version you are
using now is the last one you will get; if a later one arrives, treat it as a gift rather than
as the plan.

That matters more than usual here, because this is a **driver** — the piece everything else
sits on. So it is built to be survivable without its author:

- The **licence is Apache-2.0**, so you may keep using, patching and shipping what is here
  whatever happens to this project.
- **Nothing is hidden.** Every byte on the wire is written in this repository; there is no
  vendor driver underneath to fall back to and no service to call home to.
- The **tests are the specification**, and they run against real PostgreSQL, MySQL, MariaDB,
  SQL Server and Oracle servers. They are the thing to read first if you ever have to take
  this over — and the reason you could.
- **Security reports** are taken seriously and handled as fast as one person can, which is not
  the same as an SLA.

If seclume matters to something you are paid to keep running, budget for owning it rather than
for being supported. That is the honest arrangement, and saying so up front seems better than
letting anyone find out at the wrong moment.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Use it commercially, modify
it, ship it inside a closed product. The licence grants the patent rights along with the
copyright ones, which for a project full of protocol implementations is the part that matters.

The transport that moves a live session between hosts is **not** part of this repository, is
not covered by that licence, and no rights to it are granted here.
