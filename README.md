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
| `callback` | your own code, handed native memory to write into |

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

**Mutual TLS, with the client key off the heap too**

A password held carefully while the private key that authenticates the *same* connection sits
in an unwipeable `PrivateKey` protects nothing — whoever has that key does not need the
password. So seclume signs the client `CertificateVerify` with a P-256 key that never becomes
a Java object: the key file goes through a secret provider into native memory,
`EcPrivateKeyFile` picks the scalar out of the PKCS#8 or SEC1 structure in place, and CNG or
OpenSSL keeps it from there. Only the certificate chain and the signature — both public —
are ordinary objects.

```java
try (ClientIdentity me = new P256ClientIdentity(Path.of("/etc/tls/client.crt"),
                                                SecretProviders.of(Map.of(
                                                    "provider", "file",
                                                    "path", "/etc/tls/client.key")));
     TlsConnection tls = ClientHandshake.connect(transport, host, trust, me)) {
    ...
}
```

P-256 only, and refused rather than downgraded for anything else: an RSA client certificate
would mean the JCA, and the JCA means the key on the heap.

**What is not wired up yet:** this works on seclume's own TLS stack, which is also what the
live-session move needs — but the four drivers still reach TLS through an `SSLEngine`, so a
JDBC URL cannot ask for a client certificate this way yet. Doing so through JSSE would need a
`KeyManager`, which puts the key back on the heap and gives up the only thing this is for. The
two meet when the drivers move onto the own stack.

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
