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
| `callback` | your own code, handed native memory to write into |

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

- Procedures returning cursors on Oracle and SQL Server.
- CockroachDB and YugabyteDB are exercised in CI, but without authentication, so that is not
  yet evidence that the driver serves them.
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
MariaDB 11.4, SQL Server 2022 and Oracle Free 23ai on every push.

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
