# Changelog

All notable changes to seclume are recorded here. Versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Work towards 1.0.0. The three items under *Not yet* in 0.9.0 are what stands
between here and that number: fuzzing the four wire parsers, generating the
compatibility matrix from the run, and making the benchmark figures
reproducible.

## [0.9.0] - 2026-09-22

The first published artifact, and the version number is the point: **0.9.0 is
not 1.0.0, deliberately.** Everything below works and is tested against real
servers, but three things a 1.0 should be able to claim are not true yet, and
they are listed under [Not yet](#not-yet-and-why-this-is-090) rather than
glossed over.

### What this is

Four JDBC drivers and a connection pool for PostgreSQL, MySQL, SQL Server and
Oracle, written from the wire protocol up, with one defining property:

> **A secret never becomes a `String` or a `char[]` on the Java heap.**

Credentials are read from a provider straight into off-heap memory, used where
the protocol needs them, and wiped. A heap dump of an application using these
drivers does not contain the database password, because the password was never
an object that a dump could find. `seclume-heapcheck` exists to prove that on a
running process rather than to assert it in a comment.

No runtime dependency beyond the JDK. Java 25.

### Modules

| | |
|---|---|
| `seclume-core` | secret providers, off-heap buffers, the TLS 1.3 client, the JDBC scaffolding |
| `seclume-postgresql`, `seclume-mysql`, `seclume-sqlserver`, `seclume-oracle` | the four drivers |
| `seclume-pool` | a connection pool that understands credential lifetimes |
| `seclume-spring-boot-starter` | auto-configuration, JFR-to-Micrometer metrics, tracing |
| `seclume-verify` | a preflight command: does this configuration actually connect, and how |
| `seclume-heapcheck` | reads a live heap and reports whether a secret is in it |
| `seclume-bom`, `seclume-tck`, `seclume-bench`, `seclume-diff`, `seclume-spring-test` | dependency management, the shared test kit, benchmarks, the differential harness against the vendor drivers |

### Secrets

- Providers for a file, an environment variable, a Unix domain socket, an
  encrypted file, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault and
  Google Secret Manager - **none of them through a vendor SDK**, so none of
  them drags a dependency or a `String` in with it.
- Vault leases and AWS temporary credentials are understood: a connection is
  retired before its credential expires rather than after it fails.
- `secret-uri` in a JDBC URL, and a guard that refuses a plaintext password in
  one.
- The wipe is proven on the failure paths, not only the happy one - a login
  that is rejected, a connection that dies mid-handshake, a server that is not
  there at all.

### TLS

- Two stacks, chosen per connection with `tlsStack`: the JDK's `SSLEngine`, or
  **seclume's own TLS 1.3 client**, where every traffic secret lives in native
  memory.
- mTLS with a client key that never becomes a Java object.
- Channel binding (SCRAM-SHA-256-PLUS) on both stacks.
- TDS 8.0 for SQL Server, which is the only route by which that driver reaches
  the own stack - and therefore the only route to a client certificate there.
- Oracle over TCPS.
- The own stack is checked against the RFC 8448 vectors, against JSSE, and
  against all four real servers.

### The drivers

- Every driver has `CallableStatement`, named parameters, XA, `DatabaseMetaData`,
  procedures that return rows, and a pipeline block that puts a unit of work in
  one round trip.
- Result rows are read **in place** out of the receive buffer - a thousand rows
  cost a handful of system calls and no copies.
- Statement caching per connection, with an eviction that gives the server its
  cursors back rather than leaking them.
- `targetServerType=primary|secondary` over a host list, with a per-engine probe
  for what a server says it is.
- A `QueryFingerprint` that names a statement's shape and carries none of its
  values.

### Observability

- JFR events for statements, the cache, failover and TLS, with no runtime
  dependency.
- The Spring Boot starter bridges those to Micrometer and to tracing spans.
- `StatementListener`, the one hook in the statement path, for a span that needs
  the caller's thread context.

### Testing

1695 tests. CI runs against PostgreSQL 15 and 18, MySQL 8.4, MariaDB 11.4,
SQL Server 2022 and 2025, Oracle Free 23ai, CockroachDB and YugabyteDB.

The vendor drivers are used as the oracle in a differential harness: the same
statement, the same server, both drivers, and any disagreement is a defect
here. It found eight.

### Also in this release

- **A session can be handed from one holder to another.** `detach()` gives up
  an authenticated stream and `resume()` picks one up, so a login can happen
  once, where the credential is, and whoever receives the stream never needs
  one. On seclume's own TLS stack the encryption goes along with it; on the
  JDK's it cannot, and the refusal says why. What anybody builds on that is
  their business - this library provides the join.
- **`OracleSession.releaseCursors()`.** `detach()` refuses while cursors are
  open and told callers to close them, and nothing here offered a way. Now it
  does, at the cost of one round trip.
- **Fixed:** `close()` on all four channels ignored a channel that had been
  given up, and so closed the socket it had just handed over.

### Not yet, and why this is 0.9.0

| | |
|---|---|
| **The wire parsers are not fuzzed.** | Four protocols are parsed here by hand, and every one of those parsers reads a length and then trusts it. The property tests are good at valid values and at edges; they are not an adversary. A 1.0 for a library whose argument is byte-level correctness should be able to say it has been attacked. |
| **The compatibility matrix is prose, not generated.** | The list of servers above is written by hand next to the run instead of produced by it, so it can drift from it. |
| **The benchmark numbers are not reproducible by a reader.** | The figures in the README are real and were measured, but without the hardware, the server configuration, the warm-up, the repetitions and the raw data beside them they ask to be taken on trust. |

The API may still change before 1.0.0. It changed on the day of this release.

### A note on this registry

GitHub Packages requires a token even to **read** a public package. That is a
property of the registry, not of this project. A dependency that should simply
resolve belongs on Maven Central, and that is where 1.0.0 will go.

[0.9.0]: https://github.com/Seclume/seclume/releases/tag/v0.9.0
