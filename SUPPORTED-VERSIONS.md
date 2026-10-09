# Supported database versions

Which server versions seclume works with, and how that was established: each version below
was started as a container, the driver's whole test suite was run against it, and
`space.seclume.verify.Compatibility` connected to it - then the container and its image were
removed. Nothing in the tables is taken from a vendor's documentation.

Run on 2026-10-07 with the code that becomes 0.11.1; Oracle 11g, 18c and 21c again on
2026-10-09, after the fixes described below. The newest versions (PostgreSQL 15-18,
SQL Server 2022, Oracle Free 23ai, MySQL 8.4, MariaDB 11.4, CockroachDB 24.1, YugabyteDB
2024.1) are tested on every push by CI and are not repeated here; see
[COMPATIBILITY.md](COMPATIBILITY.md) for what they report.

## The matrix

| Database | Version | Status | Login | TLS on the own stack |
|---|---|---|---|---|
| PostgreSQL | 18, 17, 16, 15 | **supported** (CI) | SCRAM-SHA-256-PLUS | TLS 1.3 |
| PostgreSQL | 14, 13, 12 | **supported** | SCRAM-SHA-256(-PLUS), md5 | TLS 1.3 |
| PostgreSQL | 11, 10 | **supported** | SCRAM-SHA-256(-PLUS from 11), md5 | TLS 1.2 or 1.3, as the server's OpenSSL allows |
| PostgreSQL | 9.6 | **supported** | md5 | TLS 1.2 or 1.3, as the server's OpenSSL allows |
| SQL Server | 2025, 2022 | **supported** (CI) | SQL login inside TLS, Kerberos, Entra token | TDS 8.0 (TLS 1.3) or TDS 7.4 (TLS 1.2) |
| SQL Server | 2019, 2017 | **supported** | SQL login inside TLS | TDS 7.4 (TLS 1.2) |
| SQL Server | 2016 | **not tested** | - | - |
| SQL Server | 2014 and older | expected to work from 2012 (TDS 7.4), **not tested** | | |
| SQL Server | 2008 R2 and older | **not supported** - TDS 7.3 | | |
| Oracle | 23ai (Free) | **supported** (CI) | O5LOGON, 12c verifier | TCPS TLS 1.3 / 1.2, or Native Network Encryption |
| Oracle | 21c, 18c (XE) | **supported** | O5LOGON, 12c verifier | TCPS TLS 1.2 |
| Oracle | 19c, 12c | **not tested** - no public container image | | |
| Oracle | 11g (XE 11.2) | **supported, opt-in** - `legacyVerifier=11g` | O5LOGON, 11g verifier | none - 11g XE's listener does not bring up TCPS |

"Supported" means: the driver's suite passes against the version, apart from tests that use a
server feature the version does not have (listed per version below).

## PostgreSQL 9.6 to 14

`postgres:<version>` images, TLS with the test certificates, SCRAM from 10 on (9.6 knows md5
only), `max_prepared_transactions=20` for XA. The PostgreSQL driver's suite, 249 tests:

| Version | Passed | Not passed, and why |
|---|---|---|
| 14 | all | - (run before the fixes below and the test they added: 248 tests) |
| 13 | all but 1 | a test creates a procedure with an `OUT` parameter - PostgreSQL 14 and later |
| 12 | all but 1 | the same |
| 11 | all but 4 | `OUT` in procedures; three tests that expect TLS 1.3, which this image's OpenSSL does not offer - the own stack negotiated TLS 1.2 |
| 10 | all but 11 | as 11, plus: procedures (11 and later) in six tests, SCRAM channel binding (11 and later) in two |
| 9.6 | all but 15 | as 10, plus: SCRAM (10 and later) in two tests - one of them the heap-dump proof, which logs in by SCRAM - and identity columns (10 and later) in two |

The heap-dump proof logs in by SCRAM, so on 9.6, which has only md5, the md5 login has no
heap-dump proof of its own in this run.

**Found and fixed by this run:**

- **Floats lost digits in the text format before PostgreSQL 12.** The server's default was 15
  significant digits, so `1.0/3` read as `0.333333333333333` in text and as
  `0.3333333333333333` in binary. The driver now sends `extra_float_digits=3` at login, as
  pgjdbc does.
- **`getColumns` failed on 9.6**: it named `pg_attribute.attidentity`, a column of
  PostgreSQL 10. It is read by name at run time now.
- **`getProcedures`, `getProcedureColumns` and `getFunctions` failed on 9.6 and 10**: they
  named `pg_proc.prokind`, a column of PostgreSQL 11. Before it, every routine is a function
  or an aggregate, and that is what is read now.

`Compatibility` against each: every line answers; md5 on 9.6-13 with the images' defaults,
SCRAM-SHA-256-PLUS on 14.

## SQL Server 2017 and 2019

`mcr.microsoft.com/mssql/server:2017-latest` (14.0.3550) and `2019-latest` (15.0.4490). The SQL
Server driver's suite, 182 tests: all passed on both, XA included (with the database
`seclume_test` created, as [TESTING.md](TESTING.md) describes). Both negotiate TLS 1.2 on TDS 7.4
with ECDHE and AES-128-GCM on the own stack.

**SQL Server 2016** has no Linux container - Linux support began with 2017 - so it is not
tested here. It speaks TDS 7.4 like 2017; with the TLS 1.2 updates Microsoft shipped for it,
nothing is expected to differ, but until it has been run that is an expectation, not a result.

## Oracle

`gvenzl/oracle-xe` images: 11g (11.2.0.2), 18c and 21c. Oracle 12c and 19c exist only in
Oracle's own container registry, behind a sign-in and a licence acceptance, and were not run.

What older servers needed, all of it found by running the suite against them:

- **The login.** Their listeners ask for the CONNECT again (`RESEND`) on a plaintext port too,
  which the driver had taken for TCPS. `FAST_AUTH` (protocol, data types and the first login
  step in one message) is sent only when the server's ACCEPT announces it - 23ai does, 21c,
  18c and 11g do not, and get the three steps one by one.
- **The TTC field version.** The server's compile capabilities say which fields its messages
  have; the driver now speaks the lower of the two versions instead of always 23.4. That
  decides the token number in every call (23.1 on), the columns' domain, annotation and vector
  fields (23.1 and 23.4), the SQL type and checksum in an error (20.1), the trailing fields of
  an execute (12.1, 12.2), `oaccolid` (12.2), and the wide error number and row count in an
  error (12.1). It is carried across a detach and resume.
- **The end of an answer.** Before protocol 319 no packet is flagged as the last one; the
  driver walks what has arrived until it reaches the call's closing status.
- **11g in particular**: chunk lengths are one byte rather than a number (the "big chunks"
  capability came with 12.1), and a persistent LOB locator is 148 bytes rather than 112.

- **11g**: an account there has only the 11g password verifier, a single SHA-1 round. seclume
  refuses it by default and names the option that allows it: `legacyVerifier=11g` in the URL
  (or `setLegacyVerifier("11g")` on the data source). With it the whole suite passes except the
  tests for features 11g does not have - identity columns, `dbms_session.sleep`, JSON - and
  TCPS, which the 11g XE listener does not bring up for any client (`TNS-00540`, with JSSE and
  OpenSSL alike). The password is handled as on 23ai: it never reaches the Java heap, which the
  heap-dump test checks on 11g too.
- **18c and 21c**: the whole suite passes, TCPS included (a listener added with the fixture's
  wallet), except on 18c the JSON tests (no JSON type before 21c). Their TCPS is TLS 1.2 without
  the extended master secret, which the own stack accepts - see TLS.md. Their plaintext
  listener asks for the CONNECT again with a RESEND, and the RESEND's header says whether a TLS
  session of the server process's own follows; a TLS proxy in front of such a listener works.
- **23ai**: the whole suite (292 tests) still passes with these changes, over TCP and TCPS, and
  still logs in with `FAST_AUTH`.

## Repeating it

Each version was brought up the way [TESTING.md](TESTING.md) brings up the fixtures, on another
port, and the suite pointed at it with system properties - for example
`-Dseclume.pg.host=... -Dseclume.pg.port=5440`, `-Dseclume.mssql.port=1440`,
`-Dseclume.oracle.port=1530 -Dseclume.oracle.service=XEPDB1`. Afterwards the container and
its image were removed.
