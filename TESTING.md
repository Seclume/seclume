# Running the tests

`./mvnw test` works on a bare clone. Everything that needs no database runs; everything that
needs one **skips itself** and says why. A green run on an empty machine therefore proves less
than it looks like it does, and this page is about closing that gap.

## What runs without anything installed

The cryptography against the published vectors, the wire protocols against known answers, the
pool mechanics, the heap-dump proof with its negative control, and the rule that no forbidden
API call slips into production code. That is most of the suite.

## What needs a server

Every test class whose name begins with `Local`, plus the Spring Data suite. They look for two
things and skip unless both are there:

- **a password file** beside the project, one per database;
- **a server** answering on the address they were told about.

Nothing is read out of those files by the tests. The path goes into the driver's configuration
and the driver fetches the secret straight into native memory — the same path an application
uses, which is the point of the library.

## The four databases

Any container runtime will do; `docker` and `podman` take the same arguments here. Choose your
own passwords and write each one into the file named beside it.

```bash
# PostgreSQL
podman run -d --name seclume-pg -p 5432:5432 \
  -e POSTGRES_USER=seclume_test -e POSTGRES_DB=seclume_test \
  -e POSTGRES_PASSWORD="$PW" -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  postgres:18
printf '%s' "$PW" > .local-pg-password

# MySQL — MariaDB works too, and exercises the other authentication plugin
podman run -d --name seclume-mysql -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD="$ROOT" -e MYSQL_DATABASE=seclume_test \
  -e MYSQL_USER=seclume_test -e MYSQL_PASSWORD="$PW" \
  mysql:8.4
printf '%s' "$PW" > .local-mysql-password

# SQL Server
podman run -d --name seclume-mssql -p 1433:1433 \
  -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD="$PW" \
  mcr.microsoft.com/mssql/server:2022-latest
printf '%s' "$PW" > .local-mssql-password
# The XA tests enlist per database, so master will not do:
#   create database seclume_test

# Oracle
podman run -d --name seclume-ora -p 1521:1521 \
  -e ORACLE_PASSWORD="$ADMIN" -e APP_USER=seclume_test -e APP_USER_PASSWORD="$PW" \
  gvenzl/oracle-free:23-slim
printf '%s' "$PW" > .local-oracle-password
```

The Spring Data suite additionally wants a schema per dialect; Flyway creates it on the first
run from `seclume-spring-test/src/main/resources/db/migration`.

## When they are not on this machine

The tests ask `space.seclume.tck.TestHosts` where to look, and it answers from the first of
these that says anything:

| | |
|---|---|
| `-Dseclume.test.host=…` | this run |
| `SECLUME_TEST_HOST` | this shell |
| `.local-test.properties` | this machine |
| otherwise | `localhost` |

PostgreSQL has three of its own, because it is the one that usually runs somewhere other than
the rest: `seclume.pg.host`, `seclume.pg.port` and `seclume.pg.passwordFile` — the last names
*which* file to read, so a second instance can be tested without disturbing the first.

Nothing matching `.local-*` is checked in:

```properties
seclume.test.host=db.example.invalid
seclume.pg.host=db.example.invalid
seclume.pg.port=5433
seclume.pg.passwordFile=.local-pgtls-password
```

## CI

`.github/workflows/ci.yml` runs the same tests against real servers on every push —
PostgreSQL 15 and 18, MySQL 8.4 and MariaDB 11.4, SQL Server 2022, Oracle Free 23ai, and
CockroachDB and YugabyteDB for the claim that the PostgreSQL driver serves them too. That last
pair is reachable without a password, so the tests that need one skip there; the job is not
evidence yet and the workflow says so.

If a run of yours has no server, it stays green and proves less. That is deliberate: a suite
that fails on a laptop teaches people to ignore it.
