# Running the tests

`./mvnw test` works on a bare clone. Everything that needs no database runs; everything that
needs one **skips itself** and says why. A green run on an empty machine therefore proves less
than it looks like it does, and this page is about closing that gap.

## What runs without anything installed

The cryptography against the published vectors, the wire protocols against known answers, the
pool mechanics, the heap-dump proof with its negative control, and the rule that no forbidden
API call slips into production code. That is most of the suite.

## The wipe, and the paths where it gets lost

The heap-dump proof covers a login that works. Wipes are not usually lost there - they are
lost on the way out of a failure, where a method leaves early and the cleanup was attached to
the end. Three classes cover that, none of them needing a server:

- `space.seclume.secret.WipeOnFailureTest` - the shapes, one layer down: a source that dies
  mid-write, one that lies about the length, an exception or an `Error` thrown while the
  credential is in hand, an interrupted thread, a timeout, nested scopes, and a forged
  ciphertext that must leave the caller's segment untouched.
- `space.seclume.postgresql.ConnectFailureWipeTest` - the same against a socket: a rejected
  password, a connection dropped mid-login, a server that stops answering while the client is
  interrupted, and a refused TLS handshake, which must not read the secret at all.
- `space.seclume.mysql.LoginFailureWipeTest` - the second handshake, which shares nothing with
  the first but `SecretScope`, plus an unreachable server that must not cost a secret read.

Two different things are measured, and the difference matters. `SecretScope.open()` says
whether the scope was closed - it is counted rather than read back, because after a real close
the memory is released and reading it would mean reading freed pages. That closing leaves
zeroes is shown separately, in an arena the test owns so the segment stays mapped.

## The vendor drivers as the oracle

`seclume-diff` runs the same values through seclume and through pgjdbc or Connector/J, against
the same server, and reports every disagreement. It is the only module that depends on anybody
else's code, it is never published, and it exists because a hand-written test can only check
what its author thought of — and the author of a driver is the worst person to guess what he
got wrong.

Every value is written by one driver and read by both, in both directions, and through a
`Statement` **and** a `PreparedStatement` — text and binary are different wire protocols
decoded by different code, and a driver can be right in one and wrong in the other. Compared:
`getString`, `getObject`, `wasNull`, the whole `ResultSetMetaData`, and
`DatabaseMetaData.getColumns`, which is what Hibernate and Flyway read before they will run at
all.

The first run found eight real defects, none of which any existing test had caught:

| Where | What was wrong |
|---|---|
| PostgreSQL | `getObject` on a `smallint` returned `Short`; JDBC 4.3 table B-3 and every other driver say `Integer` |
| PostgreSQL | `getColumns` computed sizes differently from `ResultSetMetaData` — one driver, two answers about the same column |
| PostgreSQL | `getColumns.TYPE_NAME` returned `character varying(64)`, the declaration, where a type name belongs |
| MySQL | `bigint unsigned` read 18446744073709551615 back as **−1** — the wrong value, no exception |
| MySQL | integer precision counted the minus sign: 11 for `int`, where JDBC means 10 digits |
| MySQL | `getColumns.TYPE_NAME` returned `varbinary(32)` and dropped `UNSIGNED` |
| MySQL | `getString` on a `float` gave `0` through one protocol and `0.0` through the other |
| MySQL | `getColumns.COLUMN_SIZE` was 0 for every date and datetime |

Differences that remain are listed in the tests one at a time, and the two kinds are kept
apart on purpose: `allow(...)` is a place where two drivers may honestly disagree and seclume
has decided, with the reason; `knownDefect(...)` is a place where seclume is wrong and the fix
has not happened yet. Mixing them would turn the list into somewhere bugs go to be forgotten.

SQL Server and Oracle have no differential run yet. The harness is not database-specific — what
is missing is a corpus for each, and the vendor drivers are already on the module's classpath.

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

CockroachDB and YugabyteDB are described the same way, each under a key of its own, and each
is only tried when its `host` is set — a machine that has one and not the other simply says
so. The user, the database and the password file all default to
`seclume_test` / `seclume_test` / `.local-<key>-password`.

Nothing matching `.local-*` is checked in:

```properties
seclume.test.host=db.example.invalid
seclume.pg.host=db.example.invalid
seclume.pg.port=5433
seclume.pg.passwordFile=.local-pgtls-password
seclume.crdb.host=db.example.invalid
seclume.crdb.port=26257
seclume.yb.host=db.example.invalid
seclume.yb.port=5433
```

### Bringing those two up

Both have to be started **with authentication**, or the tests prove nothing and say so.

CockroachDB has no unencrypted port, so its certificates are made before the node starts.
The image's entrypoint refuses a listen address that is not loopback — a limitation of that
wrapper script, not of the server — so the binary is called directly:

```
podman volume create crdb-certs
img=cockroachdb/cockroach:v24.1.5
certs="--certs-dir=/certs --ca-key=/certs/ca.key"
podman run --rm -v crdb-certs:/certs:Z $img cert create-ca $certs
podman run --rm -v crdb-certs:/certs:Z $img cert create-node localhost 127.0.0.1 0.0.0.0 <this host> $certs
podman run --rm -v crdb-certs:/certs:Z $img cert create-client root $certs
podman run -d --name seclume-crdb -v crdb-certs:/certs:Z -p 26257:26257   --entrypoint /cockroach/cockroach $img start-single-node   --certs-dir=/certs --listen-addr=0.0.0.0:26257 --store=/tmp/crdb
podman exec seclume-crdb /cockroach/cockroach sql --certs-dir=/certs --host=localhost:26257   -e "create user seclume_test with password '…'; create database seclume_test;
      grant all on database seclume_test to seclume_test;"
```

YugabyteDB needs one flag, and its YSQL listens on the container's own address rather than on
loopback — which is what `hostname -i` is for:

```
podman run -d --name seclume-yb -p 5434:5433 yugabytedb/yugabyte:2024.1.3.0-b105   bin/yugabyted start --daemon=false --ysql_enable_auth=true
ip=$(podman exec seclume-yb hostname -i)
podman exec -e PGPASSWORD=yugabyte seclume-yb bin/ysqlsh -h "$ip" -U yugabyte -d yugabyte   -c "create user seclume_test with password '…'"   -c "create database seclume_test owner seclume_test"
```

## CI

`.github/workflows/ci.yml` runs the same tests against real servers on every push —
PostgreSQL 15 and 18, MySQL 8.4 and MariaDB 11.4, SQL Server 2022, Oracle Free 23ai, and
CockroachDB 24.1 and YugabyteDB 2024.1 for the claim that the PostgreSQL driver serves them
too. Those two demand a password like the rest, and the tests assert which method the server
asked for — SCRAM-SHA-256 over TLS for CockroachDB, md5 for YugabyteDB — so a server that
quietly stopped asking would fail the job rather than pass it.

If a run of yours has no server, it stays green and proves less. That is deliberate: a suite
that fails on a laptop teaches people to ignore it.
