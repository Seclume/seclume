# Moving from HikariCP, pgjdbc, Connector/J, mssql-jdbc or ojdbc

Start with the tool: it translates the configuration you have and names what was unsafe in it.

```
java -jar seclume-verify.jar --migrate application.properties
```

Then the part people search for: the errors that stop happening. Each row names the test that
shows it, run against real servers. Where seclume does not make the error impossible but warns
earlier or says more, the row says that instead. Everything else is in
[FEATURES.md](FEATURES.md).

## Errors that go away

| The error you know | What happens instead | Evidence |
|---|---|---|
| `column "doc" is of type jsonb but expression is of type character varying` (pgjdbc, unless `stringtype=unspecified`) | A string parameter's type is left to the server, so `setString` fills `jsonb`, `uuid` and enum columns | `PgjdbcErrorsTest.aStringGoesIntoJsonbAndUuidColumns` |
| `ERROR: cached plan must not change result type` after a deployment altered a table | Outside a transaction the plan is replaced and the statement runs again. Inside one, the error goes to the caller, because the transaction is already aborted | `PgjdbcErrorsTest.aPreparedStatementSurvivesTheTableChangingUnderIt` |
| `ORA-01795: maximum number of expressions in a list is 1000`, and SQL Server's `The incoming request has too many parameters. The server supports a maximum of 2100 parameters.` | `where id in (?)` with `setObject(1, list)` binds the whole list as one value, with one plan and no limit | `InListTest` (5000 elements, all four servers) |
| `Communications link failure` / `The last packet successfully received from the server was … ago` on a connection that sat idle in the pool | The pool keeps idle connections alive below the server's own `wait_timeout` / `idle_session_timeout` / `IDLE_TIME`, and TCP keepalive keeps firewalls and load balancers from dropping them | `IdleLimitTest`, with a control that the server does close the session |
| `ORA-01000: maximum open cursors exceeded` from statements a borrower forgot | Statements left open are closed when the connection is returned, and logged with the place they were created | `SessionResetTest.statementsLeftOpenAreClosedOnReturnAndCounted` |
| `password authentication failed for user "v-token-…"` an hour after start, with Vault dynamic credentials | The pool retires connections before their credential expires and opens the replacement first | `CredentialExpiryTest` |
| `PKIX path building failed`, answered with `trustServerCertificate=true` or `sslmode=require` | `tlsRootCert=/path/ca.pem` names the CA for one connection. `tlsPin=sha256/…` pins the server's key. `seclume-verify --print-pin` shows the pin | `TrustChoiceTest`, `PinnedTlsTest` (all four servers) |
| `java.lang.OutOfMemoryError: Java heap space` from a query without a `where` | Data sources made by the starter have a result limit (a quarter of the heap, 16–256 MB), and that one statement fails with a message naming the limit | `ResultLimitDefaultTest` |

## Failures that were silent and are not any more

These produced no error at all, which is worse than any of the above.

| What happened | What happens instead | Evidence |
|---|---|---|
| The password in a heap dump: `/actuator/heapdump`, `-XX:+HeapDumpOnOutOfMemoryError`, a support upload | It is never a `String` or `char[]`. It lives in locked native memory, is left out of crash dumps, and is wiped | `PgHeapDumpTest`, `MyHeapDumpTest`, `TdsHeapDumpTest`, `OracleHeapDumpTest`, each with a control that must find it |
| `SET app.tenant_id = 42` reaching the next request on the same pooled connection, which is how row-level security usually breaks | Session state is reset on return, and with a `SeclumeSessionContext` bean the pool sets the tenant on every borrow itself | `SessionResetTest`, `SessionContextTest` |
| A commit whose answer was lost, reported as an ordinary failure and retried, so the row exists twice | `TransactionResolutionUnknownException`, SQLState `08007`, never retried | `CommitOutcomeTest` |
| An index scan on a `varchar` column because every Java driver sends text as `nvarchar` (SQL Server) | ASCII text compared with a `varchar` column goes as `varchar`, and the plan shows a seek | `VarcharParametersTest`, which reads the cached plan |
| `setReadOnly(true)` behind PgBouncer in transaction mode making *another* client's session read-only | With `proxyMode=transaction`, read-only and isolation travel in each transaction's own `BEGIN` | `PgBouncerTest`, with a control that shows the leak |
| A killed MySQL statement that returns a partial answer as success | `setQueryTimeout` turns it into `SQLTimeoutException` | `LocalQueryTimeoutTest` (MySQL) |

## Warned about before it happens

| The error | What seclume does | Evidence |
|---|---|---|
| `FATAL: sorry, too many clients already` after scaling out | At its first connection the pool compares its size with the server's free connections and warns while there is still room. `seclume-verify` prints a `capacity` line | `CapacityTest`, `CapacityWarningTest` |
| `Connection is not available, request timed out after 30000ms` | Still a timeout, but the message names the three connections out the longest, and with leak detection on it says where they were borrowed | `PoolTest` |
| Running transactions cut off by SIGTERM | Closing the pool lets borrowed connections finish for up to `shutdown-timeout` (10 s) | `ShutdownDrainTest` |

## Not yet

These still fail with seclume, and it says so rather than pretending otherwise:
- Windows' SSPI, SQL Server Integrated Security and Oracle Kerberos logins. Azure AD
  (`FEDAUTH`) works as `authentication=token` with a token provider, not yet run against a
  live Azure SQL. Kerberos for PostgreSQL and MariaDB on Linux works.
- Oracle Native Network Encryption. TNS aliases from `tnsnames.ora` work: use
  `jdbc:seclume:oracle:tns:ALIAS`.

See "What it does not do yet" in the [README](README.md).
