# Compatibility

Produced by `space.seclume.verify.Compatibility` on 2026-09-22 by connecting to each server, not by hand.
A blank cell means the server did not report that line at all.

| | PostgreSQL 16 | MySQL 8.4 | SQL Server 2022 | Oracle 23ai |
|---|---|---|---|---|
| **driver** | space.seclume.postgresql.jdbc.SeclumeDriver 0.1 | space.seclume.mysql.jdbc.MyDriver 0.1 | space.seclume.sqlserver.jdbc.TdsDriver 0.1 | space.seclume.oracle.jdbc.OraDriver 0.1 |
| **product** | PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2) | MySQL 8.4.11 | Microsoft SQL Server 16.0.4275.2 | Oracle 23.0.0.0.0 |
| **user** | seclume_test | seclume_test@% | sa | SECLUME_TEST |
| **catalog** | seclume_test | seclume_test | master | - |
| **read only** | false | false | false | false |
| **isolation** | read committed | repeatable read | read committed | read committed |
| **round trips counted** | true | true | true | true |
| **pipeline block** | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together |
| **block cursors** | yes - 500 rows came in 11 round trips | yes - 500 rows came in 13 round trips | yes - 500 rows came in 13 round trips | yes - 500 rows came in 10 round trips |
| **generated keys** | yes | yes | yes | yes, with named columns - Oracle needs a returning clause |
| **two-phase commit** | off on this server - max_prepared_transactions is 0 | XADataSource available - see the XA notes | XADataSource available - see the XA notes | XADataSource available - see the XA notes |
| **result limit** | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError |
| **failover** | one server - no failover | one server - no failover | one server - no failover | one server - no failover |
| **transaction, one query** | 2 | 2 | 2 | 1 |
| **prepared, first run** | 1 | 2 | 1 | 1 |
| **prepared, second run** | 1 | 1 | 1 | 1 |
| **measured with** | select 1 | select 1 | select 1 | select 1 from dual |
| **result** | everything answers | everything answers | everything answers | everything answers |
