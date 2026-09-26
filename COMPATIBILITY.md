# Compatibility

Produced by `space.seclume.verify.Compatibility` on 2026-09-24 by connecting to each server, not by hand.
A blank cell means the server did not report that line at all.

| | PostgreSQL 16 | MySQL 8.4 | SQL Server 2022 | SQL Server 2025 (TDS 8.0) | Oracle 23ai | Oracle 23ai (TCPS) | CockroachDB | YugabyteDB |
|---|---|---|---|---|---|---|---|---|
| **driver** | space.seclume.postgresql.jdbc.SeclumeDriver 0.1 | space.seclume.mysql.jdbc.MyDriver 0.1 | space.seclume.sqlserver.jdbc.TdsDriver 0.1 | space.seclume.sqlserver.jdbc.TdsDriver 0.1 | space.seclume.oracle.jdbc.OraDriver 0.1 | space.seclume.oracle.jdbc.OraDriver 0.1 | space.seclume.postgresql.jdbc.SeclumeDriver 0.1 | space.seclume.postgresql.jdbc.SeclumeDriver 0.1 |
| **product** | PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2) | MySQL 8.4.11 | Microsoft SQL Server 16.0.4275.2 | Microsoft SQL Server 17.0.5005.3 | Oracle 23.0.0.0.0 | Oracle 23.0.0.0.0 | PostgreSQL 13.0.0 | PostgreSQL 11.2-YB-2024.1.3.0-b0 |
| **user** | seclume_test | seclume_test@% | sa | sa | SECLUME_TEST | SECLUME_TEST | seclume_test | seclume_test |
| **catalog** | seclume_test | seclume_test | master | master | - | - | seclume_test | seclume_test |
| **read only** | false | false | false | false | false | false | false | false |
| **isolation** | read committed | repeatable read | read committed | read committed | read committed | read committed | read committed | read committed |
| **round trips counted** | true | true | true | true | true | true | true | true |
| **authentication** | scram-sha-256-plus | caching_sha2_password | SQL login (LOGIN7, inside TLS) | SQL login (LOGIN7, inside TLS) | O5LOGON (12c verifier, AES-256) | O5LOGON (12c verifier, AES-256) | scram-sha-256 | md5 |
| **encryption** | TLSv1.3 / TLS_AES_256_GCM_SHA384 (seclume) | TLSv1.3 / TLS_AES_256_GCM_SHA384 (seclume) | TLSv1.2 / TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | TLSv1.3 / TLS_AES_256_GCM_SHA384 (seclume) | none - this connection is in the clear | TLSv1.3 / TLS_AES_256_GCM_SHA384 (seclume) | TLSv1.3 / TLS_AES_128_GCM_SHA256 | none - this connection is in the clear |
| **pipeline block** | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together | yes - writes in a Pipeline block go out together |
| **block cursors** | yes - 500 rows came in 11 round trips | yes - 500 rows came in 13 round trips | yes - 500 rows came in 13 round trips | yes - 500 rows came in 13 round trips | yes - 500 rows came in 10 round trips | yes - 500 rows came in 10 round trips | yes - 500 rows came in 11 round trips | yes - 500 rows came in 11 round trips |
| **generated keys** | yes | yes | yes | yes | yes, with named columns - Oracle needs a returning clause | yes, with named columns - Oracle needs a returning clause | yes | yes |
| **two-phase commit** | off on this server - max_prepared_transactions is 0 | XADataSource available - see the XA notes | XADataSource available - see the XA notes | XADataSource available - see the XA notes | XADataSource available - see the XA notes | XADataSource available - see the XA notes | could not tell: unrecognized configuration parameter "max_prepared_transactions" | off on this server - max_prepared_transactions is 0 |
| **result limit** | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError | off - a runaway query ends in an OutOfMemoryError |
| **failover** | one server - no failover | one server - no failover | one server - no failover | one server - no failover | one server - no failover | one server - no failover | one server - no failover | one server - no failover |
| **transaction, one query** | 2 | 2 | 2 | 2 | 1 | 1 | 2 | 2 |
| **prepared, first run** | 1 | 2 | 1 | 1 | 1 | 1 | 1 | 1 |
| **prepared, second run** | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| **measured with** | select 1 | select 1 | select 1 | select 1 | select 1 from dual | select 1 from dual | select 1 | select 1 |
| **result** | everything answers | everything answers | everything answers | everything answers | everything answers | everything answers | everything answers | everything answers |
