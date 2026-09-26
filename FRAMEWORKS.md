# Frameworks

Produced by `space.seclume.verify.FrameworkMatrix` on 2026-09-24 by reading the test reports of the run that made it, not by hand.

**`unsupported` means nobody has run it**, not that it fails. The only way to change a cell is to write the test: a framework has to name a test class per server, and that class has to appear in a report with tests in it.

| | PostgreSQL | MySQL | SQL Server | Oracle |
|---|---|---|---|---|
| **Spring Data JPA** | verified (20) | verified (20) | verified (20) | verified (20) |
| **Hibernate** | verified (10) | verified (10) | verified (10) | verified (10) |
| **Flyway** | verified (20) | verified (20) | verified (20) | verified (20) |
| **Hibernate, the edges** | verified (5) | verified (5) | verified (5) | verified (5) |
| **Spring JDBC and transactions** | verified (13) | verified (13) | verified (13) | verified (13) |
| **Spring Data JDBC** | verified (1) | verified (1) | verified (1) | verified (1) |
| **Liquibase** | verified (1) | verified (1) | verified (1) | verified (1) |
| **jOOQ** | verified (1) | verified (1) | verified (1) | verified (1) |
| **MyBatis** | verified (1) | verified (1) | verified (1) | verified (1) |

- **Spring Data JPA** - repositories, derived queries, pagination, stored procedures
- **Hibernate** - every entity shape JPA allows, and every mapped Java type
- **Flyway** - the schema under each test is migrated by Flyway before it runs
- **Hibernate, the edges** - a JSON column, LOBs as values and as streams, @Formula, bulk HQL - the skipped cases are open gaps, named in the CHANGELOG
- **Spring JDBC and transactions** - REQUIRES_NEW, NESTED, readOnly, isolation, a timeout; batchUpdate, named parameters, generated keys, scripts, JDBC escapes
- **Spring Data JDBC** - an aggregate over two tables, optimistic locking, paging
- **Liquibase** - update, rollback, update again, and the history it keeps
- **jOOQ** - inserts, a batch, a typed read, a rolled-back transaction, a lazy cursor - SQL Server and Oracle with SQLDialect.DEFAULT, because jOOQ's free edition has no dialect for either
- **MyBatis** - generated keys, dynamic SQL, the batch executor, a typed null

## What this table does not say

That a verified cell covers everything the framework can do. It covers what its test class asks of it, which is written down beside each row above and is less than the whole of any of these libraries.
