# Audit remediation tracking

Source: SEC-AUDIT-2026-09-30-01, audited commit `e1983ad`.
Findings must be checked against current code; the original report's ratings
and claimed experiments are not treated as independently verified evidence.

## SEC-01 — session isolation

Implemented for review:

- Reset every used Seclume session, regardless of SQL tracking. Unwrapping
  the driver counts as use. Failed resets retire the physical connection.
- PostgreSQL uses DISCARD ALL and invalidates prepared statement caches;
  MySQL and SQL Server no longer skip resets based on SQL heuristics.
- Oracle reports an incomplete reset and is retired on return: arbitrary
  application contexts and dynamic ALTER SESSION cannot safely be inferred.
- Pool detach/adopt keeps the live session and transaction intact. Reset is
  deferred until the adopted borrow is returned.
- Foreign JDBC drivers without SessionReset retain JDBC-only cleanup; the
  stronger guarantee applies to Seclume drivers.

Evidence: 41 focused unit/regression tests passed. A separate live run passed
36 tests with zero skips across all four databases (SessionResetTest,
SessionContextTest, PoolHandOnSeamTest, UnconditionalSessionResetTest).
Stored procedures deliberately mutate tenant state without setting the SQL
tracker's flag. CI now executes and requires these pool regressions in each
database job, including MySQL and MariaDB; PostgreSQL also requires handoff tests.
CI results must be checked on the PR before declaring this finding complete.

## Remaining audit work, in sequence

1. SEC-02: asynchronous zeroization and caller-owned arena semantics.
2. SEC-03: public suffix handling for TLS wildcards.
3. SEC-04: TLS and memory-lock defaults, compatibility and migration coverage.
4. Security policy and vulnerability reporting process.
5. SEC-05: bounded MySQL split-packet reassembly.
6. TDS reassembly complexity, MemoryLock contention and WireBuffer growth.
7. JSON Unicode/parser hardening and the seven requested fuzz harnesses.
8. Release signing, SBOMs and provenance.
9. External assurance: OSS-Fuzz acceptance and sustained runs, hardware timing
   measurements, independent audit, 72-hour soak tests and governance.

External services, elapsed-time evidence, maintainer commitments and formal
certifications cannot be satisfied by adding files alone. Keep those gates
open until the corresponding evidence exists.
