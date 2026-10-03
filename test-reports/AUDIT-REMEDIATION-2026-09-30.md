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

## SEC-02 — secret cleanup checked against current code

Owned SecretScope allocations use shared arenas and can be wiped by a timeout
thread. Concurrent close calls wait for the complete wipe. Caller-owned arenas
remain owned by the caller: their lifetime and thread restrictions still apply,
and writers must stop before cleanup.

The focused checks on 2026-10-03 passed 39 tests with one Linux-specific check
skipped on Windows: AsyncSecretScopeTest, SecretScopeTest,
SecretLifecycleRegressionTest, WipeOnFailureTest, MemoryLockPagesTest and
MemoryLockRegressionTest. Coverage includes complete-capacity wipes, provider
errors, interrupted workers, concurrent closes and refusal of wrong-thread
cleanup without preventing the owner from subsequently wiping.

No new lifecycle defect was reproduced in these cases. This is not a proof
against callers violating the documented arena lifetime or writer contract.

## SEC-03 — public suffix boundaries for TLS wildcards

Implemented for review: HostnameMatch now checks an offline, pinned Public Suffix
List, using its ICANN entries with wildcard rules and exceptions.
Certificate patterns such as `*.co.uk` and `*.com.au` are refused; exact
names and wildcards below registrable domains remain supported. Missing or
unreadable list data refuses wildcards. PRIVATE hosting entries remain eligible
for provider certificates, with explicit RDS compatibility checks.

Seven new negative hostname cases failed before the fix. With the fix, 75 TLS
hostname, suffix and certificate-trust checks passed, including a generated
trusted certificate that must not cover independently controlled domains.
The source, SHA-256, license and update procedure accompany the bundled data.
Loading uses bounded bytes and strict UTF-8 decoding, with no reader exceptions
to the production-source credential-safety check. Native-image metadata includes
the resource; a native-image build was not run in this local verification.

## Remaining audit work, in sequence

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
