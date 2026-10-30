# Test strategy report

What seclume's tests showed before this round of work, what was added, what was found, and what
is still missing. Status at 2026-10-30. It covers the pull requests of that day:
- #165: Flight Recorder redaction;
- #166 and #171: the admission webhook and its chart;
- #168: the Central bundle;
- #169: audit preparation and fuzzing;
- #170: getting started;
- #172: current server versions;
- this one: the security gate and platforms.

Numbers are counted from the repository, not estimated. Results are what CI or a local run
reported, with the platform named. Nothing here is simulated.

## 1. Where it started

The test suite was already unusually strong where seclume's claim lives:

- **632 test classes, 2,736 test methods.** Every database driver runs against real servers in CI:
  PostgreSQL 15 and 18, MySQL 8.4, MariaDB 11.4, SQL Server 2022, Oracle Free, CockroachDB,
  YugabyteDB, MongoDB, Redis, Kafka, RabbitMQ, Vault and OpenBao, Elasticsearch and OpenSearch.
- **Proofs with negative controls.** The heap is dumped after real logins and searched in every
  encoding (`HeapDumpTest`, `NoCredentialOnTheHeapTest`, `NoKeyOnTheHeapTest`), and all
  process memory is searched through `/proc/<pid>/mem` (`ProcessMemoryTest`). In each case a
  control that puts the secret on the heap has to be found.
- **Secret lifecycle.**
  - Zeroing is checked by reading the memory back (`SecretScopeTest`).
  - Wiping after errors, failed logins and refused connections
    (`SecretLifecycleRegressionTest`, `WipeOnFailureTest`, `LoginFailureWipeTest`,
    `ConnectFailureWipeTest`).
  - Receive buffers (`ReceiveBufferWipeTest`).
  - Memory locking and dump exclusion, read from `/proc/self/smaps` (`MemoryLock*Test`,
    `DumpExclusionTest`).
- **TLS:**
  - RFC 8448 vectors and Wycheproof;
  - interop against OpenSSL, GnuTLS, Go, rustls and JSSE (weekly);
  - TLS-Anvil (weekly);
  - refusal tests for untrusted certificates, wrong host names and low versions.
- **Hostile input:** 14 Jazzer targets over the four database protocols, TLS, SCRAM, MongoDB,
  LDAP, JSON and HTTP. A deterministic sample runs in every build, the corpus nightly, and the
  JSON reader gets a minute of search per PR.
- **Timing:** dudect-style tests with a control that must leak (nightly).
- **Static rules:** `ForbiddenApiTest` (no heap paths for secrets), `ErrorMessageTest` (no secret
  in messages), `DocumentationTest`.
- **Supply chain:** CodeQL, Semgrep, Trivy, Scorecard, Dependabot, actions pinned by digest.

## 2. What was missing

| Gap | Why it mattered |
|---|---|
| **No platform but Linux x86_64 in CI** | The Windows paths (CNG, `VirtualLock`, `WerRegisterExcludedMemoryBlock`) and ARM64 were tested by hand at best; the docs claimed them |
| **Skipped tests counted as passed** | A security test that skips - no OpenSSL, no `/proc`, a server not up - left the build green. Only the pool regressions and a few database tests had a "must have run" check |
| **No matrix of claims to evidence** | THREAT-MODEL and SECURITY named tests; nothing tied every claim to a test, a method, a result and a platform |
| **Fuzzing did not cover the newest decoders** | The SPIFFE agent's answers, KMS answers and heap dumps from outside |
| **Server versions behind** | CockroachDB 24.1 and YugabyteDB 2024.1 out of support; RabbitMQ from Ubuntu's 3.12; no MySQL 9.x, MariaDB 12+, SQL Server 2025, PostgreSQL 19 or MongoDB 9. SUPPORTED-VERSIONS.md claimed SQL Server 2025 in CI, which CI had never run |
| **No audit material** | No threat model in one place, no inventory of what is computed here rather than taken from a library |

## 3. What was added

| Area | Added | Where |
|---|---|---|
| Native memory | `NativeAllocationFailureTest`: an allocation refused first and after five scopes, and a provider running out halfway. Checks that nothing is left open, earlier scopes stay whole and are wiped (read back), and memory is used again afterwards | this PR |
| Release gate | `security_gate.py` with PASS, FAIL, SKIPPED, INCONCLUSIVE and NOT APPLICABLE over 33 tests in 5 groups; in the core job and the four database jobs; tested itself (`test_security_gate.py`) | this PR |
| Platforms | `security-platforms`: the gate's core group on Linux ARM64 and Windows x64 | this PR |
| Verification matrix | SECURITY-VERIFICATION.md: property, attacker, test, method, result, limits, platform; what each platform protects | this PR |
| Audit material | THREAT-MODEL.md, AUDIT.md (crypto inventory, fuzzing map, open questions) | #169 |
| Fuzzing | Workload API answers (X.509 and JWT), KMS answers (raw ECDSA to DER with a property test, PEM), broken heap dumps; a `parser-fuzz` job with 8 targets a minute each per PR, findings as annotations | #169 |
| Server versions | PostgreSQL 19 RC1, MySQL 9.7 LTS and 26.10, MariaDB 12.3 LTS and 13.0, SQL Server 2025, MongoDB 9.0; CockroachDB 26.2, YugabyteDB 2026.1, RabbitMQ 4.4, Kafka 4.4, Vault 2.0 | #172 |
| End to end | getting-started example in CI: the usual stack must leak the password into the heap, seclume must not | #170 |
| Kubernetes | the webhook on kind with a real out-of-memory dump redacted in the pod; the chart in all TLS modes | #166, #171 |

## 4. Numbers

| | before | added | after |
|---|---|---|---|
| Test classes | 632 | 10 (`NativeAllocationFailureTest`, `WorkloadApiAnswerFuzzTest`, `KmsAnswerFuzzTest`, `BrokenDumpTest`, `RecordingRedactionTest`, `JsonTest`, `InjectionTest`, `AdmissionServerTest` and the Python `test_central_bundle`, `test_security_gate`) | 642 |
| Jazzer targets | 14 | 4 | 18 |
| Tests under the release gate | 0 (only pool and framework "must have run" checks) | 33 | 33 |
| CI platforms | linux-x64 | linux-arm64, windows-x64 | 3 |

## 5. What ran, and its result

| Run | Where | Result |
|---|---|---|
| The gate's core group, 19 of its 24 classes (2,333 cases) | local, Linux x86_64, JDK 25 | PASS 19, nothing skipped. The other 5 need Maven test dependencies that cannot be reached from the sandbox; they run in CI |
| heapdump suite with `BrokenDumpTest` | local | 36/36 |
| `WorkloadApiAnswerFuzzTest` sample | local | 3/3, also at 20,000 mutations |
| `KmsAnswerFuzzTest` | local | 3/3 |
| `parser-fuzz`, 8 targets | CI | 2 FAIL on the first run: a real defect (section 6). After the fix, the job is rerun on #169 |
| `test_security_gate.py`, `test_central_bundle.py` | local | 6/6 and 6/6 |
| `security-platforms` on ARM64 and Windows | CI | first run with this PR, recorded below once it is in |

## 6. Security defects found

| Defect | Found by | Fixed |
|---|---|---|
| A broken heap dump made attribution - and the redaction, the sidecar and the in-app folder watch - allocate a record's claimed length, up to 2 GB | `BrokenDumpTest`, seeded mutation | #169: a length beyond the file is an `IOException` |
| heapcheck's HPROF scanner ended broken dumps in `BufferUnderflowException`, `IndexOutOfBoundsException`, `IllegalArgumentException` | the same | #169 |
| An unreadable key in a SPIFFE agent's answer surfaced as an `IllegalArgumentException` | `WorkloadApiAnswerFuzzTest` sample | #169 |
| A protobuf length near 2^63 in a SPIFFE agent's answer wrapped the bounds check `at + length > end` | `parser-fuzz` in CI, in its first minute | #169: `length > end - at`, with a regression test |
| SUPPORTED-VERSIONS.md claimed SQL Server 2025 was tested in CI | review | #172 makes it true |

## 7. Remaining risks

- **No external review** of the TLS client and the primitives computed in Java (AUDIT.md lists
  the open questions).
- **Constant time is measured, not proven.** The JIT gives no guarantee.
- **macOS is not gated.** It has no dump exclusion and no private-key backend.
- **Windows and ARM64 run the core group only.** The database drivers run against servers on
  Linux x86_64 only.
- **No 72-hour endurance run.** The nightly benchmarks include a chaos benchmark and the pool
  state machine (20,000 sequences), but no long soak with native-memory accounting.
- **Native memory exhaustion for real** ends the JVM rather than seclume's code. A child JVM
  that allocated 16 KB secret scopes until the machine refused memory ended in HotSpot's
  `os::commit_memory failed` error report, not an `OutOfMemoryError` (2026-10-30). The secrets
  end with the process, and the kernel zeroes the pages before reuse. What returns as an
  `OutOfMemoryError` is tested (`NativeAllocationFailureTest`).

## 8. Recommendations

1. An external review of `space.seclume.tls` and `space.seclume.crypto`. AUDIT.md is written for
   it.
2. A nightly soak profile: hours of connection lifecycles with secret rotation, with
   `-XX:NativeMemoryTracking=summary` sampled and compared across the run, failing on growth.
3. Run the database jobs on ARM64 as well. GitHub's ARM runners are free for public
   repositories.
4. Grow the gate: every new security claim gets its manifest entry in the same pull request.

## 9. Rating

**8 / 10** for quality, meaningfulness, reproducibility and security relevance - not for the
number of tests.

What earns it:
- every central claim is tested the way an attacker would check it, by searching memory and
  dumps for a random canary;
- every proof has a control that must fail;
- the tests run against the real servers;
- and now, skipped security tests stop the build.

What keeps it from higher:
- one platform for most of the suite;
- no external review;
- timing measured rather than proven;
- no long-running soak.
