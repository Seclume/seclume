# Security quality, measured

[![ci](https://github.com/Seclume/seclume/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Seclume/seclume/actions/workflows/ci.yml?query=branch%3Amain)
[![security](https://github.com/Seclume/seclume/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/Seclume/seclume/actions/workflows/security.yml?query=branch%3Amain)
[![codeql](https://github.com/Seclume/seclume/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Seclume/seclume/actions/workflows/codeql.yml?query=branch%3Amain)
[![fuzz](https://github.com/Seclume/seclume/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Seclume/seclume/actions/workflows/fuzz.yml)
[![mutation](https://github.com/Seclume/seclume/actions/workflows/mutation.yml/badge.svg)](https://github.com/Seclume/seclume/actions/workflows/mutation.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Seclume/seclume/badge)](https://scorecard.dev/viewer/?uri=github.com/Seclume/seclume)

What the tests of seclume establish, and how much of the code they reach. The rules for this
file:

- **Every figure is from a CI run that is linked next to it** and can be checked against the
  counts in that run's log. No figure is estimated, rounded up or taken from a local run.
- A figure is replaced by a newer one only together with the link to the run that produced it.
- What is not measured says so. An empty cell is not a zero and not a pass.

The security properties themselves, each with its attacker and its test, are in
[SECURITY-VERIFICATION.md](SECURITY-VERIFICATION.md). The attackers are in
[THREAT-MODEL.md](THREAT-MODEL.md). How to run each kind of test is in [TESTING.md](TESTING.md).

## Test architecture

| Layer | What it shows | Where it runs |
|---|---|---|
| Unit tests | each class's behaviour, including its error paths | every pull request, `core` job (29 modules) |
| Database tests | the drivers against real servers: PostgreSQL 15, 18, 19rc1; MySQL 8.4, 9.7, 26.10; MariaDB 11.4 to 13.1-rc; SQL Server 2022, 2025; Oracle Free; CockroachDB; YugabyteDB; PgBouncer | every pull request, one job per server |
| Heap and process proofs | no secret in a heap dump or anywhere in process memory after a real login - each with a negative control that must be found | `core`, `postgresql`, `security-platforms` |
| Security gate | every test that carries a security claim ran and passed - a skip fails the job | every job with a group in [`.github/security-gate.json`](.github/security-gate.json) |
| Property tests | invariants over thousands of seeded random cases: field encryption, the secret lifecycle (`SecretScopeModelTest`), URL redaction and parsing (`JdbcUrlPropertyTest`), the vendor drivers as oracles (`seclume-diff`, see below) | every pull request; `seclume-diff` on those that touch a driver or the core, and nightly (`differential.yml`, since 11.11.2026 - before, only `PgBouncerTest` of it ran in CI) |
| Hostile servers | every TLS mode against servers that refuse, break or fake TLS (`TlsNeverFallsBackTest`); logins and decoders against corrupted answers | every pull request |
| Fuzzing | Jazzer, corpus replay and coverage-guided search | `json-fuzz`, `parser-fuzz` on every pull request; nightly `fuzz` |
| Mutation testing | whether the tests notice a fault put into the code | `mutation` on pull requests that touch the packages; weekly |
| Static analysis | CodeQL, Semgrep, OpenSSF Scorecard | every pull request; Scorecard on `main` |
| Dependencies | CycloneDX SBOM of everything the build uses, checked by Trivy for HIGH and CRITICAL | every pull request (`dependencies`) |
| TLS conformance | TLS-Anvil against the own TLS client; interop against OpenSSL, GnuTLS, Go's crypto/tls, rustls and JSSE | scheduled (`tls-anvil`, `tls-interop`) |
| Flakiness | the whole of `ci.yml` three times on one commit | by hand, Saturday night (`flake-hunt`) |

**What blocks a merge.** Branch protection on `main` requires 16 checks, and administrators are
held to it too: `core`, `post-quantum`, `dependencies`, `semgrep`, `postgresql (15)`,
`postgresql (18)`, `pgbouncer`, `mysql (mysql:8.4, …)`, `mysql (mariadb:11.4, …)`, `sqlserver`,
`oracle`, `cockroachdb`, `yugabytedb`, `rabbitmq`, CodeQL and `analyze`.

## Baseline, 8 November 2026

The state before the round of work that started on 8 November 2026. It is the reference for
the before-and-after comparison.

### Coverage

The `core` job's tests - all that need no server - with JaCoCo 0.8.14, for commit
[`1c99717`](https://github.com/Seclume/seclume/commit/1c99717e97f9d28072d288f2875a3641c0e7110a).
Its Java code and tests are those of `main` at `0ed8239`.
[Run 42475880953](https://github.com/Seclume/seclume/actions/runs/42475880953), job `core`.
The figures are `covered / all`.

| | Lines | Line coverage | Branches | Branch coverage |
|---|---:|---:|---:|---:|
| **All 29 modules with a report** | 31272 / 55618 | **56.2 %** | 14694 / 28056 | **52.4 %** |
| seclume-core | 14228 / 20924 | 68.0 % | 6786 / 10556 | 64.3 % |
| seclume-postgresql | 1296 / 4277 | 30.3 % | 530 / 1932 | 27.4 % |
| seclume-mysql | 1668 / 3593 | 46.4 % | 627 / 1724 | 36.4 % |
| seclume-sqlserver | 1404 / 5172 | 27.1 % | 580 / 2656 | 21.8 % |
| seclume-oracle | 2292 / 6656 | 34.4 % | 1037 / 3302 | 31.4 % |
| seclume-pool | 1056 / 1837 | 57.5 % | 561 / 923 | 60.8 % |
| seclume-heapdump | 1272 / 1380 | 92.2 % | 752 / 880 | 85.5 % |

The security-critical packages, as named in
[`.github/coverage-critical.json`](.github/coverage-critical.json):

| Package | Why | Lines | Line coverage | Branches | Branch coverage |
|---|---|---:|---:|---:|---:|
| `space.seclume.secret` | secret providers, scopes, wiping | 2885 / 4368 | 66.0 % | 1382 / 2245 | 61.6 % |
| `space.seclume.internal` | native memory, locking, transports, TLS plumbing, URL parsing | 3205 / 6120 | 52.4 % | 1834 / 3292 | 55.7 % |
| `space.seclume.crypto` | keys in OpenSSL/CNG, primitives | 3003 / 4079 | 73.6 % | 890 / 1370 | 65.0 % |
| `space.seclume.tls` | the own TLS client | 2690 / 3442 | 78.2 % | 1168 / 1720 | 67.9 % |
| `space.seclume.field` | field encryption | 718 / 823 | 87.2 % | 399 / 452 | 88.3 % |
| `space.seclume.audit` | the signed access log | 362 / 385 | 94.0 % | 200 / 226 | 88.5 % |
| `space.seclume.pool` | the pool: session resets, tenant isolation | 1056 / 1837 | 57.5 % | 561 / 923 | 60.8 % |
| `space.seclume.heapdump` | heap dump redaction and scanning | 1272 / 1380 | 92.2 % | 752 / 880 | 85.5 % |

**Read with care.** These are the tests that need no server. Most of a driver's code runs only
against one, in the database jobs, and those did not record coverage then: the drivers' low
figures say what the unit tests reach, not what is tested. The `coverage` job merges the
database jobs' data with the core job's. Its first figures replace this caveat once a run on
`main` has produced them. Thirteen modules have no report: ten whose tests run only in other jobs
(`seclume-spring-boot-starter`, the MongoDB modules, `seclume-redis`, `seclume-kafka`,
`seclume-elasticsearch`, `seclume-micronaut`, `seclume-helidon`, `seclume-r2dbc`), and three that are
not library code (`seclume-bench`, `seclume-tls-anvil`, `seclume-spring-test`). Two runs of the
same commit can differ by a few lines where a test's path depends on timing - `seclume-ldap`
was 84.9 % in [run 42472937189](https://github.com/Seclume/seclume/actions/runs/42472937189)
and 84.5 % in the run above.

### Tests

| | Count | Source |
|---|---:|---|
| Tests run by the `core` job | 6045, of them 674 skipped | Surefire's results per module, [run 42475880953](https://github.com/Seclume/seclume/actions/runs/42475880953) |
| Security regression tests in the gate | 51 (core 37, PostgreSQL 5, MySQL 3, SQL Server 3, Oracle 3) | [`.github/security-gate.json`](.github/security-gate.json) at `0ed8239` |
| Fuzz test classes | 31, of them 12 with Jazzer `@FuzzTest` methods (21 methods) | the repository at `0ed8239` |
| Coverage-guided fuzz targets, nightly | 16, 15 minutes each | [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml) |

The database jobs run more tests. They are not in this count, which is that of the one job
whose results are summed here.

### Mutation score

PIT 1.30.1 on the four packages `mutation.yml` covered, in the scheduled
[run 42427494528](https://github.com/Seclume/seclume/actions/runs/42427494528) of 7 November
2026 (commit `1a48071`). Two scores, as `pit_report.py` reports them. "With a test" counts the
mutants on lines some test runs. "All" also counts the mutants on lines no test under PIT runs.
Most of those lines need a server, a KMS or Windows.

| Package | Killed, of those with a test | Score with a test | Killed, of all | Score of all |
|---|---:|---:|---:|---:|
| `field` | 472 / 483 | 97.7 % | 472 / 534 | 88.4 % |
| `audit` | 228 / 250 | 91.2 % | 228 / 268 | 85.1 % |
| `crypto` | 2368 / 2549 | 92.9 % | 2368 / 3148 | 75.2 % |
| `secret` | 1431 / 1641 | 87.2 % | 1431 / 2486 | 57.6 % |

`tls`, `internal` and `pool` were not under mutation testing.

### Fuzzing

The nightly `fuzz` run on the five nights before the baseline:

| Night | Run | Result |
|---|---|---|
| 5 Nov | [42005416211](https://github.com/Seclume/seclume/actions/runs/42005416211) | red: `ConstantTimeLeakageTest` (t = -11.5), not a fuzz finding |
| 6 Nov | [42197677715](https://github.com/Seclume/seclume/actions/runs/42197677715) | green |
| 7 Nov | [42358677439](https://github.com/Seclume/seclume/actions/runs/42358677439) | red: `ConstantTimeLeakageTest` (t = 6.8, 15.3, 8.9), not a fuzz finding |
| 8 Nov | [42467135680](https://github.com/Seclume/seclume/actions/runs/42467135680) | green |

No coverage-guided target failed on these nights. An input that fails a target is uploaded as
an artifact (`crash-*`); it then goes into `src/test/resources` as a regression case, which
replays in every build.

### Native sanitizers

Not run. seclume has no C of its own in the library: native code is OpenSSL 3 and, on
Windows, CNG, reached through the FFM API. Building OpenSSL with AddressSanitizer and running
the tests against it has not been set up yet.

## What the 8 November round found

Each finding was reproduced, has a regression test that fails on the code before the fix, and
was fixed in the same pull request.

| Finding | Found by | Fixed in |
|---|---|---|
| A vendor's JDBC URL in an error message kept its password: SQL Server's `;password=`, `//user:pw@`, Oracle's `user/pw@`, MySQL's key-value hosts | `JdbcUrlPropertyTest` (new property test) | [#266](https://github.com/Seclume/seclume/pull/266) |
| A seclume URL with `user:pw@` before its host: the password became a port or part of a host name, and was named in messages | `JdbcUrlPropertyTest` | [#266](https://github.com/Seclume/seclume/pull/266) |
| A renewal's old key stayed in OpenSSL's memory for a minute, through a checkpoint; a closed Vault PKI, SPIFFE or reloading key manager freed no key at all | the core job's red `VaultPkiTest` | [#263](https://github.com/Seclume/seclume/pull/263) |

Tested and found sound: no TLS mode of the PostgreSQL or MySQL driver falls back, against
seven hostile servers on both TLS stacks (`TlsNeverFallsBackTest`,
[#268](https://github.com/Seclume/seclume/pull/268)). Three faults put into each driver's TLS
negotiation are each detected.

## Platforms and JDKs

| | Tested | How |
|---|---|---|
| linux-x64 | everything above | every job |
| linux-arm64 | the security gate's core group | `security-platforms` |
| windows-x64, macos-arm64 | the security gate's core group; the PostgreSQL, MySQL and MongoDB drivers | `security-platforms`, `postgresql-platforms`, `mysql-platforms`, `mongodb-platforms` |
| JDK 25 (Temurin) | everything | every job; the code is compiled for release 25 |
| JDK 27 | Helidon 27 SE only | `framework-compat` |

Other JDKs and other platforms are not tested.

## Known limits and untested areas

- **Coverage of the database tests** has been recorded only since the `coverage` job was added.
  The figures above are from the unit tests alone.
- **Native code** is OpenSSL's and CNG's. Their own testing covers it. seclume tests the
  boundary - what it passes in, what it frees, and that nothing it gave them is left behind -
  but not their memory safety. No sanitizer build is run yet.
- **Mutation testing** covers four packages. `tls`, `internal`, `pool` and the drivers are not
  under it yet.
- **The constant-time measurement** found `ConstantTime.equals` leaking on two of five nights
  and not on the others or locally. The failure now names the processor, so that the red nights
  can be attributed to the code, a processor model or noise. Open until then.
- **A process killed with `SIGKILL`** wipes nothing; its locked pages go back to the kernel,
  which zeroes them before reuse. Tested only as far as that the pages were locked.
- **Property-test library.** The property tests use a seeded `Random` and a model, not jqwik:
  jqwik runs on the JUnit Platform 1.x only, and the tests run on JUnit 6. Each failure names its
  seed and round and replays with `-Dseclume.<name>.seed=`.
