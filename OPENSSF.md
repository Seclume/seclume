# OpenSSF: Best Practices badge and Scorecard

Two outside measures of how seclume is run, and where each stands.

- **[OpenSSF Best Practices](https://www.bestpractices.dev/en/projects/15186)** - a
  questionnaire the maintainers answer, project 15186. Below, every criterion of the
  **passing** level with the answer this repository supports and the evidence for it, so that
  the form can be filled from here and checked against it.
- **[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Seclume/seclume)** -
  automated checks of the repository itself. `scorecard.yml` runs on every push to `main` and
  weekly, uploads SARIF to GitHub code scanning and publishes the result the badge reads;
  `scorecard-report.yml` runs the same checks and writes every score with its reason into the
  run's summary. The checks below 10 are listed at the end.

The criteria are those of
[criteria.yml](https://github.com/coreinfrastructure/best-practices-badge/blob/main/criteria/criteria.yml)
as of 11 November 2026: 67 at the passing level, 43 of them MUST. "Met" below is what this
repository shows; the answers are given on bestpractices.dev by a maintainer.

Links are relative to `https://github.com/Seclume/seclume/blob/main/`.

## Passing level

### Basics

| Criterion | | Answer | Evidence |
|---|---|---|---|
| `description_good` | MUST | Met | [README.md](README.md) - first lines: what it does, the problem it solves |
| `interact` | MUST | Met | README (Maven Central coordinates), [CONTRIBUTING.md](CONTRIBUTING.md) (issues, pull requests) |
| `contribution` | MUST | Met | URL: [CONTRIBUTING.md](CONTRIBUTING.md) |
| `contribution_requirements` | SHOULD | Met | URL: [CONTRIBUTING.md](CONTRIBUTING.md) - tests, style, compiler warnings, no secrets in reports |
| `floss_license` | MUST | Met | Apache-2.0 |
| `floss_license_osi` | SUGGESTED | Met | Apache-2.0 is OSI-approved |
| `license_location` | MUST | Met | URL: [LICENSE](LICENSE) |
| `documentation_basics` | MUST | Met | [README.md](README.md), [FEATURES.md](FEATURES.md), [TLS.md](TLS.md), [PROVIDERS.md](PROVIDERS.md) |
| `documentation_interface` | MUST | Met | [SECRETS-API.md](SECRETS-API.md), the Javadoc published with every release |
| `sites_https` | MUST | Met | GitHub, Maven Central and seclume.space, all HTTPS |
| `discussion` | MUST | Met | [GitHub issues](https://github.com/Seclume/seclume/issues): searchable, addressable by URL, open to anyone |
| `english` | SHOULD | Met | documentation in English; CONTRIBUTING.md asks for English reports |
| `maintained` | MUST | Met | commits and releases in the last months ([CHANGELOG.md](CHANGELOG.md)) |

### Change control

| Criterion | | Answer | Evidence |
|---|---|---|---|
| `repo_public` | MUST | Met | https://github.com/Seclume/seclume |
| `repo_track` | MUST | Met | git: who changed what, when |
| `repo_interim` | MUST | Met | every change reaches `main` through a pull request between releases |
| `repo_distributed` | SUGGESTED | Met | git |
| `version_unique` | MUST | Met | `v0.9.0` ... `v0.13.1` |
| `version_semver` | SUGGESTED | Met | [CHANGELOG.md](CHANGELOG.md): "Versions follow Semantic Versioning" |
| `version_tags` | SUGGESTED | Met | signed tags per release ([SECURITY.md](SECURITY.md#verifying-a-release)) |
| `release_notes` | MUST | Met | URL: [CHANGELOG.md](CHANGELOG.md) |
| `release_notes_vulns` | MUST | N/A | no vulnerability of seclume has had a CVE or other public identifier yet; the security fixes are named in CHANGELOG.md and [REVIEWS.md](REVIEWS.md) all the same |

### Reporting

| Criterion | | Answer | Evidence |
|---|---|---|---|
| `report_process` | MUST | Met | URL: [CONTRIBUTING.md](CONTRIBUTING.md) - GitHub issues |
| `report_tracker` | SHOULD | Met | GitHub issues |
| `report_responses` | MUST | Met | no bug report has come in yet (11 November 2026); the criterion concerns those that do |
| `enhancement_responses` | SHOULD | Met | as above, none received |
| `report_archive` | MUST | Met | URL: https://github.com/Seclume/seclume/issues?q=is%3Aissue |
| `vulnerability_report_process` | MUST | Met | URL: [SECURITY.md](SECURITY.md) |
| `vulnerability_report_private` | MUST | Met | URL: https://github.com/Seclume/seclume/security/advisories/new - private vulnerability reporting is enabled |
| `vulnerability_report_response` | MUST | Met | no report in the last six months. SECURITY.md promises no response time yet; adding one is a maintainer's decision |

### Quality

| Criterion | | Answer | Evidence |
|---|---|---|---|
| `build` | MUST | Met | `./mvnw -B package` ([CONTRIBUTING.md](CONTRIBUTING.md)) |
| `build_common_tools` | SUGGESTED | Met | Maven, through the Maven wrapper |
| `build_floss_tools` | SHOULD | Met | Maven and OpenJDK |
| `test` | MUST | Met | JUnit suites in every module; [TESTING.md](TESTING.md) |
| `test_invocation` | SHOULD | Met | `./mvnw -B test` |
| `test_most` | SUGGESTED | Met | all tests of all CI jobs together: 65.0 % of lines, 60.4 % of branches ([SECURITY-QUALITY.md](SECURITY-QUALITY.md)) |
| `test_continuous_integration` | SUGGESTED | Met | `.github/workflows/ci.yml` on every pull request, against real PostgreSQL, MySQL, MariaDB, SQL Server and Oracle servers |
| `test_policy` | MUST | Met | [CONTRIBUTING.md](CONTRIBUTING.md): regression tests for fixes, tests for new functionality |
| `tests_are_added` | MUST | Met | the pull requests of the last months; every review finding in [REVIEWS.md](REVIEWS.md) came with a test that failed before its fix |
| `tests_documented_added` | SUGGESTED | Met | [CONTRIBUTING.md](CONTRIBUTING.md) |
| `warnings` | MUST | Met | `-Xlint:all` in `pom.xml` |
| `warnings_fixed` | MUST | Met | `-Werror`: a warning fails the build |
| `warnings_strict` | SUGGESTED | Met | `-Xlint:all -Werror`, plus CodeQL and Semgrep |

### Security

| Criterion | | Answer | Evidence |
|---|---|---|---|
| `know_secure_design` | MUST | Met | [THREAT-MODEL.md](THREAT-MODEL.md), [SECURITY-VERIFICATION.md](SECURITY-VERIFICATION.md) |
| `know_common_errors` | MUST | Met | [REVIEWS.md](REVIEWS.md) (what a review checks), [TLS.md](TLS.md) (what the TLS 1.2 profile leaves out and why) |
| `crypto_published` | MUST | Met | TLS 1.3 and 1.2 (RFC 8446, 5246), AES-GCM, ECDHE on X25519/P-256/P-384, ML-KEM, PBKDF2, SCRAM (RFC 5802/7677), HKDF, Shamir's secret sharing - published and reviewed algorithms only |
| `crypto_call` | SHOULD | **Unmet, justified** | seclume has its own TLS client and its own digests, so that traffic secrets and passwords never become Java objects ([TLS.md](TLS.md)). What it does not write itself: the key exchange, ML-KEM and AES-GCM run in OpenSSL or CNG, and certificates and signatures are checked by the JDK. A platform without OpenSSL or CNG falls back to a constant-time Java AES |
| `crypto_floss` | MUST | Met | everything runs on OpenJDK and OpenSSL |
| `crypto_keylength` | MUST | Met | fixed TLS key sizes of at least 128-bit security; RSA below 2048 and EC below 256 bits refused ([TLS.md](TLS.md)) |
| `crypto_working` | MUST | Met, with a note | no MD4, RC4, DES or CBC by default. MD5 is answered only when a PostgreSQL server's `pg_hba.conf` asks for an `md5` login - libpq and pgjdbc do the same - and `requireAuth=scram-sha-256` refuses it |
| `crypto_weaknesses` | SHOULD | Met, with a note | SHA-1 only where a protocol demands it: MySQL's `mysql_native_password`, Oracle's 11g verifier (`legacyVerifier11g`, off by default) |
| `crypto_pfs` | SHOULD | Met | TLS 1.3; the TLS 1.2 profile has ECDHE only, no static RSA |
| `crypto_password_storage` | MUST | N/A | seclume stores no passwords of users; it reads its own credentials from a secret provider |
| `crypto_random` | MUST | Met | keys and nonces from the operating system's generator, written straight into native memory: `getrandom(2)`, `BCryptGenRandom`, OpenSSL's generator - `SecureRandom` where there is none of these (`Entropy`) |
| `delivery_mitm` | MUST | Met | Maven Central and GitHub Packages over HTTPS; every file signed with OpenPGP ([SECURITY.md](SECURITY.md#verifying-a-release)) |
| `delivery_unsigned` | MUST | Met | no hash is fetched over HTTP; the Maven wrapper's jar is checked against `wrapperSha256Sum` |
| `vulnerabilities_fixed_60_days` | MUST | Met | no publicly known vulnerability of medium or higher severity is open; the review findings were fixed within days ([REVIEWS.md](REVIEWS.md)) |
| `vulnerabilities_critical_fixed` | SHOULD | Met | as above |
| `no_leaked_credentials` | MUST | Met | the only passwords in the repository are throwaway ones for CI's own containers, explained at the top of `ci.yml`; repository secrets override them. Semgrep's `p/secrets` rules run on every pull request |

### Analysis

| Criterion | | Answer | Evidence |
|---|---|---|---|
| `static_analysis` | MUST | Met | justification: CodeQL (`codeql.yml`) and Semgrep (`security.yml`, the `p/java`, `p/security-audit` and `p/secrets` rules) on every pull request, both required checks of `main` |
| `static_analysis_common_vulnerabilities` | SUGGESTED | Met | CodeQL's security queries, Semgrep's security rules |
| `static_analysis_fixed` | MUST | Met | a finding of CodeQL or Semgrep fails a required check, so it is fixed - or dismissed with its reason in the source - before the merge |
| `static_analysis_often` | SUGGESTED | Met | every pull request, every push to `main`, and weekly |
| `dynamic_analysis` | SUGGESTED | Met | Jazzer fuzzing every night (`fuzz.yml`), its targets replayed over their corpus with the tests of every pull request; TLS-Anvil weekly (`tls-anvil.yml`) |
| `dynamic_analysis_unsafe` | SUGGESTED | Met | the native code is called through FFM; the tests that reach OpenSSL run against an AddressSanitizer build of it nightly (`sanitizers.yml`) |
| `dynamic_analysis_enable_assertions` | SUGGESTED | Met | Surefire runs the tests with assertions enabled (its default, not switched off) |
| `dynamic_analysis_fixed` | MUST | Met | the fuzz and sanitizer findings were fixed with a regression test ([REVIEWS.md](REVIEWS.md), CHANGELOG.md) |

### What a maintainer should look at before answering

- `crypto_call` is a SHOULD that seclume does not meet by design. The badge still allows
  passing with it unmet and the justification above.
- `vulnerability_report_response` is met because nothing has been reported. A stated response
  time in SECURITY.md (the criterion's own measure is 14 days) would make it a promise.

## Scorecard: the checks below 10

The current scores are in the summary of the latest
[scorecard-report](https://github.com/Seclume/seclume/actions/workflows/scorecard-report.yml)
run. Measured so far: run 43021437797 of 11 November 2026 (Scorecard v5.6.0), on a pull
request - where Scorecard runs the eleven checks that need only the files - **9.2 / 10**.

| Check | Score | Why | What follows |
|---|---:|---|---|
| Fuzzing | 0 | "project is not fuzzed": Scorecard knows OSS-Fuzz, ClusterFuzzLite and some languages' own fuzzers, and not Jazzer started from Maven, which is what `fuzz.yml` runs every night | open - a ClusterFuzzLite configuration around the same targets would be seen |
| License | 9 | "license file detected" - on a pull request Scorecard reads the file only and cannot ask GitHub which licence it is | expected to be 10 on `main`; to be read from the first run there |
| Packaging | not scored | "packaging workflow not detected": no workflow in this repository publishes the releases; they are signed and published outside of it ([SECURITY.md](SECURITY.md#verifying-a-release)) | accepted |
| Binary-Artifacts, Dangerous-Workflow, Dependency-Update-Tool, Pinned-Dependencies, SAST, Security-Policy, Token-Permissions, Vulnerabilities | 10 | | |

Not measured on a pull request, so not known yet: Branch-Protection, CI-Tests,
CII-Best-Practices, Code-Review, Contributors, Maintained, Signed-Releases. They are in the
first `scorecard-report` run on `main`, and this table is completed from it. Two of them can
be told in advance to stay low for reasons that are not defects: Code-Review counts
approvals by a second person, and this project has one maintainer; Maintained and
Contributors count a repository's age and the organisations behind it.
