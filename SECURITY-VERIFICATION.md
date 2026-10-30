# Security verification matrix

Every security property seclume claims, with:
- the attacker it is against ([THREAT-MODEL.md](THREAT-MODEL.md));
- the test that checks it, and how;
- the result, the platforms it holds for, and what the test cannot show.

A claim without a row here is not a claim.

**How the result column is kept honest.** The `Security gate` step of each CI job reads the job's
test reports against [`.github/security-gate.json`](.github/security-gate.json) and gives every
listed test one status:

| Status | Meaning | Lets the build through |
|---|---|---|
| PASS | ran, nothing skipped, nothing failed | yes |
| FAIL | a case failed, or the test did not run at all | **no** |
| SKIPPED | every case was skipped | **no** |
| INCONCLUSIVE | some cases ran, some were skipped | **no** |
| NOT APPLICABLE | the test is not for this platform | yes, and says so |

A skipped security test is never counted as a passed one. Where a test may skip cases on one
platform for a stated reason, the manifest names the platform and the reason, and the job
summary shows both. The result below is the gate's on the default branch, for linux-x64. The
ARM64 and Windows runs of the `core` group are the `security-platforms` job; their first results
are recorded in [TEST-STRATEGY-REPORT.md](TEST-STRATEGY-REPORT.md). A pull request that turns a
PASS into anything else fails before it can merge.

## Secrets in memory

| Security property | Attacker | Test | Methodology | Result | Limitations | Platform |
|---|---|---|---|---|---|---|
| No credential in a heap dump after a login | A1 heap dump | `HeapDumpTest` (tck) with a negative control; `NoCredentialOnTheHeapTest`, `NoKeyOnTheHeapTest` (per module) | a random canary of 24+ bytes is the secret; the JVM dumps its own heap, which is searched in UTF-8, UTF-16 (both orders), Latin-1 and Base64, raw and per object. The control puts the canary on the heap and must be found | PASS (linux-x64) | one moment, one process: a secret the *application* copies to the heap is outside the library | linux-x64 (CI); linux-arm64, windows-x64 (security-platforms) |
| No credential anywhere in the process after a TLS login | A1, A5 | `ProcessMemoryTest` (postgresql job) | every readable mapping of `/proc/<pid>/mem` (~400 MB) searched for the canary, with a control | PASS | Linux only; memory the kernel holds (socket buffers) is not readable this way | linux-x64 |
| A secret scope is zero after close | A1, A5 | `SecretScopeTest`, `AsyncSecretScopeTest` | the arena belongs to the test, so the segment stays readable after `close()` and is read back byte by byte | PASS | shows the wipe of seclume's own memory; copies made by OpenSSL or CNG inside their calls are theirs (both wipe key material they free) | all three |
| Errors leave nothing open or unwiped | A1, A5 | `SecretLifecycleRegressionTest`, `WipeOnFailureTest`, `LoginFailureWipeTest` (MySQL, SQL Server, Oracle), `ConnectFailureWipeTest` (PostgreSQL) | providers that throw, stack overflows, failed logins and refused connections, with the buffers read back afterwards | PASS | a JVM killed with `SIGKILL` wipes nothing; locked pages then go back to the kernel, which zeroes them before reuse | linux-x64 (all); core tests also linux-arm64, windows-x64 |
| Received bytes are wiped once read | A5 | `ReceiveBufferWipeTest` (all four drivers) | a server answer holding a canary passes through the receive buffer, which is read back | PASS | the kernel's socket buffer is outside the process | linux-x64 |
| Secret pages are locked and kept out of core dumps | A5, crash dumps | `MemoryLockPagesTest`, `MemoryLockRegressionTest`, `DumpExclusionTest` | `/proc/self/smaps` flags (`lo`, `dd`) of the very pages, under limits and concurrency; on Windows the registration call's result | PASS | locking fails quietly under a tight `RLIMIT_MEMLOCK` unless `-Dseclume.mlock.required=true`; Windows' exclusion applies to WER reports, not to a debugger's full dump | linux-x64, linux-arm64; windows-x64 with the smaps cases declared |
| No production code puts a secret on the heap | A1 | `ForbiddenApiTest` | every `src/main/java` of every module scanned for `new String(`, `getBytes`, `char[]`, `BigInteger`, readers, JCA `byte[]` APIs; each exception carries a reason (`seclume-allow:`) | PASS | a static rule: it finds the constructs, not every path to the heap. The heap tests above are the dynamic side | all |

## Logs, exceptions, debugging

| Security property | Attacker | Test | Methodology | Result | Limitations | Platform |
|---|---|---|---|---|---|---|
| No exception message carries a secret | A2 logs | `ErrorMessageTest` | every thrown message in production code parsed; concatenations of secret-named variables refused | PASS | static; a message built elsewhere and passed in is not seen | all |
| A failed login's exception and log hold no secret | A2 | `LoginFailureWipeTest`, and the driver and provider tests that search a refused login's messages for the canary | the canary in a refused login; message, cause chain and captured log records searched | PASS | loggers the application adds are its own | linux-x64 |
| The application's secrets are masked in its log lines | A2 | `SecretMaskerTest`, `LogbackRedactionTest`, `LogRedactionTest` | a real Logback configuration; the file written is searched; the masker's heap is dumped and searched for the secret | PASS | only output that goes through the converters; a secret split across log calls is not one match | all |
| Debugging | A5 | - | **not tested.** A debugger attached to the JVM (JDWP) or the process (`ptrace`) can read native memory too | - | out of scope ([THREAT-MODEL.md](THREAT-MODEL.md#out-of-scope)) | - |

## TLS

| Security property | Attacker | Test | Methodology | Result | Limitations | Platform |
|---|---|---|---|---|---|---|
| An untrusted, expired, mismatched or wrongly used certificate is refused | A3 network | `CertificateTrustTest`, `Tls12RefusedCertificateTest`, `LocalTlsTest`, `MutualTlsTest` | certificates made for the test with each defect; the handshake must fail | PASS | validation is the JDK's PKIX; seclume's part is passing the right inputs and refusing on failure | all (core); linux-x64 (live) |
| Host names match as RFC 6125 says | A3 | `HostnameMatchTest`, `HostnameMatchFuzzTest` | wildcards, IDNs, public suffixes, IP addresses; fuzzed boundaries | PASS | - | all |
| No downgrade below the configured version | A3 | `TlsVersionRefusedTest`, the TLS 1.2 sentinel in `ClientHandshake` | servers offering only lower versions, and a TLS 1.2 ServerHello carrying the downgrade sentinel | PASS | TLS 1.2 is allowed where configured; its cipher suites are then the server's choice among those offered | all |
| No connection without an authenticated server | A3, A4 | `ServerHelloFuzzTest`, `EncryptedFlightSampleTest` | a server that holds the handshake key and seals fuzzed flights; none may end in a connection | PASS | coverage-guided search nightly and per PR; a finite search | all |
| The key schedule is the standard's | A3 | `Rfc8448VectorsTest`, `TlsInteropTest`, TLS-Anvil (weekly) | RFC 8448 vectors; handshakes against OpenSSL, GnuTLS, Go, rustls, JSSE; TLS-Anvil's test suite | PASS | interop proves agreement with five stacks, not correctness against an attacker - that is what the vectors and Anvil are for | linux-x64 |
| Primitives computed here are correct | A3 | `WycheproofTest`, `DigestTest`, `AesTest`, `GhashTest`, `Ed25519Test` | Wycheproof suites (AES-GCM, HMAC, HKDF, PBKDF2, ECDH), FIPS and RFC vectors | PASS | correctness, not timing | all |
| Comparisons and AES do not leak through timing | A3, A5 | `ConstantTimeLeakageTest` (nightly) | dudect's method (Welch's t over two input classes) with a negative control that must leak | PASS (nightly) | a measurement on one machine with one JIT, not a proof; C2 gives no constant-time guarantee | linux-x64 |

## Field encryption

| Security property | Attacker | Test | Methodology | Result | Limitations | Platform |
|---|---|---|---|---|---|---|
| The database holds only ciphertext | A8 database | `LocalEncryptedColumnTest` (all four drivers) | values written through `EncryptedColumn` are read back raw from the server and searched for the plaintext; their length is the plaintext's plus 34 | PASS | the length of each value, NULL-ness and, in deterministic columns, equality are visible by design ([ENCRYPTION.md](ENCRYPTION.md#what-it-does-not-hide-and-does-not-do)) | linux-x64 |
| Neither the value nor the key is in a heap dump after a read | A1 heap dump | `LocalEncryptedColumnTest#neitherTheValueNorTheKeyIsInAHeapDump` | a child JVM builds the ring from a key file, reads the value with `readInto`, dumps its heap; searched for the value and for the key in raw and Base64. The control reads it as a `String` and must be found | PASS | `setString`/`getString` are the heap path by name | linux-x64 |
| An altered, copied or foreign value does not decrypt | A8 | `FieldEncryptionTest`, `FieldEncryptionPropertyTest`, `EncryptedValueFuzzTest`, `LocalEncryptedColumnTest` | every flipped bit and cut of a value; values from another column, mode, row context or key; thousands of random cases and coverage-guided fuzzing; a value copied between rows in a real table | PASS | a value replaced by an older value of the *same* row and context decrypts - that needs a context that changes, such as a version column | all three |
| The format is the one documented | - | `FieldEncryptionTest#theFormatIsTheOneAnotherImplementationWrites` | vectors produced by a separate implementation (Python, `cryptography`) are written and read | PASS | - | all three |
| AES-GCM-SIV is RFC 8452 | A3, A8 | `WycheproofTest` (202 vectors), `AesGcmSivTest` | Wycheproof, RFC 8452's own vector; a repeated nonce shown to reveal equality only; every altered byte refused with the output wiped | PASS | built on seclume's AES and GHASH, whose timing `ConstantTimeLeakageTest` measures; the tag check is `ConstantTime.equals` | all three |
| A data key opened by Vault transit reaches native memory only | A1, A4 | `VaultTransitSecretProviderTest`, `LocalVaultTransitFieldKeyTest` (Vault and OpenBao) | a stand-in Vault answering every malformed shape; real Vault and OpenBao with a token that may open one key and no other | PASS | the token's own protection is the token provider's | linux-x64 (Vault); all three (stand-in) |
| A data key opened by a cloud KMS reaches native memory only | A1, A4 | `KmsDecryptSecretProviderTest` | stand-ins for AWS KMS, Cloud KMS and Key Vault: the request, the plaintext decoded off-heap (Base64 and Base64url), every refusal and malformed answer | PASS | no live cloud in CI | all three |
| A `Sealed` JPA attribute is never plaintext on the heap; a `String` one is kept from the database | A1, A8 | `JpaFieldEncryptionCase` (Hibernate, four databases), `ConvertersTest` | a child JVM loads the entity with Hibernate, opens the sealed token into native memory and dumps its heap: the token and the key are not found, the `String` attribute is (control); the server's bytes are searched for every plaintext | PASS | `String` and `byte[]` attributes are on the heap by design | linux-x64 |
| The Spring Boot ring is wiped when the context closes, and a bad configuration leaves nothing | A1 | `FieldEncryptionAutoConfigurationTest` | open `SecretScope`s counted before and after; six misconfigurations refused at start | PASS | - | linux-x64 |

## Hostile input

| Security property | Attacker | Test | Methodology | Result | Limitations | Platform |
|---|---|---|---|---|---|---|
| Every decoder of a server's bytes ends in a value or an `IOException` | A4 hostile server | the fuzz targets ([AUDIT.md](AUDIT.md#fuzzing)) | Jazzer, coverage-guided; a deterministic sample in every build, a minute per target per PR, the corpus nightly | PASS | finite search; a crash input becomes a regression test | linux-x64 |
| A broken heap dump or recording is an `IOException`, not an allocation | A6 hostile files | `BrokenDumpTest`, `RecordingRedactionTest` | seeded mutations of a dump through attribution, redaction and the scanner; a length claiming 2 GB | PASS | the JDK's own JFR parser reads recordings | all |

## Platforms

What the protection is on each platform. "Supported" means the gate runs there in CI.

| | Linux x86_64 | Linux ARM64 | Windows x64 | macOS |
|---|---|---|---|---|
| Secrets off the heap (`SecretScope`) | yes | yes | yes | yes, Java only |
| Locked pages | `mlock` | `mlock` | `VirtualLock` | `mlock` |
| Excluded from crash dumps | `MADV_DONTDUMP` | `MADV_DONTDUMP` | `WerRegisterExcludedMemoryBlock` (WER reports) | **not done** |
| Private keys outside the JVM | OpenSSL 3 | OpenSSL 3 | CNG | **no** - the key operations need OpenSSL 3 on Linux or CNG |
| Gated in CI | `core` job and the database jobs | `security-platforms` | `security-platforms` | **not gated** |

On macOS the libraries load. The Java-only parts work there and pages are locked, but nothing
keeps them out of a crash report. The private-key features need OpenSSL 3 on Linux or CNG, and
are not available there (`PrivateSigningKey.available()` is false); they do not fall back to
the heap. macOS is not gated, and this page claims nothing for it beyond this row.

## What no test here can show

seclume does not protect against:
- **Root, the kernel, a hypervisor.** They read any memory.
- **A compromised OpenSSL, CNG or JDK.** seclume trusts the platform's cryptography and its
  certificate validation.
- **Swap**, where locking failed under the limits and `seclume.mlock.required` was not set.
- **Hardware attacks:** cold boot, DMA, Rowhammer, and speculative execution beyond what the
  timing tests measure.
- **A debugger or Java agent attached to the process.**

Each of these is listed in [THREAT-MODEL.md](THREAT-MODEL.md#out-of-scope). None is a
property this matrix claims.
