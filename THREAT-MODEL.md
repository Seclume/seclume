# Threat model

What seclume defends against, how, and where the proof of each defence is.
What it does not defend against is listed with the same care at the end: a
reader deciding whether to rely on it needs both. The audit guide
([AUDIT.md](AUDIT.md)) turns this into a scope for a review.

## What is protected

| Asset | Examples | Where it lives in seclume |
|---|---|---|
| **Credentials** | database passwords, API keys and tokens, Vault tokens, cloud keys, SASL secrets | locked native memory (`SecretScope`), read there by a secret provider; never a `String`, `char[]` or `byte[]` |
| **Private keys** | TLS client and server keys, SSH keys, JWT signing keys, SPIFFE SVID keys | OpenSSL 3 or Windows CNG, imported from native memory; a key in a KMS never leaves it |
| **Derived secrets** | SCRAM salted passwords, TLS traffic keys, session keys of Oracle's O5LOGON | native memory of the operation, zeroed when it ends |
| **Data in transit** | queries and results, secret manager answers | seclume's own TLS 1.3 (and 1.2 where a server needs it), or the platform's |

## Who attacks, and what seclume does about it

### A1 - Somebody with a heap dump

The commonest leak: `-XX:+HeapDumpOnOutOfMemoryError`, `/actuator/heapdump`, a dump
attached to a support ticket, a profiler snapshot.

- **Defence:** no secret is ever on the Java heap, so no heap dump has one. The rule is enforced
  by `ForbiddenApiTest` over every module's production source. `new String(`, `getBytes`,
  `char[]`, `BigInteger`, readers and JCA `byte[]` APIs need a marked reason.
- **Proof:** `HeapDumpTest` and `NoCredentialOnTheHeapTest` dump the heap after real logins and
  search it in every encoding, each with a negative control that must find the secret.
  `ProcessMemoryTest` searches all of the process's readable memory on Linux.
- **For other people's code:** `seclume-heapcheck` proves the same for any JVM. `--redact`,
  `--watch`, the starter's folder watch and the admission webhook overwrite what a dump or a
  Flight Recorder recording holds before it leaves.
- **Residual:** secrets the *application* puts on the heap (a password it builds into a URL, a
  token in a log line) are outside the library. heapcheck finds them, the redaction removes
  what it knows, and `seclume-logging` masks log lines.

### A2 - Somebody who reads logs, metrics or traces

- **Defence:**
  - Error messages never carry a secret. `ErrorMessageTest` checks that no message concatenates
    a secret-named variable.
  - JFR events and metrics name things, never values.
  - `seclume-logging` masks the application's own secrets in Logback output. The masker holds
    keyed fingerprints and HMAC tags, never the secret.
- **Residual:** a logger that formats a secret before seclume sees it, or one that is not wired
  to the masker.

### A3 - A network attacker

The attacker sits between the application and its database, secret manager, KMS or broker.

- **Defence:**
  - seclume's TLS 1.3 client validates the certificate chain with the JDK's `X509TrustManager`
    (PKIX) or a pinned key (`tlsPin`), and matches host names itself (`HostnameMatch`, public suffix aware).
  - Extensions are checked strictly (`StrictExtensions`).
  - A downgrade to TLS 1.2 happens only where configured, with the RFC 8446 downgrade sentinel
    checked.
  - SCRAM uses channel binding (`tls-server-end-point`) where the server offers it, so a proxy
    that terminates TLS cannot relay the login.
  - X25519MLKEM768 is offered where the platform has ML-KEM.
- **Proof:**
  - RFC 8448 vectors.
  - Interop against OpenSSL, GnuTLS, Go, rustls and JSSE (`TlsInteropTest`).
  - TLS-Anvil weekly.
  - `ServerHelloFuzzTest`, plus `EncryptedFlight`: no fuzzed flight may produce a connection to a
    server nobody authenticated.
- **Residual:** a CA the deployment trusts that issues a certificate for the server's name, and
  opt-outs a deployment chooses (`trustServerCertificate=true`, `sslmode=require`) - which some
  integrations refuse unless a `tlsPin` names the key.

### A4 - A hostile or compromised server

The attacker controls a database, a secret manager, a KMS, a SPIFFE agent or a broker that
answers seclume.

- **Defence:**
  - Every decoder of an answer treats it as hostile: lengths are bounded by what has arrived, and
    nothing is allocated off a length taken from the wire.
  - A broken answer ends in an `IOException`.
  - A KMS's public key is checked with a signature before the key is used.
  - A SPIFFE SVID's key must match its certificate.
  - A secret manager's answer is read in place (`SecretFetch`, `JsonOff`) and only the requested
    value is copied, into native memory.
- **Proof:** a fuzz target for every decoder ([AUDIT.md](AUDIT.md#fuzzing)). The ordinary build
  replays a deterministic sample, the nightly job runs the corpus in full, and CI runs short
  coverage-guided searches.
- **Residual:** a server that is entitled to the secret receives it. seclume cannot stop the real
  database from misusing the password it was sent.

### A5 - Another unprivileged process on the same host

- **Defence:**
  - Secret pages are locked (`mlock`/`VirtualLock`) so they do not go to swap.
  - Those pages are marked `MADV_DONTDUMP` so they stay out of core dumps.
  - Secrets are zeroed when their scope closes.
  - heapcheck never takes a secret on its command line, where every process could read it.
- **Residual:** same-user processes with `ptrace` or `/proc/<pid>/mem` access can read native
  memory as well as the heap. That is the operating system's boundary, not seclume's.

### A6 - Hostile files handed to the tools

Heap dumps from a support case, Flight Recorder recordings, key files, configuration.

- **Defence:** the HPROF readers (attribution, redaction, heapcheck's scanner), the key file
  readers and the recording reader end a broken file in an `IOException`. A redacted copy is
  checked again and read back before it gets its name. A copy that is not clean is deleted, and
  an existing file is never overwritten.
- **Proof:** `BrokenDumpTest`, `KeyFilesFuzzTest`, `RecordingRedactionTest`.

### A7 - The supply chain

- **Defence:**
  - The runtime dependency is the JDK alone. Integrations bring their client library as
    `provided`.
  - Releases and tags are signed (SECURITY.md) and carry a CycloneDX SBOM per module.
  - CI runs CodeQL, Semgrep, Trivy and OpenSSF Scorecard.
  - Actions and the webhook's base image are pinned by digest.

## Out of scope

- **Root, the kernel, the hypervisor, physical access.** Anyone who can read any process's
  memory can read seclume's.
- **Code running inside the JVM:** a Java agent, a deserialization gadget, a malicious
  dependency. It can call into native memory as seclume does. seclume narrows what such code
  finds lying around, but it is not a sandbox.
- **Micro-architectural side channels beyond what is measured.** Comparisons, AES and the GCM tag
  check are measured with dudect's method (`ConstantTimeLeakageTest`). The JIT is not a
  constant-time compiler, so these are measurements, not proofs.
- **The JDK and the platform libraries themselves:** PKIX validation, OpenSSL, CNG.
- **What the application does with a secret** after it asks seclume for it on purpose (an
  `ExpiringCredentials` value it copies, a token it logs).
