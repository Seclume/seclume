# Diagnose an installation

```sh
java --enable-native-access=ALL-UNNAMED -jar seclume-verify.jar \
  --doctor --pool-size 20 \
  'jdbc:seclume:postgresql://db:5432/app?user=app&provider=file&path=/run/secrets/db&tls=verify-full'
```

Use the network JDBC URL and JVM options used by the application. The doctor opens
one connection, authenticates through its provider and checks the negotiated TLS
stack, configured certificate verification, certificate validity when exposed,
and database connection headroom. It also allocates a temporary native page to
test memory locking and crash-dump exclusion in **the doctor's own process**.
It does not read application.properties, expand Spring placeholders, inspect an
existing application's pool, or prove that every credential stays off its heap.
Oracle TNS aliases should first be resolved to a network JDBC URL.

`--pool-size` is the application's configured maximum, supplied explicitly. It is
compared with the currently free database connections; the doctor's connection is
included in the server's in-use count. This is a conservative snapshot, not a
reservation. Allow headroom for all replicas. Without the option the pool check
says `NOT CHECKED`; without access to server capacity it says `UNKNOWN`.

The report never prints the JDBC URL, provider values, certificate subject, user,
or underlying exception text. Inline `password`/`pwd` settings are rejected.
It gives corrective settings without changing them or weakening TLS verification.
A JSSE connection is reported as lacking the native-memory TLS guarantee, even
when it successfully negotiated TLS 1.3. A pin is a separately verified public
key, not a substitute for checking who supplied it.

Add `--json` for the existing verify JSON envelope (`ok`, `status`, `sections`,
`problems`). Exit codes for **doctor**: 0 completed without actionable findings,
1 connection failure or actionable findings, 2 invalid invocation/configuration.
`UNKNOWN` and `NOT CHECKED` remain visible even with exit 0; that exit code is not
a security certification. Ordinary verify keeps its existing exit-code contract.

# Heapcheck in CI

```sh
java --enable-native-access=ALL-UNNAMED -jar seclume-heapcheck.jar \
  --dump app.hprof --secret-dir /run/secrets/app \
  --report heapcheck.json --report heapcheck.md --report heapcheck.sarif
python3 seclume-heapcheck/ci/compare.py previous.json heapcheck.json
```

`.sarif` and `.sarif.json` select SARIF 2.1.0. Each leaked credential has one
`SECLUME-HEAP-001` result with a logical location identifying its source file;
heap addresses and duplicate encodings do not create extra alerts. SARIF does not
include credential values, hashes, lengths, heap offsets, or a dump checksum.
It describes a runtime finding, so it does not invent a source-code line.
See the [SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).
The CI action retains SARIF as an artifact; it does not promise source-line
annotations in [GitHub code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

The Python 3 comparison uses the existing JSON format, with no dependencies. It
reports `new`, `persistent`, `resolved`, `not_checked` and `added` source names.
Source names must be stable across runs (prefer the same relative paths).
Changing a source's binary/text kind makes the old check `not_checked`.
Removing a secret from the scan never counts as resolving its leak. The tool
compares presence by source and kind, not credential identity or finding count.
It cannot detect that a credential file's contents changed between runs.

Exit 0 means the current report is clean and all previous sources were checked;
1 means a current leak or incomplete coverage; 2 means invalid/unreadable input.
**A baseline never suppresses a known leak.** Keep baselines from a trusted
previous run. An invalid baseline fails the comparison instead of being ignored.

After checking out this repository, building the heapcheck JAR, and producing a
dump of your application after login or rotation, use the composite action:

```yaml
- uses: ./.github/actions/heapcheck
  with:
    jar: seclume-heapcheck/target/seclume-heapcheck-0.11.0.jar
    dump: app.hprof
    secret-directory: /run/secrets/app
    baseline: previous.json # optional
    artifact-name: heapcheck # change if calling twice in one job
```

The action needs a JDK 25, Bash and Python 3 on the runner. It writes a job summary,
retains only reports for seven days, and fails on leaks, incomplete comparisons or
scanner errors. Reports contain source file names; choose artifact access
accordingly. Neither credential files nor heap dumps are uploaded. Supplied
`--dump` files remain caller-owned: delete them after the step, including failures.
The repository's `heapcheck-action` job tests both a clean process and a leaking
negative control using disposable credentials.
