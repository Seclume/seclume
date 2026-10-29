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

## Credentials nobody named: `--discover`

```sh
java --enable-native-access=ALL-UNNAMED -jar seclume-heapcheck.jar \
  --dump app.hprof --discover --report discover.json --report discover.md
java -jar seclume-heapcheck.jar --list-detectors
```

`--secret-file` answers whether *this* secret is in the heap. `--discover` answers what
*else* is: it goes through every run of printable text in the dump - as single bytes and as
UTF-16 in both byte orders, the way a `String`, a `byte[]` and a `char[]` lie in an HPROF
file - and holds it against 17 credential shapes: private keys in PEM, signed JWTs, AWS,
Vault/OpenBao, GitHub, GitLab, Slack, Stripe, Google, npm and AI-provider keys, Azure Storage
keys and SAS signatures, passwords in URLs and URL parameters, and `Authorization` header
values. It runs alone or together with named secrets.

A report names the detector, numbers the distinct values it found (#1, #2 - meaningless
outside that report), counts how often each occurs and gives the first positions. It never
holds a value, a part of one or a hash. In JSON the result is a `discovery` object with its
own `verdict`; the top-level `verdict` keeps meaning the named secrets, so `compare.py` and
other readers of the existing format are unaffected (`compare.py` compares named secrets only
and needs at least one). SARIF gets one rule per detector (`SECLUME-HEAP-DISCOVER-<ID>`) and
one result per distinct value. Exit code 1 when anything is found, named or discovered.

What it does not do: a credential without a recognisable shape - a plain password, a key
without a prefix - looks like any other string; name it with `--secret-file`. A match has the
shape of a credential and can still be a test key, an expired token or an example a library
carries; templates (`${...}`), masks (`****`) and the word `password` itself are left out.
`--ignore <detector>` leaves a detector out when its findings are understood; an unknown id is
an error, not a filter that filters nothing. It reads about 40 MB of dump a second.

## What holds it

An offset says a credential is in the dump; an audit needs the line of code. So for every
finding in the dump file - named or discovered - heapcheck works out what holds it:

```
FOUND - the secret from /run/secrets/api is in the heap dump, 2 time(s):
  raw file: UTF-8 match of 40 bytes at 81234567 - held by String in com.acme.Config.apiKey
DISCOVERED - a JSON Web Token (signed) (`jwt`, value #1) is in the heap dump, 1 time(s):
  raw file: ASCII match of 612 bytes at 90311002 - held by String in static com.acme.TokenCache.current
```

It finds the `byte[]` or `char[]` the match lies in, then what refers to that array, and where
the array is the value of a `String`, what refers to the `String`: an instance field (named by
the class that declares it, inherited fields included), a static field, or an element of an
object array (`as element of java.lang.Object[]` - a list or a map behind it). Up to three
holders are named per finding. `unreferenced` is garbage the collector had not reclaimed when
the dump was taken - a dump with `live=false` keeps it, and so does an attacker's copy of the
file. `outside any object` is a match in the dump's own bookkeeping or memory no object owns.

Reports carry it as `heldBy` per finding in JSON, a column in Markdown and a sentence in the
SARIF message; only class and field names, never a value. It takes three more passes over the
dump, reading it in windows, so dumps over 2 GB work too; `--no-attribution` leaves it out.
A dump whose structure cannot be read still gets its report, without holders.

## Reports and baselines

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

With `--discover` in either report, a `discovery` object compares by detector - value
numbers are counted per report and mean nothing across two: `new`, `persistent`,
`resolved` and `not_checked` detector ids, and `more_values` for a detector that found more
distinct values than before. A detector left out with `--ignore`, or a run without
`--discover`, makes the old findings `not_checked`, not `resolved`. A report with discovery
and no named secret is a valid scope.

Exit 0 means the current report is clean and all previous sources were checked;
1 means a current leak or incomplete coverage; 2 means invalid/unreadable input.
**A baseline never suppresses a known leak.** Keep baselines from a trusted
previous run. An invalid baseline fails the comparison instead of being ignored.

After checking out this repository, building the heapcheck JAR, and producing a
dump of your application after login or rotation, use the composite action:

```yaml
- uses: ./.github/actions/heapcheck
  with:
    jar: seclume-heapcheck/target/seclume-heapcheck-0.13.1.jar
    dump: app.hprof
    secret-directory: /run/secrets/app   # optional with discover
    discover: 'true'                       # optional: credentials nobody named
    ignore: 'jwt'                          # optional, space-separated detector ids
    baseline: previous.json # optional
    artifact-name: heapcheck # change if calling twice in one job
```

The action needs a JDK 25, Bash and Python 3 on the runner. It writes a job summary,
retains only reports for seven days, and fails on leaks, incomplete comparisons or
scanner errors. Reports contain source file names; choose artifact access
accordingly. Neither credential files nor heap dumps are uploaded. Supplied
`--dump` files remain caller-owned: delete them after the step, including failures.
The repository's `heapcheck-action` job tests both a clean process and a leaking
negative control using disposable credentials, and the same with `discover`: the clean
process must stay clean, a token nobody named must be found, and ignoring its detector
must let it pass.
