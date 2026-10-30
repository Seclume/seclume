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

## The dumps nobody asked for: `--redact-dir`, `--watch`

`-XX:+HeapDumpOnOutOfMemoryError` writes everything the JVM holds, every secret included, to
`-XX:HeapDumpPath`. There the dump outlives the container, gets copied into a ticket, and is
the most common way a heap dump leaves. These two commands redact such dumps where they lie:

```sh
java -jar seclume-heapcheck.jar --redact-dir /dumps --discover --secret-dir /run/secrets/app
java -jar seclume-heapcheck.jar --watch /dumps --discover --secret-dir /run/secrets/app
```

`--redact-dir` handles every finished dump in the folder once - and every finished Flight
Recorder recording (`.jfr`, see [below](#a-flight-recorder-recording---dump-appjfr)), which
becomes `<name>-<time>.redacted.jfr`. `--watch` keeps watching until it is stopped, for example
as a sidecar sharing the folder with the application:

```yaml
containers:
  - name: app
    env: [{name: JAVA_TOOL_OPTIONS, value: "-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/dumps"}]
    volumeMounts: [{name: dumps, mountPath: /dumps}]
  - name: redact-dumps
    image: eclipse-temurin:25-jre
    command: [java, -jar, /opt/seclume-heapcheck.jar, --watch, /dumps, --discover,
              --secret-dir, /run/secrets/app]
    volumeMounts: [{name: dumps, mountPath: /dumps}, {name: app-secret, mountPath: /run/secrets/app}]
```

How it works:

- **A copy, then the original goes.** Each dump is redacted as `--redact` does it (named
  secrets, the shapes and their echoes, String hashes). The copy goes next to the dump as
  `java_pid1-20261030T001500Z.redacted.hprof`, stamped with the dump's time, so the next dump
  of a process with the same pid finds its name free. Then the original is deleted.
- **Only finished dumps.** A dump counts as finished when it ends with the `HEAP DUMP END`
  record HotSpot writes last, a recording when every chunk in it is marked finished and the
  last one ends where the file does. `--watch` also waits until the size has not changed
  between two looks (`--interval`, 10s).
- **Partial copies.** Copies left by a redaction that died are removed after an hour.
- **When a dump cannot be made clean.** It stays, and the failure is reported once, not on
  every look. `--delete-unredactable` deletes it instead, which loses the dump but not the
  secrets. `--redact-dir` exits 2 if any dump failed.

**In the application itself.** The Spring Boot starter does the same in the application's own
JVM. It watches wherever the JVM writes its dumps, if it writes any:

- `HeapDumpPath`, or the working directory when that is not set;
- `seclume.heapdump.oom.folder` names another folder;
- `seclume.heapdump.oom.interval` sets how often it looks (default 30s);
- `seclume.heapdump.oom.redact=false` turns it off.

A dump from before a restart is redacted once the application is up again. A JVM that exits on
the error (`-XX:+ExitOnOutOfMemoryError`) leaves the dump to that next start. The starter looks for
the shapes and for the application's own secrets, each data source's password and
`seclume.heapdump.secrets.*`, without a copy of them on the heap (see
[OBSERVABILITY.md](OBSERVABILITY.md#actuatorheapdump-a-redacted-copy-never-the-heap-itself)).

## Inside a Kubernetes pod: `kubectl seclume heapcheck`

```sh
cp seclume-heapcheck/kubectl/kubectl-seclume seclume-heapcheck.jar ~/bin/   # any directory on PATH
kubectl seclume heapcheck orders-7d9f -n shop --secret-dir /run/secrets/db --format json > report.json
kubectl seclume heapcheck orders-7d9f -n shop --discover
```

Copying a heap dump out of a pod to check it would be the leak the check looks for. So the
check goes to the dump instead. An ephemeral container (`kubectl debug --target`) joins the
application container's process namespace, and seclume-heapcheck runs in it with `--in-target`:

- **Finding the JVM.** It is the `java` process of the application's container. Pass
  `--pid` if there is more than one.
- **The dump.** The JVM writes it into its own file system (`--dump-dir`, default `/tmp`).
  The check reads it through `/proc/<pid>/root` and deletes it there.
- **Secrets.** `--secret-dir` and `--secret-file` are paths in the application's container.
  They are read there, inside the pod.
- **What comes out.** The report goes to stdout (Markdown, JSON or SARIF), the check's own
  lines go to stderr, and the exit code is the check's.
- **Same reports as before.** Secrets are named by their paths as given, so reports compare
  across runs with `compare.py` as before.

**A dump that has to leave the pod.** For a memory leak or a vendor's support case, `redact`
makes the dump the same way and redacts it inside the pod with `--redact`. Only the redacted
copy comes out:

```sh
kubectl seclume redact orders-7d9f -n shop -o orders.hprof --secret-dir /run/secrets/db --discover
```

- **What goes.** The named secrets and the shapes discovery knows, with their echoes, are
  overwritten. The copy is searched again inside the pod.
- **When it comes out.** Only when that search comes back clean. Otherwise the command exits
  2 and nothing is copied.
- **On your side.** The copy is owner-only, and an existing file is never overwritten.
- **The original.** The dump itself is deleted where the JVM wrote it.

Requirements:

- **Kubernetes.** Ephemeral containers (1.25+) and `kubectl debug --profile=general`, which
  gives the debug container `SYS_PTRACE`. Reading another user's `/proc/<pid>/root` needs it.
- **The debug image.** A JDK 25 with `jdk.attach` and `tar`. The default is
  `eclipse-temurin:25-jdk`; choose another with `--image` or `SECLUME_HEAPCHECK_IMAGE`.
  `kubectl cp` puts the JAR into the debug container, so no image of seclume's own is needed.
- **The application's JVM.** Any HotSpot JVM. The attach mechanism accepts a root caller from
  another container.

Each run leaves an exited ephemeral container in the pod's status, because Kubernetes does
not remove them. A namespace whose policy forbids ephemeral containers or `SYS_PTRACE`
(Pod Security `restricted`) forbids this too. Use `--dump` on a dump the JVM writes itself
(`-XX:+HeapDumpOnOutOfMemoryError`), or `--redact` before it leaves the pod.

The CI job `kubectl-heapcheck` runs this against a kind cluster with three pods: a JVM as an
unprivileged user with the credential from a mounted secret, one without it, and one with a
token for `--discover`. The leak must be found, the clean pod must pass, the token must be
discovered. `redact` copies of the leaking and the token pod must pass a check with the
credential itself, and a second `redact` to the same file must be refused. Afterwards no
`.hprof` file may be left in any pod and no report may hold the credential.

## A dump to hand on: `--redact`

```sh
java --enable-native-access=ALL-UNNAMED -jar seclume-heapcheck.jar \
  --dump app.hprof --secret-dir /run/secrets/app --discover --redact app-redacted.hprof
```

A heap dump is needed - for a memory leak, for a vendor's support ticket - and it carries
every credential the process held. `--redact` writes a copy with each of them overwritten:

- **What goes:** every occurrence of each named secret, in every encoding it can lie in
  (UTF-8, UTF-16 in both byte orders, Base64; a binary secret as its bytes and as Base64),
  and with `--discover` the value of every credential of a known shape - the password of a
  URL rather than the URL, all of a PEM block.
- **Echoes too:** what discovery found is then looked for where it has no shape - the URL's
  password in a configuration field of its own, a JWT's payload a library split off, a key's
  line, a token's body without `ghp_` or `xoxb-`. A whole value of at least 8 characters,
  a part of at least 16: anything shorter would match by chance in the dump's own records.
- **How:** with `*` in the occurrence's own encoding (`00 2A` in a `char[]`), or zero bytes
  for a binary secret. Nothing moves: a `String` keeps its length, the dump stays a dump that
  analysers open. The `hash` field of every `String` whose text went is cleared as well - a
  32-bit hash of a password confirms a guess.
- **Checked:** the copy is searched again the same way before it gets its name. If anything is
  still found, it is deleted and the run fails with exit 2 - a half-redacted dump is worse than
  none, because it is trusted. The copy is readable by its owner only, written next to its
  destination and renamed into place; an existing file is never overwritten.

Exit 0 means the copy is written and checked, whatever the original held - the reports, if
asked for, still describe the original. What it does not reach: a credential named by nobody
and of no known shape, one split across objects, compressed or encrypted. The check proves
that what was looked for is gone, not that nothing else is there; name what you know.

The redaction itself is in `seclume-heapdump`, a library without dependencies
(`space.seclume.heapdump.Redactor`), together with the discovery and the object attribution.

## Log lines: the application's secrets masked before they are written

A password that reaches a log line is on the heap already; what is left to stop is the line
reaching a file, a collector, a support ticket. `seclume-logging` looks for the application's
own secrets in every message and stack trace and writes `[redacted:<label>]` instead:

```xml
<!-- logback-spring.xml -->
<conversionRule conversionWord="msg"
                class="space.seclume.logging.logback.RedactingMessageConverter"/>
<conversionRule conversionWord="xEx"
                class="space.seclume.logging.logback.RedactingThrowableConverter"/>
```

(`class` is the attribute's name since Logback 1.5; older versions call it `converterClass`.)

```properties
seclume.logging.redact=true                   # with seclume-logging on the class path
seclume.heapdump.secrets.api.provider=file    # a secret of the application's own, besides
seclume.heapdump.secrets.api.path=/run/secrets/api-key   # every data source's password
seclume.logging.refresh-interval=5m           # read again, so a rotated one is looked for
```

**To look for a secret, the masker does not keep it.** A filter configured with the password
holds the password - a `String` on the heap for as long as the application runs. Here each
secret is read once into locked native memory and kept as two numbers: a rolling fingerprint
of its characters and an HMAC-SHA-256 tag, both keyed with 32 random bytes that never leave
locked native memory. A heap dump of the process holds neither the secret nor a hash anybody
could guess against; the tests prove the first with a heap dump. A log line is scanned with the
fingerprint over every window as long as a secret, and a window that matches is confirmed by
its tag.

- **What is found:** the secret itself and its Base64, anywhere in the message or in an
  exception's message and stack trace. Secrets shorter than six characters are not looked for:
  they would mask ordinary words.
- **Which secrets:** every data source's password and `seclume.heapdump.secrets.<label>.*` -
  the same the heap dump redaction looks for. Read again once every bean is made, and then every
  `seclume.logging.refresh-interval`.
- **Other loggers:** `SecretMasker.maskInstalled(text)` is the whole of it - a Log4j2 rewrite
  policy or a JUL formatter can call it; `new SecretMasker(providers)` works without Spring.

## A Flight Recorder recording: `--dump app.jfr`

```sh
java -jar seclume-heapcheck.jar --dump app.jfr                       # what it holds
java -jar seclume-heapcheck.jar --dump app.jfr --discover --redact app-redacted.jfr
```

A recording goes to a vendor's support as readily as a heap dump, is opened in more tools,
and is just as full of credentials. Every recording starts with the process's environment
(`jdk.InitialEnvironmentVariable`), its system properties (`jdk.InitialSystemProperty`) and
its command line (`jdk.JVMInformation`), so `DB_PASSWORD=...` and
`-Dspring.datasource.password=...` are in each one, and any event may have recorded a string
holding a token.

`--dump` and `--redact` take a `.jfr` as they take an `.hprof` - the file's first bytes decide,
not its name - and a recording needs no secret named:

- **The recording names its own.** A value whose name says secret - `password`, `passwd`,
  `pwd`, `passphrase`, `secret`, `token`, `credential`, `authorization`, `bearer`, an API,
  access, private, client, signing, encryption or master key - is looked for as a named
  secret. That covers the environment, the system properties and `-Dname=value`/`--name=value`
  arguments; the check reports it as `environment variable DB_PASSWORD (in the recording)`,
  never with its value. A name that says where a secret is (`..._FILE`, `..._PATH`, `..._DIR`,
  `..._URL`, `..._NAME`, ...) is not one, nor are `PWD` and `OLDPWD`; a value that is
  shorter than 4 characters, a number, `true`, `false`, `none` or masked already is not taken.
- **Everything else as in a dump.** Named secrets and `--discover` find what an event recorded
  - a token in an exception's message, a password in a JDBC URL - anywhere in the file.
- **In place.** Each occurrence becomes `*` of the same length, so every chunk keeps its size
  and every offset stays right. There are no `String` hashes and no holders in a recording;
  attribution is skipped.
- **Read back.** Before the copy gets its name it is searched again, its chunks are walked to
  the end and every event is parsed by the JDK's own `jdk.jfr.consumer.RecordingFile`. A copy
  that does not read is deleted and the run exits 2.

The masked settings are still there, by name: `jfr print --events jdk.InitialEnvironmentVariable
app-redacted.jfr` shows the event with `key = "DB_PASSWORD"` and `value = "************"`. `--redact-dir` and `--watch` take the
recordings in their folder the same way, so the sidecar above also covers
`-XX:StartFlightRecording:dumponexit=true,filename=/dumps/`.

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
