# Running the tests

`./mvnw test` works on a bare clone. Everything that needs no database runs; everything that
needs one **skips itself** and says why. A green run on an empty machine therefore proves less
than it looks like it does, and this page is about closing that gap.

Modules build in parallel, one thread per core (`-T 1C` in `.mvn/maven.config`): the four
drivers depend only on the core, so they run side by side, and so do the modules above them.
The full build against all four servers went from 4:43 to 2:32 minutes with the same 2020 tests
and the same results. This is safe because every module talks to its own database or uses
tables no other module touches, the fake servers take ephemeral ports, and the tests that look
at sessions look only at their own. `-T 1` restores the serial build for a run that has to be
read in order.

## What runs without anything installed

The cryptography against the published vectors, the wire protocols against known answers, the
pool mechanics, the heap-dump proof with its negative control, and the rule that no forbidden
API call slips into production code. That is most of the suite.

The published vectors come from two directions. The RFC vectors and the comparisons with the
JDK show that each primitive computes what it should. Project Wycheproof's cases
(`space.seclume.crypto.WycheproofTest`, about 1,800 of them) show that it refuses what it should: a
tag altered by one bit, an HKDF output one byte past its limit, a P-256 peer point that is not
on the curve. They were written by people collecting the bugs other libraries had, which is a
list no one writes about their own code. The files and the commit they come from are in
`seclume-core/src/test/resources/wycheproof`.

## The wipe, and the paths where it gets lost

The heap-dump proof covers a login that works. Wipes are not usually lost there - they are
lost on the way out of a failure, where a method leaves early and the cleanup was attached to
the end. Three classes cover that, none of them needing a server:

- `space.seclume.secret.WipeOnFailureTest` - the shapes, one layer down: a source that dies
  mid-write, one that lies about the length, an exception or an `Error` thrown while the
  credential is in hand, an interrupted thread, a timeout, nested scopes, and a forged
  ciphertext that must leave the caller's segment untouched.
- `space.seclume.postgresql.ConnectFailureWipeTest` - the same against a socket: a rejected
  password, a connection dropped mid-login, a server that stops answering while the client is
  interrupted, and a refused TLS handshake, which must not read the secret at all.
- `space.seclume.mysql.LoginFailureWipeTest` - the second handshake, which shares nothing with
  the first but `SecretScope`, plus an unreachable server that must not cost a secret read.

Two different things are measured, and the difference matters. `SecretScope.open()` says
whether the scope was closed - it is counted rather than read back, because after a real close
the memory is released and reading it would mean reading freed pages. That closing leaves
zeroes is shown separately, in an arena the test owns so the segment stays mapped.

## The vendor drivers as the oracle

`seclume-diff` runs the same values through seclume and through pgjdbc or Connector/J, against
the same server, and reports every disagreement. It is the only module that depends on anybody
else's code, it is never published, and it exists because a hand-written test can only check
what its author thought of — and the author of a driver is the worst person to guess what he
got wrong.

Every value is written by one driver and read by both, in both directions, and through a
`Statement` **and** a `PreparedStatement` — text and binary are different wire protocols
decoded by different code, and a driver can be right in one and wrong in the other. Compared:
`getString`, `getObject`, `wasNull`, the whole `ResultSetMetaData`, and
`DatabaseMetaData.getColumns`, which is what Hibernate and Flyway read before they will run at
all.

All four drivers now have an oracle. The runs have found **nineteen** real defects so far,
none of which any existing test had caught:

| Where | What was wrong |
|---|---|
| PostgreSQL | `getObject` on a `smallint` returned `Short`; JDBC 4.3 table B-3 and every other driver say `Integer` |
| PostgreSQL | `getColumns` computed sizes differently from `ResultSetMetaData` — one driver, two answers about the same column |
| PostgreSQL | `getColumns.TYPE_NAME` returned `character varying(64)`, the declaration, where a type name belongs |
| MySQL | `bigint unsigned` read 18446744073709551615 back as **−1** — the wrong value, no exception |
| MySQL | integer precision counted the minus sign: 11 for `int`, where JDBC means 10 digits |
| MySQL | `getColumns.TYPE_NAME` returned `varbinary(32)` and dropped `UNSIGNED` |
| MySQL | `getString` on a `float` gave `0` through one protocol and `0.0` through the other |
| MySQL | `getColumns.COLUMN_SIZE` was 0 for every date and datetime |
| MySQL | `getString` on a `datetime(6)` whose fraction was zero differed between the two protocols |
| SQL Server | `getPrecision` answered with the wire width — an `int` was 4, a `bigint` 8, on seven types at once |
| SQL Server | `getScale` was 0 for `money` and `datetime`, which have four and three decimal places |
| SQL Server | `getString` on a `varbinary` decoded the bytes as characters and returned mojibake |
| SQL Server | a `uniqueidentifier` came back in lower case |
| SQL Server | `nvarchar` was reported as `Types.VARCHAR` |
| SQL Server | `getColumns` gave no size for a bit, a date or a uniqueidentifier |
| **Oracle** | **every `NVARCHAR2` value came back corrupted** — sent in AL16UTF16, decoded as UTF-8 |
| Oracle | `nvarchar2` was reported as `VARCHAR2` |
| Oracle | `getString` on a `raw` decoded bytes as characters, and `getObject` contradicted `getColumnClassName` |
| Oracle | `getPrecision` was 0 for every date, timestamp and raw |
| Oracle | `getColumnClassName` answered `String` for everything that was not a number |

Three of those are one mistake made four times: **the catalogue and the result set answering
the same question differently**. It appeared in every driver, and in each one the two halves
had been written months apart. Worth remembering when the fifth driver's metadata is written.

The Oracle one is the most serious thing the module has found. `NVARCHAR2` is not exotic — it
is what anyone stores a name in — and the value came back as `\0g\0r…` with no error,
no warning and no test noticing, because every test that touched it had been written against
the same wrong decoder. The column had been carrying its character set since the driver was
written; nothing had ever asked it.

Two findings went the other way and are recorded as such: pgjdbc answers `getString` on a
`bytea` with `[B@3af37506` through a `PreparedStatement`, and ojdbc cannot bind a `Double`
beyond the `NUMBER` range even into a `binary_double`. And on one question the two vendor
oracles disagree with **each other** — `getObject` on a `smallint` is an `Integer` to pgjdbc
and a `Short` to mssql-jdbc — where the specification breaks the tie.

Differences that remain are listed in the tests one at a time, and the two kinds are kept
apart on purpose: `allow(...)` is a place where two drivers may honestly disagree and seclume
has decided, with the reason; `knownDefect(...)` is a place where seclume is wrong and the fix
has not happened yet. Mixing them would turn the list into somewhere bugs go to be forgotten.

### Generated values, not hand-written ones

The same comparison runs over a generated corpus (`*PropertyTest`). E1 asked whether the two
drivers agree about the values somebody thought of; this asks the harder half — whether they
agree about the values nobody did. The distinction earns its keep: the worst fault E1 found was
a `bigint unsigned` at the top of its range, and no hand-written corpus contains
18446744073709551615 because nobody sits down and decides to try it.

Each type gets its **boundaries** first — a random draw almost never lands on `Integer.MIN_VALUE`
— and then draws around them. The text corpus carries a combining mark, a surrogate pair and a
right-to-left mark; the byte corpus carries a leading zero byte and deliberately invalid UTF-8.
`ValuesTest` asserts that all of those are still in there, because a corpus that quietly stops
searching stays green while it stops looking.

Everything comes from one seeded `Random`, and the seed is printed on every run and repeated in
the failure:

```bash
./mvnw -pl seclume-diff test -Dtest=MySqlPropertyTest -Dseclume.diff.seed=438376928460100
./mvnw -pl seclume-diff test -Dtest=PostgresPropertyTest -Dseclume.diff.rows=400
```

The first generated run found a ninth defect, of the same family as two of the eight above: on a
`datetime(6)` whose fractional part happens to be zero, MySQL sends `.000000` in the text
protocol and omits the field entirely in the binary one, so seclume answered
`00:00:00.000000` through a `Statement` and `00:00:00` through a `PreparedStatement` — the same
stored value, two strings. After the fix, three seeds at 400 rows are clean on both databases.

All four drivers have both runs. After the fixes above, three seeds at 400 rows are clean on
every one of them — roughly 19,000 value comparisons per database, through both protocols and
in both write directions.

That the generated run would still catch something was checked rather than assumed: putting the
Oracle character-set fault back turns `OraclePropertyTest` red with **218** findings where the
hand-written corpus produced two. A test suite that has never been shown to fail is a suite
nobody has measured.

## Sessions that break

`FaultInjectionTest` puts a proxy between each driver and its real server and then breaks the
connection part way through a working session. Three modes, one of them the control: relay
unchanged, relay one byte per write, and cut.

The property worth more than the rest is **a truncated stream must never look like a finished
one**. A driver that raises on a broken connection is merely correct; one that hands back the
rows it managed to read, with `next()` answering false as though that were the end, has
silently lost data — and the short answer goes into a report or a ledger and nobody finds out.
So the assertion is two-sided: raising is required, and ending quietly is forbidden.

Byte-at-a-time relaying is the other half. A reassembler that works only because the operating
system usually hands over a whole message at once fails under load, on a slow link, or behind
any proxy — where it gets blamed on the network.

**This test taught its author something before it tested anything.** The first version passed
on all four drivers and proved nothing: the cut landed during `executeQuery`, before a single
row had reached the application, so there was never a partial result to mis-report. It now
insists that rows arrived first, and getting them to arrive turned up the finding below.

### What a fetch size does, and where

`FetchSizeProbe` measures how many bytes cross the wire before the tenth row of a
twenty-thousand-row result, with `setFetchSize(50)` and autocommit off:

| | seclume | pgjdbc |
|---|---|---|
| `PreparedStatement` | 2 990 bytes | 2 957 bytes |
| `Statement` | **1 188 987 bytes** | 2 957 bytes |

seclume streams on a prepared statement and reads the whole result on a plain one. That is
deliberate and `PgStatement` says why: PostgreSQL has a row limit only in the extended
protocol, and a portal only inside a transaction. The reasoning is right about the protocol —
what it leaves out is that pgjdbc reaches the same place by quietly routing a `Statement`
through the extended protocol once a fetch size is set.

It is recorded rather than changed: an application reading a large table with
`createStatement()` and a fetch size gets bounded memory from every vendor driver and the whole
table from this one, and whether to follow them is a decision about plan caching and round
trips, not a bug fix.

## Servers that misbehave

`HandshakeFuzzTest` points each driver at a server that answers with bytes no real one would
send — lengths of 2^31-1 and -1 behind every plausible tag, frames cut off mid-header, and
noise — and then closes the connection, so a lying length is a lie rather than a wait.

It is the handshake that is fuzzed, deliberately. That is the part of each protocol that runs
**before any authentication**, so it is what anything able to answer on the port, or to stand
in the middle of the connection, reaches first with no credential at all. Four protocols
written from scratch means four parsers that had until now only ever met a server that behaved.

Passing is not "it works" — none of this input can work. It is failing the way a library
fails: a `SQLException`, which is what callers catch; promptly, so a bad length cannot hang
anyone; and with no `OutOfMemoryError`, which is what a length taken off the wire and handed
to an allocator produces.

It found one defect. An empty MySQL packet made the greeting parser run off the end of the
buffer and throw `IllegalStateException` — not a type any caller is written to handle, and
about nothing the caller did. `WireBuffer` now throws its own `Truncated` for a message that
stops early, and the MySQL handshake turns that into a `SQLException`. The separate type is
the point: catching `RuntimeException` at a protocol boundary would have hidden *our* bugs
inside "the peer sent nonsense", and our bugs are the ones worth finding. The other three
drivers were already clean.

No database and no password are needed — the drivers never get far enough to want one.

## The corpus: every way a server can be wrong

`HandshakeFuzzTest` above is a handful of hand-written hostile greetings. This is the same
idea taken to its end, and it lives in `seclume-tck`, package `space.seclume.tck.fuzz`.

`ByteCorpus` is given a few *plausible* server answers per protocol — a result set, a refusal,
a login that succeeds — and produces the ways each of them can be wrong: cut at every byte,
every length-shaped field replaced with a spoilt one, every byte replaced in turn with one of
a set chosen for this job (`00 01 5a 80 fb fc fd fe ff` — the four at the end are MySQL's
length-encoded markers, and adding them is what found a real defect that the first, narrower
set did not). Then messages spliced together, repeated, degenerate and pure rubbish.

Two sweeps per driver, and they ask different questions.

| | how it is driven | what is asserted |
|---|---|---|
| **decoders** | a session that `resume()`d a scripted transport | the failure is a `SQLException` a caller can act on, the session is closed if the SQLState says so, and neither the thread nor the heap goes with it |
| **login** | the handshake itself | **`SecretScope.open()` is back where it started** after every single case |

The second is the one that carries the exercise. A refused login is expected and
uninteresting; a scope still open is a password still in the process, on a path nobody wrote
a test for because nobody thought of it.

**How each driver is reached.** PostgreSQL and MySQL talk in the clear until the login is
done, so a script can be the whole server: `ScriptedTransportProvider` registers under the
name `scripted`, a test leaves a script for its thread, and `PgSession.open` connects to it
believing it is a socket. SQL Server and Oracle cannot be reached that way — TDS never
carries a password outside TLS, and Oracle's connect sequence would need most of a server
before the first credential moves — so their sweeps enter one layer lower, at
`Login7`/`LoginResponse` and `TtcFastAuth`/`TtcLogin` over a channel built with `over()`.
What is skipped in front of those calls holds nothing to protect.

**Two sizes, and both are needed.** Every build runs a deterministic sample of about 220
cases per seed set, which costs seconds. The whole corpus — tens of thousands of cases per
driver — runs under `-Pfuzz`, nightly:

```
./mvnw -Pfuzz test                  # the full corpus, no database needed
./mvnw test -Dseclume.fuzz.full=true -Dtest=OracleLoginFuzzTest
```

Three of the defects found so far were green in the sample and red in the full run. The
sample is there so a regression is caught in the build that caused it; the nightly is there
because the sample is not the corpus.

**Every sweep has a control.** A run in which no script ever reached the driver — a wrong
transport name, a seed the reader rejects at its first byte — would "pass" every case by
failing identically, and the report would look the same. So each class also asserts that the
unspoilt seed gets all the way through and does what it says: a login that logs in, a refusal
that comes back as 28000 carrying the server's own words.

No database and no password are needed for any of it.

## The caller in the wrong order

The corpus above asks what happens when the server is wrong. `MisuseContract`
(`seclume-tck`, package `space.seclume.tck.misuse`) asks the other half, and it is the half
that happens in production every day: a column read before `next()`, a `commit()` with no
transaction open, a result set whose statement somebody else closed, a `cancel()` from a
timeout thread that arrives after the query already finished.

Twenty-seven such calls, the same list for all four drivers, each against a **real** server —
which is the point. A scripted server cannot tell whether the stream is still in step; it
answers whatever the script says next either way. So after every case the connection is asked
for a row, and it has to produce one. That is the requirement that matters: a driver which
writes a request it should have refused has put a byte on the wire that the *next* answer
will be read against, and the failure then surfaces three calls later in code that did
nothing wrong.

Three outcomes are allowed, and each case names the one it expects:

| | |
|---|---|
| `REFUSED` | a `SQLException` — not an `IllegalStateException`, not an `ArrayIndexOutOfBoundsException`. The caller's `catch` is written against the JDBC signature |
| `ACCEPTED` | completes. Closing twice, `getMoreResults()` before anything ran — the calls a `finally` block makes, and a driver that throws on them turns a clean shutdown into a stack trace |
| `ACCEPTED_OR_DECLINED` | either, where JDBC lets a driver say `SQLFeatureNotSupportedException`. Declining is an answer; failing some other way is not |

It found six defects on its first run across the four drivers, all of them shared or nearly
so: two drivers threw `IllegalArgumentException` for a parameter index of 0, all four
accepted `executeUpdate` on a `select` and a negative `isValid` timeout, and Oracle allowed
`commit()`, `rollback()` and `setSavepoint()` while auto-commit was on — which PostgreSQL had
refused since the beginning. The last one is the kind of difference that only appears when
the same application is pointed at two of these drivers in turn.

`LocalCancelTest` then asks the question the contract cannot: **does `cancel()` stop
anything.** A driver satisfies "harmless when nothing is running" by doing nothing at all,
and a query timeout is then a promise nobody keeps. So a long statement is started on one
thread, cancelled from another, and three things are checked — that it ends early, that it
ends the way that protocol ends a cancelled statement, and that **the connection still works
afterwards**, which is asked by running `select 42` on it and requiring 42.

One per driver, and the four differ in ways worth knowing:

| | the statement | the outcome |
|---|---|---|
| PostgreSQL | `select pg_sleep(30)` | fails with `57014` |
| MySQL | `select sleep(30)` | **succeeds**, returning 1 instead of 0 — a killed `SLEEP()` is not an error in MySQL, so code written against PostgreSQL's behaviour will silently accept a partial answer here |
| SQL Server | `waitfor delay '00:00:30'` | fails with `HY008` |
| Oracle | a cross join over `ALL_OBJECTS` | fails with `ORA-01013` |

**The Oracle row cost an afternoon and the lesson is about test statements, not protocols.**
The first version used `dbms_session.sleep(30)`, and it never stopped. That looked exactly
like a cancellation that did not work, and the break mechanism was rewritten twice on the
strength of it — first with an in-band MARKER packet, then with TCP urgent data. The urgent
byte was genuinely needed. But `dbms_session.sleep` is **not interruptible**: the break
arrives, the server takes it, and the sleep runs to its end regardless. A CPU-bound query
checks for a break while it runs; a sleeping one does not. A `CONNECT BY` long enough to last
thirty seconds runs out of memory first (ORA-30009), which is why it is a cross join.

`LocalQueryTimeoutTest` is the layer above, one per driver. `setQueryTimeout` used to refuse
every non-zero value — accepting a limit the driver could not enforce would have been a lie —
and now it enforces one. Four questions each: that an overrunning statement is stopped in
about the time asked for rather than in its own; that it arrives as `SQLTimeoutException`
whatever the protocol reported, because a retry is written against the JDBC type and not
against four vendor codes; that **the connection survives its own timeout**, which in a pool
is the difference between a slow query and a lost connection; and that a statement finishing
well inside its limit is left entirely alone, checked by running five of them and then waiting
past the deadline to see whether a leaked timer reaches the next one.

## The rule that is checked in the source

Two tests read the production source of **every** module rather than running anything.
Both exist for the same reason: they pin down a property that is lost by writing one line,
and that every functional test keeps passing while it is lost.

- `ForbiddenApiTest` - no `new String(`, no `char[]`, no JCA, no heap buffer on a path a
  secret takes. Where a construct demonstrably touches no secret, the line carries
  `// seclume-allow: <reason>`, so every exception is visible and justified rather than the
  rule being watered down.
- `NoStatementTextInMessagesTest` - no SQL text in an exception message. `QueryFingerprint`
  was written because the statement text must not be recorded, and the JFR events obeyed that
  from the start; the **exception messages did not**, in twenty-seven places across five
  modules. An exception message is the more certain of the two to be logged.

Both have a control: the rule is shown to be capable of failing. A source check that can only
pass is decoration.

## A conflict made on purpose

`RetryClassificationTest` needs no server: whether a failure is worth retrying is a decision
about exceptions, and the two ways of getting it wrong — too narrow, so a deadlock reaches a
user who did nothing; too wide, so a dead connection is retried on itself — are both decided
there.

`LocalRetryTest` is the other half, and it has the same shape as everything else here: a
**negative control first**. Two transactions read each other's row and write their own under
`serializable`, which is the textbook write skew, and they meet at a barrier between the read
and the write so the conflict is certain rather than likely. Run without the retry, one of
them has to fail with `40001` — if that ever stops happening, every assertion about the retry
becomes meaningless, because the two transactions would no longer be in conflict. Run with
it, both get through, the block has to have run more than twice, and the sum of the two rows
has to be exactly 2: each transaction landed once, not zero times and not twice.

A third case checks the other direction: a duplicate key is run **once** and not three times.

## The TLS client against TLS-Anvil

`.github/workflows/tls-anvil.yml` runs seclume's own TLS 1.3 client against
[TLS-Anvil](https://tls-anvil.com) (Ruhr University Bochum, Paderborn University, Hackmanit;
Apache-2.0). TLS-Anvil plays the server and runs several hundred tests derived from RFC 8446 -
reordered, repeated and malformed messages, wrong extensions and alerts, bad signatures - each
in many combinations, and judges what the client does. It is built from its source at a pinned
commit; `seclume-tls-anvil` is the client it drives, one connection per trigger.

It runs weekly, by hand, and on pull requests that touch `tls/` or `crypto/`, and takes the
better part of an hour. The results are the job summary, a comment on the pull request, and an
artifact. `tls-anvil/expected-results.json`, once committed from a reviewed run
(`summarize.py --write-expected`), is the baseline: a test that passed there and fails later
turns the run red.

The client runs without a trust store, because TLS-Anvil makes its certificates up per test:
what is measured is how the protocol is handled. How certificates are trusted is the JDK's
PKIX and is tested in `CertificateTrustTest` and `HostnameMatchTest`.

## The drivers on our own TLS

`LocalOwnTlsStackTest` (PostgreSQL) and `LocalMyOwnTlsStackTest` (MySQL) run the same login,
the same query and the same certificate refusal over `tlsStack=seclume` instead of the JDK's
`SSLEngine`. Both need the TLS server on the address the properties above name — PostgreSQL on
its TLS port, MySQL on the certificate it generates for itself at first start.

Two details in there are worth knowing before changing them.

**The stack has to be named in what it reports.** Both stacks negotiate TLS 1.3 with the same
cipher suite against the same server, so an assertion on `TLSv1.3` proves encryption and
nothing about who provided it. `SeclumeTls` therefore appends `(seclume)` to its description
and the tests assert on that. Take it away and the tests keep passing while the feature is
gone — which is exactly what happened on the first run: `Settings.at(...)`, which rebuilds the
settings for the chosen host, silently dropped the new component, so every connection fell
back to JSSE and every assertion still held.

**The MySQL login is itself the proof.** Without `allowPublicKeyRetrieval`, `caching_sha2_password`
only sends the password over a channel the server considers encrypted. A test that logs in at
all has already shown more than any assertion in the file.

Oracle is wired the same way and has no test here, because these machines run no TCPS
listener. SQL Server cannot use this stack at all: its handshake lives inside TDS packets and
is TLS 1.2 by construction.

## The client certificate, and what proves it arrives

Three test classes, each answering a different question, and none of them overlapping:

- **`MutualTlsTest`** (core) — does the certificate work? A JSSE server with
  `needClientAuth` builds the transcript itself and verifies our `CertificateVerify`, so a
  signature over the wrong bytes ends as a refused handshake rather than as a test agreeing
  with itself. Two of its cases go through `TlsLayers`, which is the path a driver takes.
- **`ClientIdentitiesTest`** (core) — do two settings build one? And, more to the point, does
  asking twice give back the **same** identity: building a second would load the private key
  into native memory a second time with nobody to release it.
- **`ClientCertificateWiringTest`** (PostgreSQL, MySQL, Oracle) — does it survive the journey?
  URL to settings, settings to the chosen host, settings to the handshake.

That third one needs no key and no certificate file, which is what makes it cheap enough to
have in all three drivers:

- a URL naming `clientCert` without `clientKey-provider` is refused, and the complaint comes
  before anything is read — so the assertion proves the URL reaches the identity builder;
- a stand-in identity that cannot sign is carried through `Settings.at(...)` — the method that
  rebuilds the record for the chosen host, and the one that silently dropped `tlsStack` when
  that was added;
- and `tlsStack=jsse` with an identity is refused **inside the handshake step**, after the
  server has agreed to TLS. A driver that lost the identity earlier would connect happily, so
  the refusal is the proof that it travelled the whole way.

Each of those was checked by breaking it: removing the identity from `at(...)` and from
`startTls` turns two of the four red, which is the only way to know a wiring test is wired.

## The events, and the one assertion that matters in them

Two test classes, and only one of them is about whether the feature works.

`QueryFingerprintTest` has twelve cases, and eleven of them are readability: does the shape
survive, do two executions of one statement group, does `in (?, ?, ?)` collapse. The twelfth
is the point - a marker planted in every literal position of every quoting form of every
dialect, asserted not to come out the other end. The list of forms **is** the test: a quoting
form added to the fingerprinter without being added there is how the property quietly stops
holding.

`JfrEventsTest` records real events against a real PostgreSQL and then walks **every field of
every event** looking for the marker, rather than checking the fields it expects to be
dangerous. The fields somebody adds later are exactly the ones nobody would remember to
check, and that is the case the walk is for.

Both were verified by breaking them: putting the raw SQL into the event, and stopping the
fingerprinter from skipping quoted runs, each turns its own test red with the value printed
in the failure message.

**Why the second one is worth its weight.** A recording is written to a file, kept for weeks
and handed to whoever is debugging. That is a longer life and a wider audience than a heap
dump - so a value reaching a JFR event is worse than one reaching the heap, and the heap is
what this whole library is about.

## Closing out the security goal

Three pieces landed together and each is tested in a different place, which is worth knowing
before looking for them.

**ALPN and TDS 8.0.** `AlpnTest` in the core runs both TLS stacks against a JSSE server that
selects `tds/8.0`, and — the case that matters — against one that selects nothing. A client
that offers a protocol and is answered with silence must refuse, because the alternative
failure is not an error but a **hang**, each side waiting for the other. Both stacks are
checked, because a check on one would pass while the other quietly carried on.

`LocalTds8Test` is the end-to-end half and **skips on the machines here**. Strict encryption
needs a certificate provisioned through `mssql-conf` (`network.tlscert`, `network.tlskey`);
the certificate a container generates for itself serves the nested 7.4 handshake and not this
one. The test asks the server with a plain `SSLSocket` first, so the skip says what is
missing rather than reporting a driver fault. What still runs there: 7.4 is unchanged and
still the default, the option parsing, and that a client certificate reaches the URL layer.

**The AWS session token.** `CanonicalRequestTest` checks the builder against the string
concatenation it replaces — the old way is the oracle, because anything else would be the
class agreeing with itself — and that closing wipes. `CloudVaultProvidersTest` gained two
cases: one with a token, one without. The expected `Authorization` is recomputed
independently and compared, which is the only assertion that can tell "signed" from merely
"sent": a signature over a canonical request one character out is a perfectly well-formed
signature that AWS rejects with nothing useful in the answer.

**The without-a-token case earned its place immediately.** Both cases failed on the first
run, and because the control covers the unchanged path it was clear within a minute that the
test's reconstruction was wrong rather than the provider: `SecretFetch` sends `Host` without
the port, and the signature has to match what goes on the wire.

Each of the three was verified by breaking it — the ALPN extension removed from the
ClientHello, the token left out of the canonical request while still being sent, the quoted
runs no longer skipped — and each turned its own test red.

## TDS 8.0: a second SQL Server, and why

`LocalTds8Test` runs against a **separate container on port 1435**, not the shared fixture,
and the reason is the finding that cost the afternoon:

**SQL Server 2022 on Linux does not accept strict encryption.** Whatever certificate it is
given it refuses a TLS-first connection on 1433 and writes:

```
Error: 17821 - A valid TLS certificate is not configured to accept strict
(TDS 8.0 and above) connections. The connection has been closed.
```

**SQL Server 2025 accepts it immediately**, with the same certificate, the same
configuration and no further coaxing - TLS 1.3, ALPN `tds/8.0`.

That is worth the eight experiments it took, because every one of them looked like a
certificate problem and none of them was. What was tried on 2022, each verified rather than
assumed: a certificate provisioned through `mssql-conf` (loads, strict still refuses); a leaf
certificate rather than the `CA:TRUE` one `openssl req -x509` makes by default; a certificate
whose SAN matches the container's own hostname; a certificate signed by a CA installed in the
container's trust store; the private key as PKCS#8 and as PKCS#1; `network.forceencryption 1`;
the configuration written **before** the first start rather than after; and a fresh container
rather than the running one. All eight: error 17821.

**The measurement that should have come first:** Microsoft's own `mssql-jdbc` with
`encrypt=strict` fails against 2022 identically and works against 2025. Thirty seconds, and
it settles whose problem it is. Two of the eight experiments were also outright mistakes worth
remembering - the key under `/etc/ssl/private`, which is `drwx------ root` and which the
server (uid 10001) cannot traverse, so it shuts down with error 49940; and `network.tlsprotocols`,
which only accepts 1.0, 1.1 and 1.2 because it governs the nested 7.4 handshake and says
nothing about strict.

### Bringing the second server up

```
cd <a directory for this>
# a leaf certificate - CA:FALSE matters, openssl req -x509 does not do it by default
openssl req -x509 -nodes -newkey rsa:2048 -days 730 -keyout mssql.key -out mssql.pem   -subj '/CN=tds8host'   -addext 'basicConstraints=critical,CA:FALSE'   -addext 'subjectAltName=DNS:tds8host,DNS:localhost,IP:<this host>,IP:127.0.0.1'   -addext 'extendedKeyUsage=serverAuth'   -addext 'keyUsage=critical,digitalSignature,keyEncipherment'
mkdir -p certs && mv mssql.pem mssql.key certs/
printf '[network]
tlscert = /certs/mssql.pem
tlskey = /certs/mssql.key
' > certs/mssql.conf
# the server runs as uid 10001 and has to be able to read them
chown -R 10001:10001 certs && chmod 644 certs/mssql.pem certs/mssql.conf && chmod 600 certs/mssql.key

# the same SA password the rest of the suite uses, so one password file serves both
printf 'ACCEPT_EULA=Y
MSSQL_PID=Developer
MSSQL_SA_PASSWORD=%s
' "$(cat .local-mssql-password)" > env
chmod 600 env

# MSSQL_TLS_CERT is not a thing; the configuration has to be in place before sqlservr starts,
# which is what the entrypoint does here
podman run -d --name seclume-mssql8 --hostname tds8host --env-file env   -p 1435:1433 -v "$PWD/certs:/certs:Z,ro"   --entrypoint /bin/bash mcr.microsoft.com/mssql/server:2025-latest   -c 'mkdir -p /var/opt/mssql && cp /certs/mssql.conf /var/opt/mssql/mssql.conf       && exec /opt/mssql/bin/sqlservr'
```

`-Dseclume.mssql8.port=` moves it; without a server the three strict cases skip, and the skip
message names what is missing rather than reporting a driver fault. The test asks with a plain
`SSLSocket` before anything else, so that distinction is never guesswork.

The 7.4 case in that class runs against the same 2025 server, which is deliberate: it shows
the old nesting still works there, so `tds=8.0` is a choice and not a migration.

## Oracle with Native Network Encryption

`LocalOracleNneTest` needs a listener that **requires** Oracle's native encryption and
checksums. `seclume-oracle/proof/nne.sh up` starts Oracle Free 23 on port 1525 and adds
`SQLNET.ENCRYPTION_SERVER` and `SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED` (AES256, SHA256) to
its `sqlnet.ora`. It writes the app user's password to a file on that machine; copy that
file unread to `.local-ora-nne-password`. Point the test at the host with
`-Dseclume.oracle.nne.host=...`. `nne.sh down` removes the container and shreds the files.
One case also uses the ordinary Oracle fixture, to show that `required` encrypts against a
listener at its defaults.

**Oracle Kerberos** has its own fixture, all of it in containers on one network:
`seclume-oracle/proof/kerberos.sh up` starts an MIT KDC, an Oracle Free with
`SQLNET.AUTHENTICATION_SERVICES = (KERBEROS5)` and a keytab, a database user identified
externally as `alice@SECLUME.TEST`, and a client with MIT Kerberos.
`kerberos.sh run <dir with seclume-core.jar and seclume-oracle.jar> [URL options]` runs
`KerberosProof` with a ticket for alice and then without one; `nativeEncryption=required` as
the option adds encryption. `kerberos.sh down` removes everything.

**Oracle NTS** exists only on a database server running Windows, so its fixture is a VM:
`seclume-oracle/proof/nts.sh up <dir with the two jars>` starts a Windows Server 2022 VM
(`dockurr/windows`, needs `/dev/kvm` and about 40 GB of disk - it lives under `/home`, not
`/tmp`) with Oracle Database Free for Windows, installed unattended. Inside, `nts/setup.ps1`
creates the database user for the local Windows user `seclume` and a second Windows user the
database does not know; `nts/proof.ps1` logs in with `NtsProof` as `seclume` - as it comes,
with `nativeEncryption=required` and with `off` - and as the stranger. `nts.sh wait` prints
the result after about 20 minutes, `nts.sh run <dir>` runs it again with new jars, and
`nts.sh down` removes the VM and its disk.

## Oracle over TCPS

`LocalOracleTlsTest` needs a **TCPS listener**, which the ordinary fixture has not got, so it
runs against a second container on port 2484. Oracle is unlike PostgreSQL and MySQL here:
there is nothing to negotiate. A TCPS listener expects the handshake as the first thing on
the socket and never speaks the protocol in the clear; a TCP listener never speaks TLS. So
there is no way to test this without a second listener, and until there was one the Oracle
TLS path was written the same way as the other two and unproven.

**It was unproven and it was broken**, which is the argument for building fixtures rather
than reasoning about them. Two defects, both reachable only over TCPS:

1. The listener answers the first `CONNECT` with **`RESEND`**, and the driver treated that as
   a failure. It is the ordinary course of events there - the listener's own log says
   `establish * FREEPDB1 * 0`, a success - and it means the socket has been handed to a
   server process.
2. That server process brings up **a TLS session of its own**. Resending the packet through
   the old one gets a plaintext fatal alert, because the new peer is waiting for a
   ClientHello and is being sent application data.

The two wrong readings each fail in a way that names itself, and both were tried: resending
without a new handshake gives the alert; opening a fresh TCP connection gives `RESEND` again,
because a new connection starts at the listener. The fix is a second handshake on the same
socket and then the same `CONNECT` again.

A third thing fell out of it. Replacing the TLS layer on a live socket needs a **release that
does not close the transport**: `SSLEngine` never owned the socket, our own `TlsConnection`
does, and `close()` on it took the socket down under the successor's ClientHello. Hence
`TlsLayer.discard()`.

**The measurement that pointed at all of this:** Oracle's own `ojdbc` connects to the same
listener without complaint. One probe, and it says the listener is fine and the driver is not
- the same thirty seconds that settled the SQL Server question in the other direction.

### Bringing the TCPS listener up

The slim image has neither a JRE nor the Oracle PKI libraries, so `orapki` cannot run in it,
and Oracle will not read an OpenSSL wallet - it wants an auto-login `cwallet.sso`, which only
`orapki` writes. The way round is to fetch the PKI jar, which is on Maven Central and is one
file:

```
podman run -d --name seclume-ora-tcps -p 1522:1521 -p 2484:2484   -e ORACLE_PASSWORD="$ADMIN" -e APP_USER=seclume_test -e APP_USER_PASSWORD="$PW"   gvenzl/oracle-free:23-slim
# wait for "DATABASE IS READY TO USE!"

podman exec -u 0 seclume-ora-tcps microdnf install -y java-17-openjdk-headless
curl -sSfLO https://repo1.maven.org/maven2/com/oracle/database/security/oraclepki/23.26.3.0.0/oraclepki-23.26.3.0.0.jar
podman cp oraclepki-23.26.3.0.0.jar seclume-ora-tcps:/tmp/oraclepki.jar

podman exec seclume-ora-tcps bash -c '
  J=/usr/lib/jvm/jre/bin/java; P=/tmp/oraclepki.jar
  C=oracle.security.pki.textui.OraclePKITextUI
  mkdir -p /opt/oracle/wallet
  $J -cp $P $C wallet create -wallet /opt/oracle/wallet -pwd "'"$ADMIN"'" -auto_login
  $J -cp $P $C wallet add -wallet /opt/oracle/wallet -pwd "'"$ADMIN"'"      -dn "CN=oratcps" -keysize 2048 -self_signed -validity 730'
podman exec -u 0 seclume-ora-tcps chown -R oracle:oinstall /opt/oracle/wallet
```

Then `listener.ora` and `sqlnet.ora` in `$ORACLE_HOME/network/admin`:

```
LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = 0.0.0.0)(PORT = 1521)))
    (DESCRIPTION = (ADDRESS = (PROTOCOL = TCPS)(HOST = 0.0.0.0)(PORT = 2484)))
  )
WALLET_LOCATION =
  (SOURCE = (METHOD = FILE)(METHOD_DATA = (DIRECTORY = /opt/oracle/wallet)))
SSL_CLIENT_AUTHENTICATION = FALSE
```

`lsnrctl stop && lsnrctl start`, then `alter system register;` as sysdba so the services show
up. `-Dseclume.oracle.tcps.port=` moves it; without a listener the class skips and says so.

## What needs a server

Every test class whose name begins with `Local`, plus the Spring Data suite. They look for two
things and skip unless both are there:

- **a password file** beside the project, one per database;
- **a server** answering on the address they were told about.

Nothing is read out of those files by the tests. The path goes into the driver's configuration
and the driver fetches the secret straight into native memory — the same path an application
uses, which is the point of the library.

**Redis** (`seclume-redis`, `LocalRedisTest` for Jedis, `LocalLettuceTest` for Lettuce) runs
only when `seclume.redis.host` is set.
`seclume-redis/proof/redis.sh up <address>` starts Redis 8 with an ACL user `orders`, a plain
port (16379) and a TLS 1.3 port (16380) with a certificate from a CA of its own. Copy its
`password` and `ca.pem` unread to `.local-redis-password` and `.local-redis-ca.pem`.

**Kafka** (`seclume-kafka`, `LocalKafkaScramTest`, `LocalKafkaSaslSslTest`) runs only when
`seclume.kafka.host` is set. `seclume-kafka/proof/broker.sh up <address>` starts a single KRaft
broker: SASL_PLAINTEXT on 19092 with SCRAM-SHA-256 and SCRAM-SHA-512, and SASL_SSL on 19093
(TLS 1.3, a certificate from a CA of its own) with SCRAM, PLAIN and OAUTHBEARER. It writes a
random password for the user `orders`, an unsigned token for OAUTHBEARER, and the CA to files on
the broker's machine. Copy them unread to `.local-kafka-password`, `.local-kafka-token` and
`.local-kafka-ca.pem`. `broker.sh down` removes the broker and shreds the files.

Both have a control, run on its own: `-Dseclume.kafka.control=true` and
`-Dseclume.redis.control=true` log in the vendor's way, and the heap search has to find the
password.

## The four databases

Any container runtime will do; `docker` and `podman` take the same arguments here. Choose your
own passwords and write each one into the file named beside it.

```bash
# PostgreSQL
podman run -d --name seclume-pg -p 5432:5432 \
  -e POSTGRES_USER=seclume_test -e POSTGRES_DB=seclume_test \
  -e POSTGRES_PASSWORD="$PW" -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  postgres:18
printf '%s' "$PW" > .local-pg-password

# MySQL — MariaDB works too, and exercises the other authentication plugin
podman run -d --name seclume-mysql -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD="$ROOT" -e MYSQL_DATABASE=seclume_test \
  -e MYSQL_USER=seclume_test -e MYSQL_PASSWORD="$PW" \
  mysql:8.4
printf '%s' "$PW" > .local-mysql-password

# SQL Server
podman run -d --name seclume-mssql -p 1433:1433 \
  -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD="$PW" \
  mcr.microsoft.com/mssql/server:2022-latest
printf '%s' "$PW" > .local-mssql-password
# The XA tests enlist per database, so master will not do:
#   create database seclume_test

# Oracle
podman run -d --name seclume-ora -p 1521:1521 \
  -e ORACLE_PASSWORD="$ADMIN" -e APP_USER=seclume_test -e APP_USER_PASSWORD="$PW" \
  gvenzl/oracle-free:23-slim
printf '%s' "$PW" > .local-oracle-password
```

The Spring Data suite additionally wants a schema per dialect; Flyway creates it on the first
run from `seclume-spring-test/src/main/resources/db/migration`.

## When they are not on this machine

The tests ask `space.seclume.tck.TestHosts` where to look, and it answers from the first of
these that says anything:

| | |
|---|---|
| `-Dseclume.test.host=…` | this run |
| `SECLUME_TEST_HOST` | this shell |
| `.local-test.properties` | this machine |
| otherwise | `localhost` |

PostgreSQL has three of its own, because it is the one that usually runs somewhere other than
the rest: `seclume.pg.host`, `seclume.pg.port` and `seclume.pg.passwordFile` — the last names
*which* file to read, so a second instance can be tested without disturbing the first.

CockroachDB and YugabyteDB are described the same way, each under a key of its own, and each
is only tried when its `host` is set — a machine that has one and not the other simply says
so. The user, the database and the password file all default to
`seclume_test` / `seclume_test` / `.local-<key>-password`.

Nothing matching `.local-*` is checked in:

```properties
seclume.test.host=db.example.invalid
seclume.pg.host=db.example.invalid
seclume.pg.port=5433
seclume.pg.passwordFile=.local-pgtls-password
seclume.crdb.host=db.example.invalid
seclume.crdb.port=26257
seclume.yb.host=db.example.invalid
seclume.yb.port=5433
```

### Bringing those two up

Both have to be started **with authentication**, or the tests prove nothing and say so.

CockroachDB has no unencrypted port, so its certificates are made before the node starts.
The image's entrypoint refuses a listen address that is not loopback — a limitation of that
wrapper script, not of the server — so the binary is called directly:

```
podman volume create crdb-certs
img=cockroachdb/cockroach:v24.1.5
certs="--certs-dir=/certs --ca-key=/certs/ca.key"
podman run --rm -v crdb-certs:/certs:Z $img cert create-ca $certs
podman run --rm -v crdb-certs:/certs:Z $img cert create-node localhost 127.0.0.1 0.0.0.0 <this host> $certs
podman run --rm -v crdb-certs:/certs:Z $img cert create-client root $certs
podman run -d --name seclume-crdb -v crdb-certs:/certs:Z -p 26257:26257   --entrypoint /cockroach/cockroach $img start-single-node   --certs-dir=/certs --listen-addr=0.0.0.0:26257 --store=/tmp/crdb
podman exec seclume-crdb /cockroach/cockroach sql --certs-dir=/certs --host=localhost:26257   -e "create user seclume_test with password '…'; create database seclume_test;
      grant all on database seclume_test to seclume_test;"
```

YugabyteDB needs one flag, and its YSQL listens on the container's own address rather than on
loopback — which is what `hostname -i` is for:

```
podman run -d --name seclume-yb -p 5434:5433 yugabytedb/yugabyte:2024.1.3.0-b105   bin/yugabyted start --daemon=false --ysql_enable_auth=true
ip=$(podman exec seclume-yb hostname -i)
podman exec -e PGPASSWORD=yugabyte seclume-yb bin/ysqlsh -h "$ip" -U yugabyte -d yugabyte   -c "create user seclume_test with password '…'"   -c "create database seclume_test owner seclume_test"
```

## CI

`.github/workflows/ci.yml` runs the same tests against real servers on every push —
PostgreSQL 15 and 18, MySQL 8.4 and MariaDB 11.4, SQL Server 2022, Oracle Free 23ai, and
CockroachDB 24.1 and YugabyteDB 2024.1 for the claim that the PostgreSQL driver serves them
too. Those two demand a password like the rest, and the tests assert which method the server
asked for — SCRAM-SHA-256 over TLS for CockroachDB, md5 for YugabyteDB — so a server that
quietly stopped asking would fail the job rather than pass it.

If a run of yours has no server, it stays green and proves less. That is deliberate: a suite
that fails on a laptop teaches people to ignore it.
