# TDS reassembly regression and local comparison

Baseline: `6e6eec70f50ac6d5ac4cb0f7e695c23dde01638a`.

The previous reader removed each packet header by shifting all bytes behind
it, including read-ahead from later packets. Streaming consumption shifted
that read-ahead again. Read-ahead used the growing message buffer, so a
connection retaining a large result capacity could repeatedly copy a large
tail for very small packets. Two messages supplied in the same transport read
also lost the second message when the next receive reset the buffer.

The regression first ran against unchanged production code: both read-ahead
budget checks failed (1 MiB requested), and the second-message test failed
with EOF. The initial other 17 invocations passed, including the timing probe.

The reader now keeps packet input in separate native storage, initially
32 KiB and at most 64 KiB for the two-byte packet length. It advances through
complete packets without moving later packets, copies each payload into the
message buffer, and compacts only an incomplete packet before another read.
Consumed packet storage is wiped immediately. Read-ahead survives message
boundaries, and both channel cleanup paths release the added storage.
Streaming still retains incomplete tokens and supports pauses between packets.

## Local comparison

Windows, Java 25, in-memory transport with coalesced one-byte payload packets,
message capacity pre-grown to 1 MiB to represent a previously large result.
Each measurement is the median of five runs after two warm-up runs. Setup and
buffer cleanup are outside the measured interval. These are diagnostic timings,
not database-throughput numbers; JIT warm-up affects the smallest case.

| Mode | Packets | Before (ms) | After (ms) |
| --- | ---: | ---: | ---: |
| Whole message | 8,192 | 5.183 | 2.607 |
| Whole message | 16,384 | 15.135 | 0.296 |
| Whole message | 32,768 | 60.590 | 0.529 |
| Streaming | 8,192 | 9.969 | 0.584 |
| Streaming | 16,384 | 26.540 | 1.167 |
| Streaming | 32,768 | 104.476 | 1.433 |

Run the optional probe with:

```text
./mvnw -B -pl seclume-sqlserver -am -Dtest=TdsReassemblyTest -Dsurefire.failIfNoSpecifiedTests=false -Dseclume.tds.probe=true test
```

CI uses deterministic checks instead of a wall-clock threshold: bounded
read-ahead after retaining a large message buffer, byte-for-byte reconstruction
under fragmented/coalesced reads, maximum packet size, consecutive messages,
streaming pauses, partial-token growth, wiping and closure, truncated input,
and invalid consumer offsets. The final suite has 24 ordinary invocations and
one optional timing probe.

The full local core, TCK and SQL Server run reported 3,283 tests with zero
failures or errors and 19 skips, including the opt-in probe and checks requiring
external services or Linux. Live SQL Server validation is left to PR CI.

The additional receive storage starts at 32 KiB. After growth its active
capacity is 64 KiB; WireBuffer also retains the zeroed original allocation
until close, making the total allocation 96 KiB in that case. This change
does not cap complete result sizes or unfinished tokens;
those remain separate resource-policy questions.
