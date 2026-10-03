# WireBuffer bounds regression checks

Baseline: `af23c0f0a357ce32d456c5e9b4b3df81fc44d7bd`.

The new `WireBufferBoundsTest` reproduced 20 failing cases before the fix
(32 test invocations in total). These are buffer API contract failures;
this check does not establish a remotely exploitable path through a driver.

Negative padding and integer widths could move the cursor backwards. Invalid
positions and capacities were accepted. Oversized writes reached native-memory
bounds exceptions after integer arithmetic, and invalid copy sources could
cause destination growth before rejection. An out-of-bounds integer patch
could write part of its value before failing. `readCString` accepted missing
terminators and advanced past the message.

Writes now validate lengths before addition or narrowing, source ranges before
growth, and integer widths and patch ranges before writing. Growth arithmetic
uses `long` and is bounded by the existing int-indexed capacity. Cursor setters
validate capacity, and C-string reads require the terminator before allocating
or advancing. Refusals use the existing `WireBuffer.Truncated` type handled by
the protocol boundaries.

All 32 new checks pass, including valid zero-to-eight-byte integer widths,
growth at the capacity boundary, content preservation, wiping the old segment,
and a terminated string ending exactly at capacity. Together with text encoding
and forbidden-API checks, the focused run passed 52 tests without skips.

The broader local run covered core, TCK, PostgreSQL, MySQL, SQL Server and Oracle:
3,608 tests, zero failures or errors, 69 skipped. It includes decoder regression
and saved fuzz inputs; it is not a new coverage-guided fuzzing campaign. Live
database and Linux-specific evidence must come from CI. The boundary tests use
small buffers; allocations close to the 2 GiB representation limit were not
attempted. No new application message-size limit is introduced.
