# JSON reader fuzzing

Baseline: `8fdf1573e380cd2dd9520baa7536102b3670cdca`.

`JsonOffFuzzTest` adds two Jazzer targets using synthetic data only:

- `arbitraryDocumentsStayWithinBounds`: arbitrary documents, truncated input
  slices, three lookup paths, zero/small/exact output buffers and invalid
  declared lengths. Only `JsonOff.NotFound` is accepted as a reader failure;
  unexpected exceptions and errors remain findings. Output guard bytes and
  unchanged input are checked.
- `generatedValuesRoundTrip`: test-generated valid documents with nested
  fields and distracting values. Decoded UTF-8 bytes must equal the JDK's
  independently encoded expected value, integers must equal the original
  generated long, and short output buffers must be refused. Raw supplementary
  characters and BMP escapes exercise the reader's supported string forms.

Twenty checked-in seed files cover Unicode, escapes, malformed input, numeric
boundaries, nesting at and past the limit, and generated-value edge cases.
Normal builds replay these seeds and Jazzer's empty input for each target.
The PR CI searches for 60 seconds per target on Linux; the nightly workflow
searches for 15 minutes each. Crash inputs are uploaded on failure.

## Reproduced contract failure

The initial empty-input fuzz invocation exposed `has` accepting a negative
document length with an empty path. Three separate regression cases failed on
the baseline: negative lengths were inconsistently accepted and lengths beyond
the supplied segment could escape as `IndexOutOfBoundsException`. Cursor
construction now checks the supplied length before any lookup. This is a
buffer-contract fix; no remotely exploitable provider path was established.

The focused local run passed 72 tests without skips, including 22 seed/empty
fuzz invocations, existing JSON tests, the three new bounds regressions and
ForbiddenApiTest. The full local core run passed with 3,186 tests, zero
failures/errors and 10 environment-dependent skips. Windows verification
replays inputs; the coverage-guided
search itself runs in Linux CI.

```text
./mvnw -B -pl seclume-core -am -Dtest=JsonOffTest,JsonOffRegressionTest,JsonOffFuzzTest,ForbiddenApiTest -Dsurefire.failIfNoSpecifiedTests=false test
JAZZER_FUZZ=1 ./mvnw -B -pl seclume-core -am '-Dtest=JsonOffFuzzTest#arbitraryDocumentsStayWithinBounds' -Djazzer.max_duration=60s -Dsurefire.failIfNoSpecifiedTests=false test
JAZZER_FUZZ=1 ./mvnw -B -pl seclume-core -am '-Dtest=JsonOffFuzzTest#generatedValuesRoundTrip' -Djazzer.max_duration=60s -Dsurefire.failIfNoSpecifiedTests=false test
```

The fuzz contract follows a field reader that may stop once the requested
value is found. It does not assert full-document validation or add support for
escaped field names or surrogate escapes. Partial output on refusal remains
the caller's cleanup responsibility. Inputs are bounded at 8 KiB for the fuzz
targets, not for production. A short successful search is not proof that no
further defects exist.
