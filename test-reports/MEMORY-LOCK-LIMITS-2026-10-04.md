# Memory locking under Linux resource limits

Baseline: `5af3163ab4b6adeafa40f1a9045c0c9a836c37f8`.

`MemoryLockOsLimitsTest` starts separate JVMs through `prlimit`; the parent
test runner and host retain their resource limits. Each child verifies its
actual soft/hard memlock limits in `/proc/self/limits` and refuses to run with
CAP_IPC_LOCK, which could bypass those limits. No failure-injection switches
are used. Kernel `VmLck` accounting and mapping `lo`/`dd` flags are checked.

Five Linux cases run in the ordinary core CI suite:

- Zero quota, default warning mode: unsuccessful pins remain properly counted
  until release, dump exclusion still applies, and repeated scope cleanup
  leaves no page or scope references behind.
- Zero quota, required mode: allocation is refused before the provider runs;
  repeated refusal rolls back page counts and dump exclusions.
- One-page quota, both modes: a two-page request overlapping a live protected
  page fails without unlocking that page or making it dumpable. Already pinned
  pages can be referenced again, and released quota can protect a different page.
- Eight-page quota, required mode: 1, 8 and 32 workers share protected pages,
  including a run spread over eight pages. Across 73,000 lock/unlock pairs the
  keeper pages must remain pinned and excluded. Timings and p50/p99 operation
  latency are printed for diagnosis, without a flaky performance threshold.

The local Windows compilation and existing focused regressions passed:
18 reported tests, no failures/errors, two Linux-related skips. The new cases
require the Linux PR CI run; a Windows skip is not operating-system evidence.
No production change is included unless these checks reproduce a defect.

References: [mlock and resource limits](https://www.man7.org/linux/man-pages/man2/mlock.2.html),
[prlimit](https://www.man7.org/linux/man-pages/man1/prlimit.1.html).

```text
./mvnw -B -pl seclume-core -am -Dtest=MemoryLockOsLimitsTest,MemoryLockRegressionTest,MemoryLockPagesTest,SecretScopeTest,ForbiddenApiTest -Dsurefire.failIfNoSpecifiedTests=false test
```

This exercises finite contention and Linux limits, not a long-duration soak
or Windows working-set exhaustion. It does not measure swap or core-file
contents, and diagnostic timings are not a throughput guarantee.
