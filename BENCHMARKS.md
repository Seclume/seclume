# Benchmarks

Produced by `space.seclume.bench.BenchRecord` from a JMH run, not written by hand.

**Every figure in the README should be traceable to a block in this file.** A measurement without the machine, the JDK, the server and the distance to it beside it is an assertion with a decimal point.

## The run

| | |
|---|---|
| **measured** | 2026-09-24T11:32:05.362553069Z |
| **commit** | v0.9.0-1-gf65be25-dirty |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | none worth recording |
| **server** | MySQL 8.4.11 |
| **round trip** | 292 µs median of 80 round trips |

## Reproducing it

```
taskset -c 2,3 java -Dbench.db=mysql -Dbench.host=127.0.0.1 -Dbench.port=3307 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.password.file=<file> -jar seclume-bench.jar QueryBenchmark InsertBenchmark PoolBenchmark -rf json -rff jmh.json -wi 3 -i 5 -f 2 -w 5s -r 5s
```

## What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `InsertBenchmark.batch [driver=seclume, rows=500]` | avgt | 17.822 | ± 0.282 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [driver=vendor, rows=500]` | avgt | 28.902 | ± 0.211 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [driver=seclume, rows=500]` | avgt | 1.953 | ± 0.035 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [driver=vendor, rows=500]` | avgt | 2.205 | ± 0.939 | ms/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | avgt | 0.518 | ± 0.041 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | avgt | 0.549 | ± 0.015 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | avgt | 0.542 | ± 0.010 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | avgt | 113.314 | ± 7.045 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | avgt | 107.509 | ± 9.805 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | avgt | 108.829 | ± 9.731 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | avgt | 125.543 | ± 10.611 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | avgt | 116.722 | ± 7.164 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | avgt | 124.623 | ± 12.483 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` | avgt | 728.618 | ± 17.770 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` | avgt | 905.595 | ± 5.085 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=seclume, rows=1000]` | avgt | 42.141 | ± 0.462 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=vendor, rows=1000]` | avgt | 41.426 | ± 0.974 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=seclume, rows=1000]` | avgt | 42.186 | ± 0.878 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=vendor, rows=1000]` | avgt | 45.095 | ± 0.672 | us/op | 2 | 3 | 5 |

## The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `InsertBenchmark.batch [driver=seclume, rows=500]` — 17.885, 17.731, 17.628, 17.760, 17.803, 17.690, 17.696, 18.188, 18.110, 17.734 ms/op
- `InsertBenchmark.batch [driver=vendor, rows=500]` — 28.835, 29.024, 28.694, 29.187, 28.742, 28.909, 28.897, 28.931, 28.853, 28.954 ms/op
- `InsertBenchmark.oneRow [driver=seclume, rows=500]` — 1.996, 1.942, 1.954, 1.953, 1.967, 1.945, 1.971, 1.944, 1.951, 1.907 ms/op
- `InsertBenchmark.oneRow [driver=vendor, rows=500]` — 1.924, 1.950, 1.967, 1.958, 1.960, 1.928, 1.920, 1.957, 2.625, 3.864 ms/op
- `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.543, 0.538, 0.542, 0.546, 0.549, 0.498, 0.491, 0.489, 0.495, 0.491 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 0.554, 0.548, 0.566, 0.557, 0.559, 0.542, 0.535, 0.538, 0.545, 0.547 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.536, 0.539, 0.548, 0.554, 0.549, 0.535, 0.533, 0.540, 0.541, 0.540 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 107.947, 114.600, 124.005, 116.974, 109.888, 109.586, 114.697, 110.407, 112.432, 112.603 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 102.233, 103.952, 103.652, 104.378, 104.941, 106.286, 108.836, 124.491, 110.832, 105.484 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 110.033, 106.842, 104.901, 104.080, 125.954, 111.617, 105.449, 106.076, 106.444, 106.895 us/op
- `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 134.250, 125.221, 124.644, 122.319, 118.629, 119.358, 120.381, 119.312, 135.810, 135.508 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 113.729, 114.925, 115.168, 113.472, 113.753, 127.952, 118.135, 113.890, 121.850, 114.344 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 120.899, 130.023, 121.928, 146.483, 121.772, 122.907, 120.402, 119.692, 119.208, 122.918 us/op
- `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` — 740.374, 735.498, 734.254, 750.601, 728.887, 719.879, 719.699, 727.522, 714.648, 714.819 us/op
- `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` — 903.183, 903.160, 900.671, 901.895, 904.474, 908.612, 906.494, 907.958, 910.402, 909.098 us/op
- `QueryBenchmark.selectOne [driver=seclume, rows=1000]` — 41.694, 42.474, 42.687, 42.156, 42.199, 41.997, 42.238, 42.094, 42.170, 41.700 us/op
- `QueryBenchmark.selectOne [driver=vendor, rows=1000]` — 41.100, 41.332, 41.236, 41.140, 41.252, 40.890, 43.200, 41.239, 41.455, 41.420 us/op
- `QueryBenchmark.selectRow [driver=seclume, rows=1000]` — 42.349, 42.697, 42.888, 42.808, 42.801, 41.551, 41.518, 41.690, 41.953, 41.600 us/op
- `QueryBenchmark.selectRow [driver=vendor, rows=1000]` — 45.345, 45.379, 46.136, 44.941, 45.187, 44.594, 44.802, 44.904, 44.763, 44.903 us/op

## What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.

---

## Batches with fair settings (25.09.2026, two runs)

The first run above compared seclume with Connector/J as it comes, and Connector/J sends a
batch row by row unless `rewriteBatchedStatements=true` is set. An outside review pointed that
out. `InsertBenchmark` now measures both ways, with both drivers set the same:
`batching=default` (neither rewrites) and `batching=rewrite` (Connector/J's
`rewriteBatchedStatements`, seclume's `rewriteBatchedInserts`).

**What the two runs say.**
- Without rewriting, seclume is ahead (17.9 against 29.1 ms), because it pipelines the rows.
- With rewriting, the result is **bimodal per JVM fork, for both drivers alike**: a fork runs
  at about 5 ms or at about 12 ms. Connector/J ran at 5.4 ms in one run and at 12 in two
  others; seclume ran at 5 in two forks and at 12.5 in a third. The cause is on the server
  side, not in either driver.
- **With rewriting, neither driver is measurably ahead.**

### The run

| | |
|---|---|
| **measured** | 2026-09-25T20:47:17.501269770Z |
| **commit** | not a git checkout |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | none worth recording |
| **server** | MySQL 8.4.11 |
| **round trip** | 127 µs median of 80 round trips |

### Reproducing it

```
taskset -c 2,3 java -Dbench.db=mysql -Dbench.host=127.0.0.1 -Dbench.port=3307 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.password.file=<file> -jar seclume-bench.jar InsertBenchmark.batch -rf json -rff jmh.json -wi 3 -i 5 -f 2 -w 5s -r 4s
```

### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` | avgt | 17.883 | ± 0.253 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` | avgt | 29.128 | ± 0.397 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` | avgt | 5.938 | ± 3.023 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` | avgt | 11.888 | ± 0.649 | ms/op | 2 | 3 | 5 |

### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` — 18.114, 17.941, 18.130, 17.806, 17.679, 17.874, 17.953, 17.699, 17.676, 17.959 ms/op
- `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` — 29.217, 28.993, 28.892, 29.778, 28.887, 29.176, 29.046, 29.146, 29.221, 28.928 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` — 5.371, 4.909, 4.883, 4.937, 4.875, 5.163, 4.901, 4.901, 9.769, 9.670 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` — 12.242, 11.351, 11.931, 12.049, 11.731, 12.505, 11.214, 11.498, 12.040, 12.317 ms/op

### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.

### The run

| | |
|---|---|
| **measured** | 2026-09-25T20:47:17.922581947Z |
| **commit** | not a git checkout |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | none worth recording |
| **server** | MySQL 8.4.11 |
| **round trip** | 134 µs median of 80 round trips |

### Reproducing it

```
taskset -c 2,3 java -Dbench.db=mysql -Dbench.host=127.0.0.1 -Dbench.port=3307 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.password.file=<file> -jar seclume-bench.jar InsertBenchmark.batch -rf json -rff jmh.json -wi 3 -i 5 -p batching=rewrite -f 3 -w 5s -r 4s
```

### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` | avgt | 7.467 | ± 3.862 | ms/op | 3 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` | avgt | 12.339 | ± 0.700 | ms/op | 3 | 3 | 5 |

### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` — 5.223, 4.901, 5.001, 4.975, 4.971, 5.203, 4.891, 4.947, 4.980, 4.978, 11.841, 12.562, 13.167, 12.080, 12.283 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` — 12.722, 12.642, 12.860, 12.803, 13.104, 11.989, 12.257, 12.553, 12.008, 10.801, 12.767, 11.802, 13.001, 11.288, 12.492 ms/op

### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.
