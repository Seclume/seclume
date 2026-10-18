# Benchmarks

Produced by `space.seclume.bench.BenchRecord` from a JMH run, not written by hand.

**Every figure in the README should be traceable to a block in this file.** A measurement without the machine, the JDK, the server and the distance to it beside it is an assertion with a decimal point.

## All four databases (13.10.2026)

One run per database, one after the other, on the same host as the run below: 4 cores, the
benchmark pinned to two of them (`taskset -c 2,3`), the server in a container on the same
machine, TLS on every connection. Built from the working tree after 0.11.0, so the records say
"not a git checkout". Each cell is **seclume / the other side**, and the bracket is seclume's
time against it: **−12 %** means seclume needed 12 % less time. "even" means the two error
bars overlap - the difference is not shown by this run.

The other side is the vendor driver (pgJDBC, Connector/J, mssql-jdbc, ojdbc) for the driver
rows and HikariCP over the vendor driver for the pool rows.

| | PostgreSQL | MySQL | SQL Server | Oracle |
|---|---|---|---|---|
| `select 1` | 46 µs / 53 µs (**−12 %**) | 41 µs / 49 µs (**−15 %**) | 86 µs / 92 µs (even) | 37 µs / 61 µs (**−39 %**) |
| one row | 42 µs / 42 µs (even) | 42 µs / 52 µs (**−21 %**) | 92 µs / 93 µs (even) | 40 µs / 40 µs (even) |
| 1000 rows | 728 µs / 696 µs (even) | 708 µs / 950 µs (**−25 %**) | 10.5 ms / 10.3 ms (even) | 932 µs / 1.2 ms (**−20 %**) |
| insert one row | 0.67 ms / 0.67 ms (even) | 6.14 ms / 7.14 ms (even) | 1.58 ms / 1.58 ms (even) | 2.17 ms / 2.27 ms (even) |
| batch of 500, as they come | 2.99 ms / 3.04 ms (even) | 17.96 ms / 32.89 ms (**−45 %**) | 9.24 ms / 9.44 ms (even) | 1.43 ms / 1.57 ms (even) |
| batch of 500, both rewriting | 1.53 ms / 1.51 ms (even) | 5.04 ms / 7.13 ms (even) | 9.37 ms / 9.35 ms (even) | 1.43 ms / 3.80 ms (even) |
| pool: borrow and return | 0.42 µs / 0.66 µs (**−36 %**) | 0.44 µs / 0.53 µs (**−17 %**) | 0.46 µs / 0.60 µs (**−24 %**) | 0.44 µs / 0.51 µs (**−15 %**) |
| pool: borrow, prepared query, return - no reset | 108 µs / 110 µs (even) | 128 µs / 139 µs (even) | 300 µs / 309 µs (even) | 105 µs / 169 µs (**−38 %**) |
| pool: borrow, prepared query, return - seclume resets the session | 263 µs / 110 µs (+138 %) | 272 µs / 139 µs (+95 %) | 325 µs / 309 µs (even) | 17.4 ms / 169 µs (103× the time) |
| the same, 4 threads with 2 ms between requests | 166 µs / 113 µs (+47 %) | 159 µs / 122 µs (+30 %) | 234 µs / 220 µs (+6 %) | 6.5 ms / 132 µs (49× the time) |

**How to read the pool rows.** The row without reset is seclume's pool over the vendor
driver, which does what HikariCP does: hand the connection back as it is. With seclume's own
driver underneath, the pool resets the session on every return - temporary tables, session
variables, `SET` statements, prepared statements and, on Oracle, the whole session - so the
next borrower cannot see what the last one left behind. HikariCP does not do that, and so
the two rows below it compare a pool that resets against one that does not. On SQL Server the
reset rides along with the next request and costs nothing measurable. On PostgreSQL and MySQL
it is one more round trip, which is what the gap is. On Oracle a complete reset means logging
off and on again on the same connection: the login is milliseconds of PBKDF2, and with eight
threads borrowing without a pause, Oracle Free cannot log sessions in as fast as they are
returned. With requests spaced 10 ms apart the median was 0.26 ms against HikariCP's 0.20 ms
(separate run, not in the records below). Oracle's DRCP with a fresh session per borrow was
measured as an alternative and was slower at normal load (about 1.3 ms per borrow) - it
was not built.

**The Oracle query rows are from a second run** (15.10.2026, below the Oracle record): the
first one had seclume reading one row in 63 µs against ojdbc's 42. Two causes, both fixed -
every answer made and closed a buffer in a shared arena, which stops all threads of the JVM
for a moment, and a query run again described its variables again where the server already
had the description.

### PostgreSQL

#### The run

| | |
|---|---|
| **measured** | 2026-10-13T13:26:15.748578858Z |
| **commit** | not a git checkout |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | -Dbench.db=postgresql -Dbench.port=5433 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.tls=on |
| **server** | not recorded - pass -Dbench.url to have it asked |

#### Reproducing it

```
taskset -c 2,3 java -Dbench.db=postgresql -Dbench.host=127.0.0.1 -Dbench.port=5433 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.password.file=<file> -Dbench.tls=on -jar seclume-bench.jar QueryBenchmark InsertBenchmark PoolBenchmark -rf json -rff result-postgresql.json -wi 3 -i 5 -f 2 -w 3s -r 3s
```

#### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` | avgt | 2.990 | ± 0.034 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` | avgt | 3.045 | ± 0.026 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` | avgt | 1.534 | ± 0.030 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` | avgt | 1.514 | ± 0.012 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=default, driver=seclume, rows=500]` | avgt | 0.667 | ± 0.023 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=default, driver=vendor, rows=500]` | avgt | 0.669 | ± 0.014 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=rewrite, driver=seclume, rows=500]` | avgt | 0.676 | ± 0.015 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=rewrite, driver=vendor, rows=500]` | avgt | 1.022 | ± 0.985 | ms/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | avgt | 0.663 | ± 0.011 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | avgt | 0.419 | ± 0.020 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | avgt | 0.424 | ± 0.016 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | avgt | 110.490 | ± 8.531 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | avgt | 108.114 | ± 3.914 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | avgt | 262.891 | ± 38.574 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | avgt | 151.224 | ± 19.602 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | avgt | 151.937 | ± 12.508 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | avgt | 250.634 | ± 10.255 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` | avgt | 728.064 | ± 25.003 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` | avgt | 696.362 | ± 17.038 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=seclume, rows=1000]` | avgt | 46.430 | ± 0.556 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=vendor, rows=1000]` | avgt | 52.739 | ± 2.305 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=seclume, rows=1000]` | avgt | 41.979 | ± 1.147 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=vendor, rows=1000]` | avgt | 42.394 | ± 0.287 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | sample | 0.930 | ± 0.182 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | sample | 0.569 | ± 0.120 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | sample | 0.594 | ± 0.123 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | sample | 63.532 | ± 0.198 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | sample | 66.566 | ± 0.233 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | sample | 142.265 | ± 0.498 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | sample | 83.138 | ± 0.237 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | sample | 84.302 | ± 0.281 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | sample | 136.581 | ± 0.456 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=hikari-vendor, size=16, thinkMicros=2000]` | sample | 113.005 | ± 1.561 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-vendor, size=16, thinkMicros=2000]` | sample | 115.923 | ± 2.069 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-seclume, size=16, thinkMicros=2000]` | sample | 166.320 | ± 1.708 | us/op | 2 | 3 | 5 |

#### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` — 2.945, 2.976, 2.974, 2.985, 3.004, 3.008, 2.985, 3.017, 2.989, 3.017 ms/op
- `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` — 3.050, 3.048, 3.043, 3.020, 3.011, 3.052, 3.045, 3.070, 3.048, 3.058 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` — 1.518, 1.529, 1.516, 1.525, 1.572, 1.541, 1.517, 1.532, 1.523, 1.566 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` — 1.498, 1.516, 1.508, 1.525, 1.520, 1.518, 1.514, 1.506, 1.519, 1.513 ms/op
- `InsertBenchmark.oneRow [batching=default, driver=seclume, rows=500]` — 0.647, 0.675, 0.648, 0.655, 0.682, 0.673, 0.681, 0.652, 0.675, 0.684 ms/op
- `InsertBenchmark.oneRow [batching=default, driver=vendor, rows=500]` — 0.668, 0.678, 0.677, 0.673, 0.647, 0.679, 0.670, 0.672, 0.662, 0.669 ms/op
- `InsertBenchmark.oneRow [batching=rewrite, driver=seclume, rows=500]` — 0.676, 0.681, 0.670, 0.679, 0.687, 0.652, 0.683, 0.678, 0.683, 0.673 ms/op
- `InsertBenchmark.oneRow [batching=rewrite, driver=vendor, rows=500]` — 0.680, 0.681, 0.655, 0.664, 0.669, 0.675, 0.666, 1.093, 2.024, 2.417 ms/op
- `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.673, 0.665, 0.667, 0.658, 0.657, 0.657, 0.662, 0.659, 0.675, 0.654 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 0.411, 0.417, 0.427, 0.412, 0.411, 0.403, 0.408, 0.447, 0.431, 0.422 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.441, 0.430, 0.433, 0.429, 0.430, 0.403, 0.417, 0.419, 0.414, 0.428 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 103.820, 113.176, 111.045, 111.973, 118.635, 109.469, 105.782, 106.351, 120.038, 104.614 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 110.269, 106.687, 107.006, 104.586, 107.839, 108.210, 110.712, 106.986, 113.193, 105.652 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 246.321, 249.910, 243.880, 251.529, 247.911, 292.776, 323.786, 254.981, 257.312, 260.500 us/op
- `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 146.398, 148.234, 153.225, 154.655, 143.467, 146.383, 146.428, 142.722, 186.414, 144.311 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 158.696, 142.820, 147.712, 146.303, 165.446, 165.708, 148.850, 146.415, 150.237, 147.184 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 242.077, 256.622, 241.114, 252.289, 250.066, 264.613, 247.601, 248.785, 252.461, 250.709 us/op
- `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` — 764.579, 741.949, 728.857, 730.879, 735.006, 715.146, 714.437, 709.990, 725.643, 714.151 us/op
- `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` — 696.469, 696.277, 691.687, 685.683, 724.431, 694.129, 692.290, 704.806, 691.743, 686.111 us/op
- `QueryBenchmark.selectOne [driver=seclume, rows=1000]` — 46.990, 46.321, 46.277, 46.587, 46.379, 46.362, 46.069, 47.034, 45.844, 46.439 us/op
- `QueryBenchmark.selectOne [driver=vendor, rows=1000]` — 51.379, 50.954, 51.073, 51.886, 51.864, 53.285, 54.027, 53.075, 54.839, 55.006 us/op
- `QueryBenchmark.selectRow [driver=seclume, rows=1000]` — 42.457, 43.345, 42.314, 42.485, 42.488, 41.224, 41.812, 40.934, 41.437, 41.291 us/op
- `QueryBenchmark.selectRow [driver=vendor, rows=1000]` — 42.363, 42.455, 42.359, 42.575, 42.690, 42.232, 42.371, 42.011, 42.541, 42.348 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.163, 0.163, 0.163, 0.163, 0.163, 0.155, 0.161, 0.161, 0.161, 0.161 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 0.104, 0.108, 0.108, 0.108, 0.108, 0.101, 0.100, 0.101, 0.101, 0.101 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.108, 0.111, 0.112, 0.112, 0.112, 0.106, 0.116, 0.115, 0.115, 0.115 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 34.560, 34.368, 35.136, 35.456, 34.816, 34.304, 36.416, 36.032, 36.352, 36.160 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 34.624, 35.136, 34.688, 35.328, 36.288, 35.648, 36.800, 35.712, 37.888, 36.608 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 62.848, 64.960, 64.320, 62.400, 64.576, 63.488, 64.064, 62.016, 65.536, 64.704 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 47.168, 49.344, 47.488, 48.896, 48.192, 49.152, 47.616, 48.448, 49.600, 49.728 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 48.640, 50.176, 49.152, 49.728, 49.152, 47.808, 48.000, 47.872, 49.344, 47.872 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 57.536, 57.920, 59.520, 55.744, 56.896, 58.560, 58.752, 56.896, 57.536, 58.112 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=hikari-vendor, size=16, thinkMicros=2000]` — 47.424, 50.880, 49.728, 51.968, 48.000, 51.584, 50.816, 51.200, 49.728, 51.136 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-vendor, size=16, thinkMicros=2000]` — 50.880, 52.672, 51.840, 49.920, 49.792, 51.584, 52.608, 50.624, 46.784, 52.160 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-seclume, size=16, thinkMicros=2000]` — 77.696, 83.584, 82.560, 76.160, 80.000, 84.608, 78.336, 76.672, 77.312, 74.240 us/op

#### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.

### MySQL

#### The run

| | |
|---|---|
| **measured** | 2026-10-13T13:56:21.016824254Z |
| **commit** | not a git checkout |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | -Dbench.db=mysql -Dbench.port=3307 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.tls=on |
| **server** | not recorded - pass -Dbench.url to have it asked |

#### Reproducing it

```
taskset -c 2,3 java -Dbench.db=mysql -Dbench.host=127.0.0.1 -Dbench.port=3307 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.password.file=<file> -Dbench.tls=on -jar seclume-bench.jar QueryBenchmark InsertBenchmark PoolBenchmark -rf json -rff result-mysql.json -wi 3 -i 5 -f 2 -w 3s -r 3s
```

#### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` | avgt | 17.964 | ± 0.435 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` | avgt | 32.891 | ± 0.604 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` | avgt | 5.041 | ± 0.114 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` | avgt | 7.127 | ± 4.001 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=default, driver=seclume, rows=500]` | avgt | 6.142 | ± 1.326 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=default, driver=vendor, rows=500]` | avgt | 7.141 | ± 1.103 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=rewrite, driver=seclume, rows=500]` | avgt | 6.580 | ± 0.357 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=rewrite, driver=vendor, rows=500]` | avgt | 6.557 | ± 0.260 | ms/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | avgt | 0.527 | ± 0.013 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | avgt | 0.496 | ± 0.315 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | avgt | 0.439 | ± 0.013 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | avgt | 139.325 | ± 19.751 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | avgt | 128.481 | ± 16.608 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | avgt | 271.506 | ± 23.006 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | avgt | 143.630 | ± 16.167 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | avgt | 151.423 | ± 33.431 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | avgt | 224.154 | ± 18.251 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` | avgt | 708.175 | ± 8.584 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` | avgt | 950.149 | ± 13.096 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=seclume, rows=1000]` | avgt | 41.058 | ± 0.862 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=vendor, rows=1000]` | avgt | 48.575 | ± 1.217 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=seclume, rows=1000]` | avgt | 41.673 | ± 0.815 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=vendor, rows=1000]` | avgt | 52.471 | ± 0.448 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | sample | 0.697 | ± 0.143 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | sample | 0.547 | ± 0.119 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | sample | 0.688 | ± 0.134 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | sample | 79.812 | ± 0.274 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | sample | 78.731 | ± 0.279 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | sample | 145.239 | ± 0.515 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | sample | 85.255 | ± 0.255 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | sample | 78.650 | ± 0.284 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | sample | 119.683 | ± 0.426 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=hikari-vendor, size=16, thinkMicros=2000]` | sample | 122.195 | ± 1.416 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-vendor, size=16, thinkMicros=2000]` | sample | 121.499 | ± 2.130 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-seclume, size=16, thinkMicros=2000]` | sample | 159.188 | ± 1.522 | us/op | 2 | 3 | 5 |

#### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` — 18.535, 17.951, 17.697, 17.629, 18.046, 17.747, 17.727, 18.132, 18.267, 17.905 ms/op
- `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` — 33.001, 33.164, 33.512, 33.073, 32.770, 33.340, 32.846, 32.401, 32.424, 32.385 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` — 5.115, 5.030, 5.039, 5.037, 4.978, 5.169, 4.888, 5.024, 5.049, 5.085 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` — 5.472, 5.471, 5.468, 5.457, 5.516, 5.459, 5.577, 10.652, 10.721, 11.474 ms/op
- `InsertBenchmark.oneRow [batching=default, driver=seclume, rows=500]` — 6.602, 5.371, 4.773, 5.063, 5.403, 7.061, 6.809, 6.779, 6.664, 6.897 ms/op
- `InsertBenchmark.oneRow [batching=default, driver=vendor, rows=500]` — 8.247, 8.413, 6.996, 6.790, 6.422, 6.798, 6.536, 6.700, 6.711, 7.796 ms/op
- `InsertBenchmark.oneRow [batching=rewrite, driver=seclume, rows=500]` — 6.614, 6.630, 7.054, 6.348, 6.525, 6.812, 6.727, 6.345, 6.362, 6.386 ms/op
- `InsertBenchmark.oneRow [batching=rewrite, driver=vendor, rows=500]` — 6.410, 6.492, 6.884, 6.612, 6.315, 6.391, 6.552, 6.681, 6.719, 6.509 ms/op
- `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.518, 0.524, 0.529, 0.527, 0.509, 0.532, 0.523, 0.537, 0.529, 0.536 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 1.088, 0.423, 0.416, 0.422, 0.429, 0.435, 0.430, 0.429, 0.435, 0.449 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.448, 0.440, 0.448, 0.442, 0.451, 0.430, 0.433, 0.432, 0.427, 0.434 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 170.307, 147.651, 127.155, 129.921, 126.751, 137.368, 140.768, 145.818, 134.757, 132.748 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 128.940, 119.692, 120.473, 118.649, 155.987, 128.143, 125.278, 123.127, 128.820, 135.700 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 259.330, 265.962, 269.201, 262.008, 267.285, 270.243, 267.901, 312.969, 264.890, 275.272 us/op
- `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 135.406, 136.860, 134.639, 135.132, 154.734, 156.277, 164.327, 138.228, 139.939, 140.763 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 196.506, 172.325, 137.400, 137.263, 135.627, 144.103, 131.984, 136.002, 147.157, 175.861 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 220.164, 247.658, 217.698, 213.970, 229.606, 220.504, 216.999, 213.250, 242.993, 218.701 us/op
- `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` — 715.053, 704.059, 707.200, 708.676, 705.661, 719.209, 711.112, 702.604, 707.523, 700.655 us/op
- `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` — 946.316, 969.258, 952.501, 947.613, 954.443, 940.314, 954.071, 941.193, 953.481, 942.300 us/op
- `QueryBenchmark.selectOne [driver=seclume, rows=1000]` — 40.397, 40.313, 40.108, 41.099, 41.287, 41.438, 41.489, 41.403, 41.303, 41.740 us/op
- `QueryBenchmark.selectOne [driver=vendor, rows=1000]` — 47.969, 48.211, 48.488, 48.410, 48.180, 48.248, 50.808, 48.397, 48.460, 48.583 us/op
- `QueryBenchmark.selectRow [driver=seclume, rows=1000]` — 41.097, 41.768, 41.497, 41.614, 40.846, 41.737, 41.918, 41.899, 41.492, 42.860 us/op
- `QueryBenchmark.selectRow [driver=vendor, rows=1000]` — 52.398, 52.436, 52.384, 52.555, 52.484, 52.231, 52.910, 52.651, 52.801, 51.858 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.140, 0.141, 0.140, 0.141, 0.141, 0.130, 0.135, 0.135, 0.135, 0.135 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 0.108, 0.108, 0.110, 0.111, 0.111, 0.106, 0.116, 0.116, 0.111, 0.111 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.105, 0.114, 0.114, 0.114, 0.114, 0.106, 0.119, 0.116, 0.116, 0.115 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 45.120, 46.016, 45.568, 45.568, 45.632, 45.312, 45.056, 44.288, 43.136, 45.376 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 42.048, 39.296, 41.472, 41.536, 42.176, 42.624, 43.776, 43.712, 43.136, 43.456 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 54.720, 54.208, 52.352, 54.656, 55.488, 53.824, 55.360, 54.400, 54.784, 54.848 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 49.408, 48.192, 47.872, 49.600, 47.360, 48.320, 48.128, 48.960, 49.472, 48.256 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 44.928, 43.776, 44.608, 45.248, 44.672, 46.848, 46.208, 45.504, 46.144, 44.096 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 52.608, 51.584, 51.904, 51.200, 50.176, 51.200, 51.328, 50.816, 52.224, 50.944 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=hikari-vendor, size=16, thinkMicros=2000]` — 58.496, 58.176, 59.968, 57.280, 59.072, 56.640, 59.648, 60.160, 61.248, 51.712 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-vendor, size=16, thinkMicros=2000]` — 58.496, 58.432, 57.664, 54.016, 61.504, 53.632, 56.896, 56.320, 62.016, 57.024 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-seclume, size=16, thinkMicros=2000]` — 66.048, 64.384, 66.304, 65.536, 64.064, 68.736, 66.048, 66.304, 65.536, 64.192 us/op

#### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.

### SQL Server

#### The run

| | |
|---|---|
| **measured** | 2026-10-13T14:26:18.068843061Z |
| **commit** | not a git checkout |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | -Dbench.db=sqlserver -Dbench.port=1433 -Dbench.database=master -Dbench.user=sa -Dbench.tls=on |
| **server** | not recorded - pass -Dbench.url to have it asked |

#### Reproducing it

```
taskset -c 2,3 java -Dbench.db=sqlserver -Dbench.host=127.0.0.1 -Dbench.port=1433 -Dbench.database=master -Dbench.user=sa -Dbench.password.file=<file> -Dbench.tls=on -jar seclume-bench.jar QueryBenchmark InsertBenchmark PoolBenchmark -rf json -rff result-sqlserver.json -wi 3 -i 5 -f 2 -w 3s -r 3s
```

#### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` | avgt | 9.238 | ± 1.077 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` | avgt | 9.439 | ± 0.557 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` | avgt | 9.372 | ± 0.925 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` | avgt | 9.354 | ± 0.773 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=default, driver=seclume, rows=500]` | avgt | 1.585 | ± 0.026 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=default, driver=vendor, rows=500]` | avgt | 1.582 | ± 0.026 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=rewrite, driver=seclume, rows=500]` | avgt | 1.581 | ± 0.022 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=rewrite, driver=vendor, rows=500]` | avgt | 1.579 | ± 0.036 | ms/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | avgt | 0.603 | ± 0.010 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | avgt | 0.461 | ± 0.269 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | avgt | 0.460 | ± 0.095 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | avgt | 309.157 | ± 60.013 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | avgt | 299.666 | ± 62.198 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | avgt | 324.945 | ± 22.889 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | avgt | 314.247 | ± 29.666 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | avgt | 326.664 | ± 52.501 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | avgt | 336.290 | ± 22.065 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` | avgt | 10483.139 | ± 140.552 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` | avgt | 10328.770 | ± 116.187 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=seclume, rows=1000]` | avgt | 86.070 | ± 3.012 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=vendor, rows=1000]` | avgt | 91.660 | ± 4.618 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=seclume, rows=1000]` | avgt | 91.600 | ± 3.567 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=vendor, rows=1000]` | avgt | 92.763 | ± 2.813 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | sample | 0.774 | ± 0.153 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | sample | 0.602 | ± 0.126 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | sample | 0.622 | ± 0.127 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | sample | 164.074 | ± 0.614 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | sample | 172.090 | ± 0.746 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | sample | 182.759 | ± 0.614 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | sample | 169.697 | ± 0.622 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | sample | 178.804 | ± 0.821 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | sample | 188.912 | ± 0.669 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=hikari-vendor, size=16, thinkMicros=2000]` | sample | 220.070 | ± 2.375 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-vendor, size=16, thinkMicros=2000]` | sample | 217.356 | ± 2.654 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-seclume, size=16, thinkMicros=2000]` | sample | 233.621 | ± 2.682 | us/op | 2 | 3 | 5 |

#### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` — 8.568, 8.810, 10.809, 9.847, 9.058, 9.456, 8.740, 8.890, 9.653, 8.550 ms/op
- `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` — 9.837, 9.391, 9.248, 10.150, 9.719, 9.052, 9.417, 9.245, 8.940, 9.388 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` — 8.839, 8.963, 9.333, 9.842, 10.224, 8.894, 8.841, 9.127, 9.124, 10.529 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` — 9.005, 9.576, 9.564, 9.005, 8.848, 9.495, 9.006, 9.241, 10.611, 9.190 ms/op
- `InsertBenchmark.oneRow [batching=default, driver=seclume, rows=500]` — 1.597, 1.561, 1.602, 1.592, 1.587, 1.607, 1.576, 1.594, 1.575, 1.556 ms/op
- `InsertBenchmark.oneRow [batching=default, driver=vendor, rows=500]` — 1.576, 1.565, 1.543, 1.589, 1.590, 1.591, 1.597, 1.586, 1.603, 1.584 ms/op
- `InsertBenchmark.oneRow [batching=rewrite, driver=seclume, rows=500]` — 1.561, 1.578, 1.589, 1.594, 1.584, 1.583, 1.593, 1.551, 1.588, 1.590 ms/op
- `InsertBenchmark.oneRow [batching=rewrite, driver=vendor, rows=500]` — 1.584, 1.601, 1.582, 1.597, 1.540, 1.601, 1.592, 1.533, 1.583, 1.581 ms/op
- `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.598, 0.595, 0.605, 0.596, 0.595, 0.607, 0.610, 0.608, 0.606, 0.614 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 0.412, 0.395, 0.389, 0.388, 0.401, 0.965, 0.414, 0.411, 0.417, 0.414 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.573, 0.429, 0.427, 0.422, 0.427, 0.583, 0.440, 0.426, 0.435, 0.435 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 285.521, 337.157, 403.407, 339.641, 289.247, 281.108, 293.030, 280.953, 298.161, 283.341 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 281.694, 278.355, 274.281, 353.962, 279.301, 396.202, 285.585, 284.769, 277.306, 285.205 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 323.177, 318.866, 343.535, 320.181, 314.093, 324.592, 310.871, 321.075, 313.560, 359.498 us/op
- `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 304.360, 313.579, 298.915, 305.946, 309.949, 300.761, 366.160, 324.811, 309.671, 308.315 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 313.441, 316.476, 301.501, 307.174, 314.625, 310.629, 336.614, 309.210, 337.344, 419.625 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 340.030, 329.974, 331.419, 370.225, 324.918, 348.315, 339.498, 331.131, 318.229, 329.160 us/op
- `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` — 10625.899, 10481.425, 10379.466, 10348.143, 10474.509, 10605.234, 10523.472, 10549.146, 10421.804, 10422.290 us/op
- `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` — 10292.461, 10386.600, 10438.847, 10199.363, 10440.033, 10323.660, 10334.492, 10327.253, 10293.155, 10251.832 us/op
- `QueryBenchmark.selectOne [driver=seclume, rows=1000]` — 87.559, 85.315, 84.575, 85.528, 85.747, 91.158, 84.640, 86.051, 84.655, 85.470 us/op
- `QueryBenchmark.selectOne [driver=vendor, rows=1000]` — 89.608, 90.831, 94.187, 88.114, 90.890, 89.474, 88.574, 97.765, 94.112, 93.046 us/op
- `QueryBenchmark.selectRow [driver=seclume, rows=1000]` — 90.492, 91.121, 90.278, 91.101, 89.534, 92.700, 90.829, 91.225, 90.813, 97.909 us/op
- `QueryBenchmark.selectRow [driver=vendor, rows=1000]` — 95.169, 93.076, 90.625, 92.207, 91.841, 92.647, 91.376, 92.602, 96.718, 91.374 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.161, 0.161, 0.162, 0.161, 0.161, 0.152, 0.151, 0.151, 0.151, 0.152 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 0.112, 0.112, 0.113, 0.112, 0.113, 0.106, 0.106, 0.106, 0.106, 0.106 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.106, 0.115, 0.114, 0.115, 0.115, 0.105, 0.114, 0.114, 0.120, 0.120 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 78.208, 77.056, 76.544, 79.104, 77.696, 74.624, 77.696, 76.544, 76.416, 76.928 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 78.720, 77.184, 78.464, 77.568, 73.600, 78.848, 78.080, 78.464, 77.056, 78.336 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 90.496, 88.064, 92.672, 86.656, 88.704, 91.008, 88.704, 91.008, 86.528, 90.624 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 83.968, 81.792, 80.896, 81.280, 81.152, 80.384, 83.200, 83.968, 85.504, 81.280 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 81.536, 82.176, 83.200, 82.688, 84.992, 84.096, 81.280, 80.896, 79.744, 82.688 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 90.880, 92.416, 91.904, 91.520, 90.880, 97.280, 91.008, 92.672, 90.880, 91.136 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=hikari-vendor, size=16, thinkMicros=2000]` — 91.264, 92.800, 91.136, 89.984, 87.168, 89.984, 95.360, 95.104, 86.016, 89.344 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-vendor, size=16, thinkMicros=2000]` — 90.240, 84.608, 94.592, 90.880, 89.216, 97.792, 97.792, 91.904, 85.248, 79.872 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-seclume, size=16, thinkMicros=2000]` — 94.848, 99.072, 105.088, 99.328, 110.848, 105.728, 105.600, 103.424, 103.552, 105.600 us/op

#### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.

### Oracle

#### The run

| | |
|---|---|
| **measured** | 2026-10-13T14:56:44.246092255Z |
| **commit** | not a git checkout |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | -Dbench.db=oracle -Dbench.port=1521 -Dbench.database=FREEPDB1 -Dbench.user=seclume_test -Dbench.tls=on |
| **server** | not recorded - pass -Dbench.url to have it asked |

#### Reproducing it

```
taskset -c 2,3 java -Dbench.db=oracle -Dbench.host=127.0.0.1 -Dbench.port=1521 -Dbench.database=FREEPDB1 -Dbench.user=seclume_test -Dbench.password.file=<file> -Dbench.tls=on -jar seclume-bench.jar QueryBenchmark InsertBenchmark PoolBenchmark -rf json -rff result-oracle.json -wi 3 -i 5 -f 2 -w 3s -r 3s
```

#### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` | avgt | 1.426 | ± 0.131 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` | avgt | 1.574 | ± 0.205 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` | avgt | 1.425 | ± 0.137 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` | avgt | 3.796 | ± 2.532 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=default, driver=seclume, rows=500]` | avgt | 2.172 | ± 0.158 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=default, driver=vendor, rows=500]` | avgt | 2.269 | ± 0.352 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=rewrite, driver=seclume, rows=500]` | avgt | 2.197 | ± 0.311 | ms/op | 2 | 3 | 5 |
| `InsertBenchmark.oneRow [batching=rewrite, driver=vendor, rows=500]` | avgt | 1.931 | ± 0.576 | ms/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | avgt | 0.512 | ± 0.009 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | avgt | 0.426 | ± 0.010 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | avgt | 0.436 | ± 0.042 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | avgt | 168.711 | ± 19.024 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | avgt | 105.090 | ± 5.286 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | avgt | 17408.381 | ± 2402.049 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | avgt | 180.745 | ± 20.188 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | avgt | 185.075 | ± 19.081 | us/op | 2 | 3 | 5 |
| `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | avgt | 18166.989 | ± 1525.760 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` | avgt | 995.408 | ± 31.709 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` | avgt | 1160.579 | ± 23.625 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=seclume, rows=1000]` | avgt | 59.109 | ± 1.026 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=vendor, rows=1000]` | avgt | 59.977 | ± 1.543 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=seclume, rows=1000]` | avgt | 62.988 | ± 1.769 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=vendor, rows=1000]` | avgt | 41.854 | ± 1.091 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` | sample | 0.800 | ± 0.158 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` | sample | 0.531 | ± 0.112 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` | sample | 0.641 | ± 0.130 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` | sample | 91.353 | ± 0.302 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` | sample | 61.375 | ± 0.193 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` | sample | 9466.504 | ± 266.853 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` | sample | 95.940 | ± 0.340 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` | sample | 94.798 | ± 0.379 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` | sample | 9515.345 | ± 265.054 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=hikari-vendor, size=16, thinkMicros=2000]` | sample | 132.321 | ± 1.197 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-vendor, size=16, thinkMicros=2000]` | sample | 105.540 | ± 2.197 | us/op | 2 | 3 | 5 |
| `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-seclume, size=16, thinkMicros=2000]` | sample | 6511.304 | ± 186.929 | us/op | 2 | 3 | 5 |

#### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `InsertBenchmark.batch [batching=default, driver=seclume, rows=500]` — 1.312, 1.483, 1.310, 1.533, 1.513, 1.469, 1.398, 1.453, 1.315, 1.477 ms/op
- `InsertBenchmark.batch [batching=default, driver=vendor, rows=500]` — 1.448, 1.582, 1.456, 1.797, 1.675, 1.696, 1.424, 1.520, 1.705, 1.438 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=seclume, rows=500]` — 1.501, 1.485, 1.305, 1.494, 1.364, 1.549, 1.273, 1.385, 1.461, 1.436 ms/op
- `InsertBenchmark.batch [batching=rewrite, driver=vendor, rows=500]` — 1.654, 8.099, 3.200, 3.298, 3.578, 4.632, 3.163, 3.301, 3.552, 3.483 ms/op
- `InsertBenchmark.oneRow [batching=default, driver=seclume, rows=500]` — 2.165, 2.222, 2.278, 2.158, 2.139, 1.900, 2.247, 2.224, 2.182, 2.208 ms/op
- `InsertBenchmark.oneRow [batching=default, driver=vendor, rows=500]` — 2.130, 2.376, 2.160, 2.253, 2.388, 1.855, 2.088, 2.683, 2.251, 2.501 ms/op
- `InsertBenchmark.oneRow [batching=rewrite, driver=seclume, rows=500]` — 2.021, 1.835, 2.358, 2.278, 2.361, 1.911, 2.369, 2.202, 2.414, 2.217 ms/op
- `InsertBenchmark.oneRow [batching=rewrite, driver=vendor, rows=500]` — 1.466, 1.878, 2.204, 2.133, 2.324, 1.454, 1.479, 1.817, 2.016, 2.538 ms/op
- `PoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.512, 0.515, 0.527, 0.510, 0.514, 0.509, 0.511, 0.502, 0.508, 0.514 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 0.430, 0.426, 0.424, 0.436, 0.437, 0.421, 0.424, 0.418, 0.418, 0.428 us/op
- `PoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.460, 0.465, 0.467, 0.459, 0.457, 0.412, 0.401, 0.412, 0.420, 0.408 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 150.025, 184.939, 164.481, 171.642, 182.900, 152.152, 170.896, 157.385, 181.861, 170.830 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 106.986, 102.733, 100.532, 112.632, 103.841, 104.170, 101.425, 104.826, 106.204, 107.552 us/op
- `PoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 17484.250, 21201.855, 17815.418, 18035.198, 16092.208, 17216.138, 17362.516, 17517.563, 15652.282, 15706.383 us/op
- `PoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 162.102, 162.863, 188.533, 181.417, 206.576, 169.971, 181.379, 181.821, 182.687, 190.107 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 175.866, 164.856, 193.537, 208.170, 185.775, 170.192, 185.551, 185.142, 186.016, 195.648 us/op
- `PoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 17850.565, 17590.636, 17639.295, 17952.670, 16947.342, 19731.962, 19306.265, 19494.712, 18177.725, 16978.717 us/op
- `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` — 998.776, 966.632, 983.990, 1008.710, 1001.448, 971.354, 999.280, 974.228, 1025.932, 1023.727 us/op
- `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` — 1142.219, 1145.613, 1146.469, 1146.711, 1149.891, 1171.161, 1168.646, 1176.792, 1180.039, 1178.255 us/op
- `QueryBenchmark.selectOne [driver=seclume, rows=1000]` — 58.395, 59.349, 60.135, 59.115, 58.927, 58.217, 58.941, 58.331, 59.849, 59.829 us/op
- `QueryBenchmark.selectOne [driver=vendor, rows=1000]` — 59.387, 62.402, 61.219, 59.389, 59.657, 59.898, 59.510, 59.574, 59.473, 59.261 us/op
- `QueryBenchmark.selectRow [driver=seclume, rows=1000]` — 65.784, 63.854, 62.428, 62.169, 63.305, 61.532, 62.760, 63.055, 62.414, 62.584 us/op
- `QueryBenchmark.selectRow [driver=vendor, rows=1000]` — 41.870, 42.191, 42.146, 41.918, 42.287, 41.055, 43.415, 41.315, 41.107, 41.242 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=hikari-vendor, size=16]` — 0.139, 0.139, 0.139, 0.139, 0.139, 0.140, 0.140, 0.140, 0.140, 0.140 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=seclume-vendor, size=16]` — 0.100, 0.113, 0.114, 0.114, 0.114, 0.111, 0.111, 0.111, 0.111, 0.111 us/op
- `PacedPoolBenchmark.borrowAndReturn [combination=seclume-seclume, size=16]` — 0.106, 0.120, 0.120, 0.120, 0.120, 0.103, 0.105, 0.105, 0.119, 0.117 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=hikari-vendor, size=16]` — 54.080, 52.864, 53.760, 52.800, 52.480, 51.712, 53.184, 53.632, 52.992, 52.736 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-vendor, size=16]` — 34.432, 35.072, 35.264, 34.432, 35.328, 34.112, 35.008, 34.752, 34.624, 35.200 us/op
- `PacedPoolBenchmark.borrowPreparedReturn [combination=seclume-seclume, size=16]` — 143.104, 130.432, 129.152, 119.168, 119.680, 137.984, 134.912, 127.872, 114.944, 115.200 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=hikari-vendor, size=16]` — 54.720, 54.400, 55.424, 55.552, 54.656, 54.784, 55.488, 56.064, 56.064, 56.000 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-vendor, size=16]` — 54.720, 55.040, 56.320, 56.256, 55.360, 55.936, 55.296, 56.768, 56.512, 56.512 us/op
- `PacedPoolBenchmark.borrowQueryReturn [combination=seclume-seclume, size=16]` — 137.728, 136.448, 140.800, 124.928, 119.040, 137.216, 142.080, 130.176, 117.376, 108.800 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=hikari-vendor, size=16, thinkMicros=2000]` — 77.312, 82.304, 79.616, 82.560, 83.712, 80.128, 81.408, 81.280, 81.280, 82.816 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-vendor, size=16, thinkMicros=2000]` — 56.896, 56.320, 52.736, 52.480, 51.584, 52.288, 54.784, 53.504, 54.080, 54.208 us/op
- `PacedPoolBenchmark.pacedPreparedReturn [combination=seclume-seclume, size=16, thinkMicros=2000]` — 140.544, 127.360, 123.904, 125.184, 115.072, 132.352, 135.424, 117.248, 115.456, 117.248 us/op

#### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.

### Oracle queries again (15.10.2026)

#### The run

| | |
|---|---|
| **measured** | 2026-10-13T16:08:55.237659724Z |
| **commit** | not a git checkout |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | -Dbench.db=oracle -Dbench.port=1521 -Dbench.database=FREEPDB1 -Dbench.user=seclume_test -Dbench.tls=on |
| **server** | not recorded - pass -Dbench.url to have it asked |

#### Reproducing it

```
taskset -c 2,3 java -Dbench.db=oracle -Dbench.host=127.0.0.1 -Dbench.port=1521 -Dbench.database=FREEPDB1 -Dbench.user=seclume_test -Dbench.password.file=<file> -Dbench.tls=on -jar seclume-bench.jar QueryBenchmark -rf json -rff result-oracle-q.json -wi 3 -i 5 -f 2 -w 3s -r 3s
```

#### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` | avgt | 931.847 | ± 11.067 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` | avgt | 1163.101 | ± 32.141 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=seclume, rows=1000]` | avgt | 36.989 | ± 0.452 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectOne [driver=vendor, rows=1000]` | avgt | 60.656 | ± 1.775 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=seclume, rows=1000]` | avgt | 39.834 | ± 0.592 | us/op | 2 | 3 | 5 |
| `QueryBenchmark.selectRow [driver=vendor, rows=1000]` | avgt | 40.448 | ± 0.596 | us/op | 2 | 3 | 5 |

#### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `QueryBenchmark.selectManyRows [driver=seclume, rows=1000]` — 925.076, 937.179, 931.785, 943.009, 939.991, 925.431, 935.201, 931.482, 919.128, 930.184 us/op
- `QueryBenchmark.selectManyRows [driver=vendor, rows=1000]` — 1150.326, 1134.097, 1137.112, 1149.908, 1152.121, 1186.830, 1178.427, 1189.266, 1187.719, 1165.204 us/op
- `QueryBenchmark.selectOne [driver=seclume, rows=1000]` — 36.735, 36.573, 36.631, 37.167, 37.100, 36.967, 37.032, 37.266, 37.538, 36.878 us/op
- `QueryBenchmark.selectOne [driver=vendor, rows=1000]` — 60.580, 61.015, 61.082, 62.494, 60.988, 62.350, 60.041, 59.123, 59.252, 59.639 us/op
- `QueryBenchmark.selectRow [driver=seclume, rows=1000]` — 40.045, 39.721, 39.779, 39.712, 39.510, 40.211, 39.691, 39.749, 39.251, 40.666 us/op
- `QueryBenchmark.selectRow [driver=vendor, rows=1000]` — 40.174, 39.989, 40.780, 39.930, 40.204, 40.359, 40.775, 40.511, 40.571, 41.184 us/op

#### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.

## R2DBC on PostgreSQL (15.10.2026)

`seclume-r2dbc` against r2dbc-postgresql 1.1.3 (Netty), and over the pools: `SeclumePool`
against r2dbc-pool 1.0.2, both sixteen connections, eight threads. Same host and settings as
above, TLS on both sides.

| | seclume | r2dbc-postgresql |
|---|---|---|
| `select 1`, one connection | 62.0 µs ± 10.8 | 68.7 µs ± 3.9 (even) |
| one row with a bind | **64.1 µs** ± 1.2 | 71.5 µs ± 1.4 (**−10 %**) |
| 1000 rows | **817 µs** ± 53 | 1304 µs ± 44 (**−37 %**) |
| pool: borrow, prepared query, return | 361 µs ± 62 | **215 µs** ± 53 (+68 %) |

The pool row is the JDBC pool row again: seclume resets the session when a connection comes
back, r2dbc-pool does not, and the difference (146 µs) is the same as against HikariCP
(153 µs). Before this run each R2DBC connection made and tore down an executor and a
scheduler; a borrow cost 1.57 ms, now 0.36.

### The run

| | |
|---|---|
| **measured** | 2026-10-15T14:54:34.908730409Z |
| **commit** | not a git checkout |
| **os** | Linux 5.14.0-687.44.1.el9_8.x86_64 (amd64) |
| **cpus** | 4 |
| **heap** | 3864 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Eclipse Adoptium) |
| **jvm arguments** | -Dbench.db=postgresql -Dbench.port=5433 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.tls=on |
| **server** | not recorded - pass -Dbench.url to have it asked |

### Reproducing it

```
taskset -c 2,3 java -Dbench.db=postgresql -Dbench.host=127.0.0.1 -Dbench.port=5433 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.password.file=<file> -Dbench.tls=on -jar seclume-bench.jar R2dbc -rf json -rff result-r2dbc.json -wi 3 -i 5 -f 2 -w 3s -r 3s
```

### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `R2dbcBenchmark.selectManyRows [driver=seclume]` | avgt | 817.193 | ± 52.560 | us/op | 2 | 3 | 5 |
| `R2dbcBenchmark.selectManyRows [driver=r2dbc-postgresql]` | avgt | 1304.293 | ± 43.682 | us/op | 2 | 3 | 5 |
| `R2dbcBenchmark.selectOne [driver=seclume]` | avgt | 61.980 | ± 10.771 | us/op | 2 | 3 | 5 |
| `R2dbcBenchmark.selectOne [driver=r2dbc-postgresql]` | avgt | 68.666 | ± 3.912 | us/op | 2 | 3 | 5 |
| `R2dbcBenchmark.selectRow [driver=seclume]` | avgt | 64.118 | ± 1.240 | us/op | 2 | 3 | 5 |
| `R2dbcBenchmark.selectRow [driver=r2dbc-postgresql]` | avgt | 71.477 | ± 1.444 | us/op | 2 | 3 | 5 |
| `R2dbcPoolBenchmark.borrowPreparedReturn [pool=seclume, size=16]` | avgt | 361.466 | ± 61.941 | us/op | 2 | 3 | 5 |
| `R2dbcPoolBenchmark.borrowPreparedReturn [pool=r2dbc-pool, size=16]` | avgt | 214.698 | ± 53.348 | us/op | 2 | 3 | 5 |

### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `R2dbcBenchmark.selectManyRows [driver=seclume]` — 810.153, 816.266, 914.224, 804.846, 794.361, 812.541, 800.312, 813.837, 802.832, 802.556 us/op
- `R2dbcBenchmark.selectManyRows [driver=r2dbc-postgresql]` — 1336.043, 1330.505, 1351.848, 1324.026, 1292.363, 1291.092, 1270.100, 1288.649, 1269.860, 1288.447 us/op
- `R2dbcBenchmark.selectOne [driver=seclume]` — 59.277, 59.583, 59.610, 59.832, 60.374, 60.724, 82.197, 60.043, 58.918, 59.244 us/op
- `R2dbcBenchmark.selectOne [driver=r2dbc-postgresql]` — 68.711, 67.601, 67.424, 68.728, 67.340, 67.443, 67.850, 67.920, 75.895, 67.743 us/op
- `R2dbcBenchmark.selectRow [driver=seclume]` — 63.260, 65.941, 64.035, 64.012, 64.847, 63.644, 63.730, 64.642, 63.772, 63.296 us/op
- `R2dbcBenchmark.selectRow [driver=r2dbc-postgresql]` — 72.489, 71.509, 70.162, 70.619, 72.934, 72.778, 71.128, 71.419, 70.741, 70.993 us/op
- `R2dbcPoolBenchmark.borrowPreparedReturn [pool=seclume, size=16]` — 355.604, 347.740, 476.648, 350.546, 337.135, 349.089, 356.799, 355.319, 341.603, 344.173 us/op
- `R2dbcPoolBenchmark.borrowPreparedReturn [pool=r2dbc-pool, size=16]` — 252.557, 195.119, 192.544, 193.858, 208.186, 299.646, 218.261, 195.817, 188.455, 202.542 us/op

### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.

## MySQL alone (24.09.2026)

### The run

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

### Reproducing it

```
taskset -c 2,3 java -Dbench.db=mysql -Dbench.host=127.0.0.1 -Dbench.port=3307 -Dbench.database=seclume_test -Dbench.user=seclume_test -Dbench.password.file=<file> -jar seclume-bench.jar QueryBenchmark InsertBenchmark PoolBenchmark -rf json -rff jmh.json -wi 3 -i 5 -f 2 -w 5s -r 5s
```

### What was measured

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

### The iterations themselves

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

### What these numbers do not say

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

---

## The TLS record layer (26.09.2026, before and after)

`RecordBenchmark` seals and opens one record of `tlsStack=seclume` - no socket and no database,
only the record layer and the AES-GCM beneath it. `native` is OpenSSL on Linux (CNG on Windows);
`java` is the constant-time fallback that every other platform gets, macOS among them.

Before is `429a36a` with only `RecordBenchmark` added, after is the commit below; same machine,
same JDK, one run each, directly after one another.

| | cipher | record | before | after | |
|---|---|---|---|---|---|
| seal | native | 64 B | 1 554 ns | 517 ns | 3.0× |
| seal | native | 16 KiB | 5 893 ns | 4 273 ns | 1.4× |
| seal | java | 64 B | 65.0 µs | 18.3 µs | 3.5× |
| seal | java | 16 KiB | 9.63 ms | 2.26 ms | 4.3× |
| open | native | 64 B | 1 469 ns | 450 ns | 3.3× |
| open | native | 16 KiB | 5 423 ns | 3 356 ns | 1.6× |
| open | java | 64 B | 62.9 µs | 19.2 µs | 3.3× |
| open | java | 16 KiB | 9.28 ms | 2.09 ms | 4.4× |

**What changed.**
- **Per record**: no confined arena for each record any more, which allocated, zeroed and
  freed up to 16 KiB every time; a record is opened straight into the caller's buffer.
- **OpenSSL**: `invokeExact` instead of `invokeWithArguments`, which boxed every argument of
  the four or five downcalls a record takes. With the first point, that is what a short
  record cost: the AES-GCM of 64 bytes is a small part of the 450 ns left.
- **Java AES**: the S-box inversion with four multiplications instead of thirteen, 64-bit bit
  planes that take four counter blocks per pass, and bytes turned into bit planes by 8x8 bit
  transposes. Still constant time - AND, XOR and shifts, no lookup.

**What they do not say.** The Java fallback is still some 500 times slower than OpenSSL for
bulk data, about 7 MB/s here. It logs a warning once when TLS uses it.

### The run

| | |
|---|---|
| **measured** | 2026-09-26T18:44:49.692741619Z |
| **commit** | v0.10.0-9-gbe37749 |
| **os** | Linux 6.18.44-fc-v37 (amd64) |
| **cpus** | 4 |
| **heap** | 3422 MB max |
| **jdk** | OpenJDK 64-Bit Server VM 25.0.4.1 (Ubuntu) |
| **jvm arguments** | the build container's proxy and trust-store settings, nothing that touches the measurement |
| **server** | not recorded - pass -Dbench.url to have it asked |

### Reproducing it

```
java -jar seclume-bench.jar RecordBenchmark -wi 3 -i 5 -f 1 -w 2s -r 3s -rf json -rff jmh.json
```

### What was measured

| benchmark | mode | score | error | unit | forks | warmup | iterations |
|---|---|---|---|---|---|---|---|
| `RecordBenchmark.open [cipher=native, payload=64]` | avgt | 449.892 | ± 67.202 | ns/op | 1 | 3 | 5 |
| `RecordBenchmark.open [cipher=native, payload=16384]` | avgt | 3355.738 | ± 373.592 | ns/op | 1 | 3 | 5 |
| `RecordBenchmark.open [cipher=java, payload=64]` | avgt | 19180.190 | ± 4241.447 | ns/op | 1 | 3 | 5 |
| `RecordBenchmark.open [cipher=java, payload=16384]` | avgt | 2094589.804 | ± 219140.808 | ns/op | 1 | 3 | 5 |
| `RecordBenchmark.seal [cipher=native, payload=64]` | avgt | 516.637 | ± 112.068 | ns/op | 1 | 3 | 5 |
| `RecordBenchmark.seal [cipher=native, payload=16384]` | avgt | 4273.361 | ± 546.567 | ns/op | 1 | 3 | 5 |
| `RecordBenchmark.seal [cipher=java, payload=64]` | avgt | 18311.489 | ± 1677.210 | ns/op | 1 | 3 | 5 |
| `RecordBenchmark.seal [cipher=java, payload=16384]` | avgt | 2262475.290 | ± 220491.378 | ns/op | 1 | 3 | 5 |

### The iterations themselves

Not a summary of them. An average with an error bar hides a bimodal result, and a bimodal result is usually the interesting one.

- `RecordBenchmark.open [cipher=native, payload=64]` — 446.478, 475.825, 426.841, 451.303, 449.011 ns/op
- `RecordBenchmark.open [cipher=native, payload=16384]` — 3246.827, 3488.071, 3323.503, 3420.147, 3300.143 ns/op
- `RecordBenchmark.open [cipher=java, payload=64]` — 17995.411, 18992.479, 18500.562, 19555.595, 20856.902 ns/op
- `RecordBenchmark.open [cipher=java, payload=16384]` — 2107494.391, 2047326.834, 2099275.030, 2038389.230, 2180463.537 ns/op
- `RecordBenchmark.seal [cipher=native, payload=64]` — 567.655, 503.333, 503.908, 495.955, 512.334 ns/op
- `RecordBenchmark.seal [cipher=native, payload=16384]` — 4152.803, 4331.466, 4494.892, 4172.018, 4215.628 ns/op
- `RecordBenchmark.seal [cipher=java, payload=64]` — 18584.228, 18339.306, 18124.489, 17688.013, 18821.410 ns/op
- `RecordBenchmark.seal [cipher=java, payload=16384]` — 2323374.974, 2292772.760, 2206829.572, 2195913.605, 2293485.539 ns/op

### What these numbers do not say

That they hold on another machine, another JDK, or another distance to the server. They say what this run measured, which is the only thing a benchmark can say.
