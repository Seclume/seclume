"""jfr_top.py <samples.json> <cpuload.json> <label>: where the CPU samples of a JFR
recording are - by thread, by library, by top frame, by the first frame of this
project under it - and how busy the JVM and the machine were."""
import collections
import json
import sys

GROUPS = ["space.seclume.r2dbc", "space.seclume.postgresql", "space.seclume.pool", "space.seclume",
          "reactor.", "io.r2dbc.postgresql", "io.r2dbc.pool", "io.r2dbc", "io.netty", "org.postgresql",
          "org.openjdk.jmh", "java.util.concurrent", "java.lang.VirtualThread", "jdk.internal.misc",
          "java.", "jdk.", "sun."]


def name(frame):
    method = frame.get("method") or {}
    kind = (method.get("type") or {}).get("name", "?").replace("/", ".")
    return f"{kind}.{method.get('name', '?')}"


def events(path):
    with open(path, encoding="utf-8") as source:
        return json.load(source)["recording"]["events"]


def main(argv):
    top, own, group, threads, stacks = (collections.Counter() for _ in range(5))
    total = 0
    for event in events(argv[1]):
        values = event.get("values", {})
        frames = [name(f) for f in ((values.get("stackTrace") or {}).get("frames") or [])]
        if not frames:
            continue
        total += 1
        top[frames[0]] += 1
        thread = values.get("sampledThread") or {}
        threads[(thread.get("javaName") or thread.get("osName") or "?").rstrip("0123456789-#@")] += 1
        group[next((g for g in GROUPS if frames[0].startswith(g)), "other")] += 1
        own[next((f for f in frames if f.startswith(("space.seclume", "io.r2dbc", "org.postgresql"))),
                 "(none)")] += 1
        stacks[" < ".join(frames[:6])] += 1
    loads = [e.get("values", {}) for e in events(argv[2])]
    if loads:
        jvm = sum(v.get("jvmUser", 0) + v.get("jvmSystem", 0) for v in loads) / len(loads)
        machine = sum(v.get("machineTotal", 0) for v in loads) / len(loads)
        print(f"== {argv[3]}: {total} samples; JVM {100 * jvm:.0f} % and machine {100 * machine:.0f} % "
              f"of all CPUs, mean of {len(loads)} readings")
    else:
        print(f"== {argv[3]}: {total} samples")
    for title, counter, n in (("by thread", threads, 8), ("top frame, by library", group, 14),
                              ("top frame", top, 25), ("first driver or pool frame on the stack", own, 25),
                              ("hottest six-frame stacks", stacks, 15)):
        print(f"-- {title}")
        for key, count in counter.most_common(n):
            print(f"{100.0 * count / max(total, 1):5.1f}%  {key[:300]}")


if __name__ == "__main__":
    main(sys.argv)
