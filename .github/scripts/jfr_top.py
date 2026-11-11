"""jfr_top.py <samples.json> <label>: where the CPU samples of a JFR recording are -
by top frame, by the first frame of this project under it, and by library."""
import collections
import json
import sys

GROUPS = ["space.seclume.r2dbc", "space.seclume.postgresql", "space.seclume.pool", "space.seclume",
          "reactor.", "io.r2dbc.postgresql", "io.r2dbc", "io.netty", "org.openjdk.jmh",
          "java.", "jdk.", "sun."]


def name(frame):
    method = frame.get("method") or {}
    return f"{(method.get('type') or {}).get('name', '?')}.{method.get('name', '?')}"


def main(argv):
    with open(argv[1], encoding="utf-8") as source:
        events = json.load(source)["recording"]["events"]
    top, own, group, threads = (collections.Counter() for _ in range(4))
    total = 0
    for event in events:
        values = event.get("values", {})
        frames = [name(f) for f in ((values.get("stackTrace") or {}).get("frames") or [])]
        if not frames:
            continue
        total += 1
        top[frames[0]] += 1
        threads[((values.get("sampledThread") or {}).get("javaName") or "?").rstrip("0123456789-")] += 1
        group[next((g for g in GROUPS if frames[0].startswith(g)), "other")] += 1
        own[next((f for f in frames if f.startswith(("space.seclume", "io.r2dbc.postgresql"))), "(none)")] += 1
    print(f"== {argv[2]}: {total} samples")
    for title, counter, n in (("by thread", threads, 8), ("top frame, by library", group, 12),
                              ("top frame", top, 25), ("first driver frame on the stack", own, 25)):
        print(f"-- {title}")
        for key, count in counter.most_common(n):
            print(f"{100.0 * count / max(total, 1):5.1f}%  {key}")


if __name__ == "__main__":
    main(sys.argv)
