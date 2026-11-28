"""Say where two jars that should be the same differ: entry by entry.

    python3 jar_entries_diff.py built.jar central.jar

Prints the entries only one has, the entries whose bytes differ (with their
sizes, and the start of a text entry's difference), a timestamp or order
that differs, and nothing at all for two jars that are the same entry by
entry. Reads both as data: nothing in them is run.
"""
import difflib
import sys
import zipfile

LIMIT = 20


def entries(path):
    with zipfile.ZipFile(path) as jar:
        return [(info, jar.read(info)) for info in jar.infolist()]


def text(data):
    try:
        return data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def compare(ours_path, theirs_path, out=print):
    ours = entries(ours_path)
    theirs = entries(theirs_path)
    mine = {info.filename: (info, data) for info, data in ours}
    other = {info.filename: (info, data) for info, data in theirs}
    lines = 0

    def say(line):
        nonlocal lines
        if lines < LIMIT * 4:
            out(line)
        lines += 1

    for name in sorted(set(mine) - set(other)):
        say(f"  only built: {name}")
    for name in sorted(set(other) - set(mine)):
        say(f"  only on Central: {name}")
    differing = 0
    for name in sorted(set(mine) & set(other)):
        (a, x), (b, y) = mine[name], other[name]
        if x != y:
            differing += 1
            if differing > LIMIT:
                continue
            say(f"  differs: {name} ({len(x)} built, {len(y)} Central bytes)")
            tx, ty = text(x), text(y)
            if tx is not None and ty is not None:
                diff = list(difflib.unified_diff(ty, tx, "central", "built", n=0, lineterm=""))
                for line in diff[2:8]:
                    say("    " + line[:200])
            elif x.replace(b"\r\n", b"\n") == y.replace(b"\r\n", b"\n"):
                say("    only line endings")
        elif a.date_time != b.date_time:
            say(f"  timestamp: {name} {a.date_time} built, {b.date_time} Central")
    if differing > LIMIT:
        say(f"  ... {differing - LIMIT} more entries differ")
    common = [n for n in (i.filename for i, _ in ours) if n in other]
    order = [n for n in (i.filename for i, _ in theirs) if n in mine]
    if common != order:
        first = next(i for i, (p, q) in enumerate(zip(common, order)) if p != q)
        say(f"  entry order differs from entry {first}: {common[first]} built, {order[first]} Central")
    return lines


if __name__ == "__main__":
    sys.exit(0 if compare(sys.argv[1], sys.argv[2]) == 0 else 1)
