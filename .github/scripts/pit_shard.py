"""The classes of one shard of a package, as PIT's targetClasses.

  pit_shard.py <source root> <package> <shard> <shards>

Every top-level class of the package and its subpackages - one source file
each - goes to exactly one of <shards> shards (1-based <shard>), the largest
files first, each to the shard with the fewest bytes so far: the shards come
out within a few per cent of each other, and a class added later is in one of
them without anyone listing it. A class's nested classes go with it
(Outer and Outer$*). Printed comma-separated, for -DtargetClasses.
"""
import os
import sys


def classes(source_root, package):
    """[(size, class name)] of the package's top-level classes, largest first."""
    root = os.path.join(source_root, *package.split("."))
    found = []
    for directory, _, files in os.walk(root):
        for name in files:
            if not name.endswith(".java") or name in ("package-info.java", "module-info.java"):
                continue
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, source_root)[: -len(".java")]
            found.append((os.path.getsize(path), relative.replace(os.sep, ".")))
    return sorted(found, key=lambda entry: (-entry[0], entry[1]))


def shards(source_root, package, count):
    bins = [[0, []] for _ in range(count)]
    for size, name in classes(source_root, package):
        smallest = min(range(count), key=lambda i: (bins[i][0], i))
        bins[smallest][0] += size
        bins[smallest][1].append(name)
    return [sorted(names) for _, names in bins]


def target_classes(names):
    return ",".join(f"{name},{name}$*" for name in names)


def main(source_root, package, shard, count):
    shard, count = int(shard), int(count)
    if not 1 <= shard <= count:
        raise ValueError(f"shard {shard} of {count}")
    names = shards(source_root, package, count)[shard - 1]
    if not names:
        raise ValueError(f"shard {shard} of {count} of {package} has no class")
    print(target_classes(names))
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:5]))
