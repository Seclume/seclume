#!/usr/bin/env python3
"""What the build fetches by name instead of by content - and that it gets no more.

    pinned_inputs.py --list  [--root .]     every input that is not pinned
    pinned_inputs.py --check [--root .]     fail on an unpinned input the ratchet does not name,
                                            and on a ratchet entry that is pinned by now
    pinned_inputs.py --pin   [--root .]     replace each image tag by tag@digest (needs crane or
                                            docker buildx and the network; a maintainer runs it)

A container image named by its tag, a Maven distribution without
distributionSha256Sum, or an archive checked against a checksum fetched from
the same place as the archive, is whatever the registry or the mirror serves
on the day: a moved tag changes the build - and the code that runs next to the
test databases' passwords and the signing step - without a change in this
repository. .github/unpinned-inputs.json lists the inputs that are not pinned
yet; --check (run in CI) keeps the list from growing and makes it shrink: a new
unpinned input fails, and so does an entry that is pinned now and still listed.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

RATCHET = os.path.join(".github", "unpinned-inputs.json")
SCANNED = (".github", "examples")
SUFFIXES = (".yml", ".yaml", ".sh", ".properties")
NAMES = ("Dockerfile", "Containerfile")

DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
# An image reference: [registry/]path[:tag][@digest], or one with a ${...} in it.
REFERENCE = re.compile(r"^[\w.${}-]+(?::\d+)?(?:/[\w.${}-]+)*(?::[\w.${}-]+)?(?:@sha256:[0-9a-f]{64})?$")
# docker / podman options that take a value as the next word.
VALUED = {"-e", "--env", "-p", "--publish", "-v", "--volume", "--name", "--network", "--net",
          "--hostname", "-h", "-m", "--memory", "--user", "-u", "--entrypoint", "-w", "--workdir",
          "--platform", "--cap-add", "--cap-drop", "--mount", "--label", "-l", "--env-file",
          "--health-cmd", "--health-interval", "--health-retries", "--health-timeout",
          "--shm-size", "--ulimit", "--add-host", "--tmpfs", "--restart", "--cpus",
          "--security-opt", "--ip", "--dns", "--log-driver", "--log-opt", "--stop-timeout",
          "--device", "--sysctl", "--pid", "--ipc", "--userns", "--group-add", "--expose",
          "--format", "-f", "--mac-address", "--memory-swap", "--pull"}


def files(root):
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in ("node_modules", "target"))
        for name in sorted(names):
            if name.startswith(NAMES) and not folder.startswith(tuple(os.path.join(root, t) for t in SCANNED)):
                path = os.path.join(folder, name)
                yield os.path.relpath(path, root).replace(os.sep, "/"), path
    for top in SCANNED:
        for folder, dirs, names in os.walk(os.path.join(root, top)):
            dirs[:] = sorted(d for d in dirs if d not in ("node_modules", "target"))
            for name in sorted(names):
                if name.endswith(SUFFIXES) or name.startswith(NAMES):
                    path = os.path.join(folder, name)
                    yield os.path.relpath(path, root).replace(os.sep, "/"), path


def logical_lines(text):
    """(line number, line) with shell continuations joined and comments dropped."""
    joined, start = "", None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = re.sub(r"(^|\s)#(?!\{).*$", "", line) if not line.lstrip().startswith("- name:") else line
        if start is None:
            start = number
        if stripped.rstrip().endswith("\\"):
            joined += stripped.rstrip()[:-1] + " "
            continue
        yield start, joined + stripped
        joined, start = "", None
    if start is not None:
        yield start, joined


def words(command):
    """The command's words, quotes taken off (no expansion)."""
    return [w.strip("'\"") for w in re.findall(r"\"[^\"]*\"|'[^']*'|\S+", command)]


def image_of(args):
    """The image a docker run / create / pull names: the first word that is no option."""
    skip = False
    for word in args:
        if skip:
            skip = False
            continue
        if word.startswith("-"):
            skip = word in VALUED and "=" not in word
            continue
        return word
    return None


def is_image(word):
    return bool(word) and REFERENCE.match(word) and not word.startswith("$") and (
        "/" in word or ":" in word) and not word.startswith(("http", "./", "/"))


REGISTRY = re.compile(r"(?<![\w./@-])((?:docker\.io|quay\.io|ghcr\.io|gcr\.io|mcr\.microsoft\.com|"
                      r"public\.ecr\.aws|container-registry\.oracle\.com|registry\.k8s\.io)"
                      r"/[\w./-]+(?::[\w.${}-]+)?(?:@sha256:[0-9a-f]{64})?)")
ASSIGNED = re.compile(r"(?<![\w-])\w*image\w*=['\"]?([^'\"\s;]+)", re.I)
# Images the build makes itself: docker build -t NAME, or the admission webhook's build-image.sh NAME.
BUILT = re.compile(r"\b(?:(?:docker|podman)\s+(?:buildx\s+)?build\b.*?(?:-t|--tag)[ =]|build-image\.sh\s+)"
                   r"['\"]?([^'\"\s]+)")


def tidy(line):
    """${{ matrix.x }} as one word."""
    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda m: "${{" + m.group(1).replace(" ", "") + "}}", line)


def images(text):
    """(line, reference) for each container image the text names, but those it builds itself."""
    built = {m.group(1) for m in BUILT.finditer(text)}
    return [(number, image) for number, image in named_images(text) if image not in built]


def named_images(text):
    found = []
    for number, line in logical_lines(text):
        line = tidy(line)
        match = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", line, re.I)
        if match and match.group(1).lower() != "scratch":
            found.append((number, match.group(1)))
        for match in REGISTRY.finditer(line):
            found.append((number, match.group(1)))
        for match in ASSIGNED.finditer(line):
            if is_image(match.group(1)):
                found.append((number, match.group(1)))
        match = re.match(r"^\s*(?:-\s*)?image:\s*['\"]?([^'\"\s]+)", line)
        if match:
            found.append((number, match.group(1)))
        for match in re.finditer(r"\b(?:docker|podman)\s+(run|create|pull)\b(.*)", line):
            image = image_of(words(match.group(2)))
            if image and is_image(image):
                found.append((number, image))
        for match in re.finditer(r"\$\{\w*IMAGE\w*:-([^}\s]+)\}|\b\w*_?image=\$\{\w+:-([^}\s]+)\}"
                                 r"|^\s*\w*IMAGE\w*:\s*['\"]?([^'\"\s]+)", line, re.I):
            value = next(g for g in match.groups() if g)
            if is_image(value):
                found.append((number, value))
    unique, seen = [], set()
    for number, image in found:
        if (number, image) not in seen:
            seen.add((number, image))
            unique.append((number, image))
    return unique


def downloads(text):
    """(line, url) for each download checked only against a checksum from the same place."""
    found = []
    lines = list(logical_lines(text))
    for number, line in lines:
        for match in re.finditer(r"(https://\S+?)\.(sha256|sha512)\b", line):
            found.append((number, match.group(1).strip("'\"") + "  (checksum from the same server)"))
    return found


def maven_distribution(text):
    """The wrapper's distribution, when no distributionSha256Sum pins it."""
    if "distributionUrl=" in text and not re.search(r"^distributionSha256Sum=[0-9a-f]{64}\s*$", text, re.M):
        url = re.search(r"^distributionUrl=(\S+)", text, re.M).group(1)
        number = text[:text.index("distributionUrl=")].count("\n") + 1
        return [(number, url + "  (no distributionSha256Sum)")]
    return maven_wrapper_jar(text)


def maven_wrapper_jar(text):
    """The wrapper jar itself: without wrapperSha256Sum mvnw runs whatever the
    server sends, and a wrapperUrl of another version than wrapperVersion says
    the version was changed without the checksum that goes with it."""
    if "wrapperUrl=" not in text and "wrapperVersion=" not in text:
        return []
    found = []
    url = re.search(r"^wrapperUrl=(\S+)", text, re.M)
    version = re.search(r"^wrapperVersion=(\S+)", text, re.M)
    where = url or version
    number = text[:where.start()].count("\n") + 1
    name = url.group(1) if url else "maven-wrapper " + version.group(1)
    if not re.search(r"^wrapperSha256Sum=[0-9a-f]{64}\s*$", text, re.M):
        found.append((number, name + "  (no wrapperSha256Sum)"))
    if url and version and ("/" + version.group(1) + "/") not in url.group(1):
        found.append((number, name + "  (wrapperUrl is not wrapperVersion " + version.group(1) + ")"))
    return found


def unpinned(root):
    """Sorted (file, input) for every input that is not pinned."""
    result = set()
    for relative, path in files(root):
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        if relative.endswith("maven-wrapper.properties"):
            result.update((relative, what) for _, what in maven_distribution(text))
            continue
        result.update((relative, image) for _, image in images(text) if not DIGEST.search(image))
        result.update((relative, url) for _, url in downloads(text))
    wrapper = os.path.join(root, ".mvn", "wrapper", "maven-wrapper.properties")
    if os.path.isfile(wrapper):
        with open(wrapper, encoding="utf-8") as f:
            result.update((".mvn/wrapper/maven-wrapper.properties", what)
                          for _, what in maven_distribution(f.read()))
    return sorted(result)


def check(root):
    with open(os.path.join(root, RATCHET), encoding="utf-8") as f:
        listed = {(e["file"], e["input"]) for e in json.load(f)["unpinned"]}
    found = set(unpinned(root))
    new = sorted(found - listed)
    done = sorted(listed - found)
    return new, done


def digest(image):
    """The digest a tag points to now, from the registry."""
    if shutil.which("crane"):
        out = subprocess.run(["crane", "digest", image], check=True, capture_output=True, text=True)
        return out.stdout.strip()
    out = subprocess.run(["docker", "buildx", "imagetools", "inspect", image, "--format",
                          "{{json .Manifest}}"], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)["digest"]


def pin(root):
    """Each tagged image (without ${...}) becomes tag@digest, in place."""
    changed = 0
    for relative, path in files(root):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        updated = text
        for _, image in images(text):
            if DIGEST.search(image) or "$" in image:
                continue
            pinned = image + "@" + digest(image)
            updated = re.sub(r"(?<![\w./@-])" + re.escape(image) + r"(?![\w.:/@-])", pinned, updated)
        if updated != text:
            with open(path, "w", encoding="utf-8") as f:
                f.write(updated)
            changed += 1
            print(f"pinned in {relative}")
    return changed


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--pin", action="store_true")
    mode.add_argument("--write-ratchet", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options.list:
        for relative, what in unpinned(options.root):
            print(f"{relative}: {what}")
        return 0
    if options.write_ratchet:
        entries = [{"file": f, "input": i} for f, i in unpinned(options.root)]
        with open(os.path.join(options.root, RATCHET), "w", encoding="utf-8") as f:
            json.dump({"_comment": [
                "Inputs the build fetches by name, not by content, that are not pinned yet.",
                "pinned_inputs.py --check fails on one that is not listed here, and on one listed",
                "here that is pinned by now: this list only shrinks. --pin pins the images."],
                "unpinned": entries}, f, indent=2)
            f.write("\n")
        return 0
    if options.pin:
        pin(options.root)
        return 0
    new, done = check(options.root)
    annotate = bool(os.environ.get("GITHUB_ACTIONS"))
    for relative, what in new:
        print(f"not pinned: {relative}: {what}")
        if annotate:
            print(f"::error file={relative},title=unpinned input::{what} - pin it by digest or checksum")
    for relative, what in done:
        print(f"pinned now, take it off {RATCHET}: {relative}: {what}")
        if annotate:
            print(f"::error file={RATCHET},title=pinned input still listed::{relative}: {what}")
    return 1 if new or done else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
