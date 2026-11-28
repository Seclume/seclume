#!/bin/sh
# heapcheck --in-target against a hostile target: links it plants in its own
# file system must not lead the check - run as root - into this one.
#
#   sudo ./run-rooted.sh <seclume-heapcheck jar> [java]
#
# A container plants /tmp/evil -> /root/rf-host (absolute), a FIFO and a
# magic link to /proc/1/root. /root/rf-host exists here too, with other
# content. The plain path through /proc/<pid>/root reads this host's file (the
# control); RootedFiles must read the container's, leave this host's victim
# file alone, refuse the FIFO without blocking and refuse the magic link.
set -eu
jar=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
java=${2:-java}
name=seclume-rooted
host=/root/rf-host
trap 'podman rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$host"' EXIT
mkdir -p "$host"
echo "HOST - the check left the container" > "$host/marker.txt"
echo "host victim" > "$host/victim.txt"
podman run -d --name "$name" docker.io/library/alpine:3 sleep 300 >/dev/null
podman exec "$name" sh -c "mkdir -p $host && echo CONTAINER > $host/marker.txt \
  && ln -s $host /tmp/evil && mkfifo /tmp/fifo && ln -s /proc/1/root /tmp/magic \
  && echo own > /tmp/own.txt"
pid=$(podman inspect -f '{{.State.Pid}}' "$name")
"$java" --enable-native-access=ALL-UNNAMED -cp "$jar" "$(dirname "$0")/RootedFilesProof.java" "$pid"
echo "PROOF host victim still there: $([ -f "$host/victim.txt" ] && echo yes || echo NO)"
