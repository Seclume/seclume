#!/usr/bin/env bash
# kind_load.sh <cluster> <image>...: puts images from the local Docker into a
# kind cluster, pulling those that are not there.
#
# Not `kind load docker-image`: with Docker's containerd image store (the
# default from Docker 29, as on the Ubuntu 26.04 runners) an image pulled
# from a registry is an index of every platform with the blobs of one, and
# the archive that command makes points at blobs it does not hold - the
# import in the node fails. An archive of this machine's platform alone has
# them all. Where `docker save` does not know --platform (Docker before 28),
# the plain archive is the same thing.
#
# On a failure the output goes to an ::error:: annotation, since a job's log
# is not always at hand.
set -euo pipefail
cluster=${1:?usage: kind_load.sh <cluster> <image>...}
shift
platform="linux/$(docker version -f '{{.Server.Arch}}')"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() {
  local what=$1 log=$2
  echo "::error title=kind_load ${what}::$(tail -c 1500 "$log" | tr '\n' ' ')"
  cat "$log" >&2
  exit 1
}
for image in "$@"; do
  log="$work/log"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker pull -q --platform "$platform" "$image" >"$log" 2>&1 || fail "pull $image" "$log"
  fi
  archive="$work/image.tar"
  if ! docker save --platform "$platform" -o "$archive" "$image" >"$log" 2>&1; then
    docker save -o "$archive" "$image" >"$log" 2>&1 || fail "save $image" "$log"
  fi
  kind load image-archive "$archive" --name "$cluster" >"$log" 2>&1 \
    || fail "load $image ($(docker version -f '{{.Server.Version}}'), $platform)" "$log"
  rm -f "$archive"
  echo "loaded $image into $cluster ($platform)"
done
