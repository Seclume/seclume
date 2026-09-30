#!/bin/sh
# Oracle's Windows native authentication (NTS), end to end. NTS exists only on a
# database server running Windows, so this starts a Windows Server 2022 VM
# (docker.io/dockurr/windows, needs /dev/kvm) with Oracle Database Free for
# Windows; inside it, the proof logs in as the local user 'seclume' with
# authentication=nts - no user, no password in the URL - and a local user the
# database does not know is refused.
#
#   nts.sh up <dir with seclume-core.jar and seclume-oracle.jar>
#        downloads Oracle Free for Windows and a JDK, starts the VM; the install
#        and the proof then run unattended inside it (about 20 minutes)
#   nts.sh wait        waits for the proof's output and prints it
#   nts.sh run <dir>   runs the proof again with new jars, without a new VM
#   nts.sh down        removes the VM, its disk and the downloads
set -eu
DIR=/home/seclume-ntsvm            # not /tmp: Windows and Oracle need some 40 GB
HERE=$(cd "$(dirname "$0")" && pwd)
ORACLE=https://download.oracle.com/otn-pub/otn_software/db-express/WINDOWS.X64_239000_free.zip
JDK=https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip

secret() { head -c 12 /dev/urandom | base64 | tr -d '/+='; }

case "${1:-}" in
up)
  umask 077
  mkdir -p $DIR/oem $DIR/data $DIR/storage
  [ -f $DIR/oem/oracle.zip ] || curl -sSfL -o $DIR/oem/oracle.zip $ORACLE
  [ -f $DIR/oem/jdk.zip ] || curl -sSfL -o $DIR/oem/jdk.zip $JDK
  cp "$2/seclume-core.jar" "$2/seclume-oracle.jar" "$HERE/NtsProof.java" \
     "$HERE"/nts/install.bat "$HERE"/nts/setup.ps1 "$HERE"/nts/runner.ps1 "$HERE"/nts/proof.ps1 \
     $DIR/oem/
  for f in vm ora stranger; do [ -f $DIR/oem/$f.pw ] || secret > $DIR/oem/$f.pw; done
  chmod -R a+rX $DIR/oem
  podman run -d --name seclume-ntsvm --device /dev/kvm --device /dev/net/tun --cap-add NET_ADMIN \
    --stop-timeout 120 -e VERSION=2022 -e RAM_SIZE=5G -e CPU_CORES=2 -e DISK_SIZE=64G \
    -e USERNAME=seclume -e PASSWORD="$(cat $DIR/oem/vm.pw)" \
    -v $DIR/storage:/storage:z -v $DIR/oem:/oem:z -v $DIR/data:/data:z \
    -p 127.0.0.1:18007:8006 docker.io/dockurr/windows >/dev/null
  echo "VM starting - installs Windows, then Oracle (about 20 minutes); console on 127.0.0.1:18007"
  ;;
wait)
  for i in $(seq 1 240); do
    [ -f $DIR/data/proof.txt ] && break
    podman ps --format '{{.Names}}' | grep -q '^seclume-ntsvm$' || { echo "VM gone"; exit 1; }
    sleep 30
  done
  iconv -f UTF-16 -t UTF-8 $DIR/data/proof.txt | tr -d '\r'    # PowerShell 5 writes UTF-16
  ;;
run)
  cp "$2/seclume-core.jar" "$2/seclume-oracle.jar" "$HERE/NtsProof.java" "$HERE/nts/proof.ps1" \
     $DIR/data/
  cat > $DIR/data/run.ps1 <<'PS'
Copy-Item -Force \\host.lan\Data\seclume-core.jar, \\host.lan\Data\seclume-oracle.jar, \\host.lan\Data\NtsProof.java C:\work\
Copy-Item -Force \\host.lan\Data\proof.ps1 C:\OEM\
& C:\OEM\proof.ps1
PS
  before=$(ls $DIR/data | grep -c '^run-' || true)
  for i in $(seq 1 60); do
    [ "$(ls $DIR/data | grep -c '^run-' || true)" -gt "$before" ] && break
    sleep 5
  done
  iconv -f UTF-16 -t UTF-8 "$DIR/data/$(ls $DIR/data | grep '^run-' | sort | tail -1)" | tr -d '\r'
  ;;
down)
  podman rm -f -t 30 seclume-ntsvm >/dev/null 2>&1 || true
  rm -rf $DIR
  ;;
*)
  echo "usage: $0 up <jars> | wait | run <jars> | down" >&2
  exit 2
  ;;
esac
