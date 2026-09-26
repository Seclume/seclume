#!/bin/bash
# The Quarkus native check on a Linux machine with podman:
#   1. build the image from target/native-sources (made on any OS with
#      mvn -f seclume-quarkus/native-it package -Dnative -Dquarkus.native.sources-only=true)
#   2. run it against the four databases, with the passwords named by file
#   3. search the heap dump it wrote for each password - and, as the control
#      that the search reads a native dump at all, for the user name, which
#      must be found.
# Layout under $DIR: src/ (native-sources), pw/{pg,mysql,mssql,oracle}, tck.jar
#   native.sh <DIR> <database host> [pg port]
set -u
DIR=$1; DB=$2; PGPORT=${3:-5433}
IMG=ghcr.io/graalvm/native-image-community:25
cd "$DIR" || exit 2
echo "== build"
podman run --rm --memory 5g -v "$DIR/src:/work:z" -w /work $IMG @native-image.args > build.log 2>&1
tail -3 build.log
BIN=$(ls src/*-runner 2>/dev/null | head -1)
[ -x "$BIN" ] || { echo "no image built"; exit 1; }
ls -la "$BIN" | awk '{print "image:", $5, "bytes"}'
echo "== run"
rm -f heap.hprof
podman run --rm -v "$DIR:/work:z" -v "$DIR/pw:/pw:ro,z" --entrypoint "/work/$BIN" \
  -e SECLUME_PG_URL="jdbc:seclume:postgresql://$DB:$PGPORT/seclume_test?user=seclume_test&tls=off&provider=file&path=/pw/pg" \
  -e SECLUME_MYSQL_URL="jdbc:seclume:mysql://$DB:3307/seclume_test?user=seclume_test&tls=off&allowPublicKeyRetrieval=true&provider=file&path=/pw/mysql" \
  -e SECLUME_MSSQL_URL="jdbc:seclume:sqlserver://$DB:1433/master?user=sa&trustServerCertificate=true&provider=file&path=/pw/mssql" \
  -e SECLUME_ORACLE_URL="jdbc:seclume:oracle://$DB:1521/FREEPDB1?user=seclume_test&provider=file&path=/pw/oracle" \
  $IMG /work/heap.hprof 2>&1 | grep -E '^(ok|FAIL|native image|heap dumped)'
[ -s heap.hprof ] || { echo "no heap dump"; exit 1; }
ls -la heap.hprof | awk '{print "heap dump:", $5, "bytes"}'
echo "== search"
scan() { podman run --rm -v "$DIR:/work:z" -v "$DIR/pw:/pw:ro,z" --entrypoint java $IMG \
  -cp /work/tck.jar space.seclume.tck.ScanDump /work/heap.hprof "$1" > /dev/null 2>&1; echo $?; }
printf 'seclume_test' > control; chmod 644 control
[ "$(scan /work/control)" = 1 ] && echo "ok   control: the user name is found in the native dump" \
  || echo "FAIL control: the search does not see the dump"
for db in pg mysql mssql oracle; do
  case $(scan /pw/$db) in
    0) echo "ok   $db: the password is not in the heap" ;;
    1) echo "FAIL $db: the password IS in the heap" ;;
    *) echo "FAIL $db: the search did not run" ;;
  esac
done
rm -f control heap.hprof
