#!/bin/sh
# The active role across the pool's reset, on MariaDB - which, like MySQL,
# keeps it through COM_RESET_CONNECTION and has no SET ROLE DEFAULT.
#
#   ./mariadb-roles.sh <dir with seclume-core.jar and seclume-mysql.jar>
#
# A throwaway MariaDB 11.4 with random passwords (never printed). Two runs of
# MariaRoleProbe: a login with no role whose borrower sets one, and a login
# with a default role whose borrower drops it. "after reset" must be the
# login's role both times (measured 27.11.2026: null, then probe_role).
set -eu
jars=$(cd "$1" && pwd)
work=$(mktemp -d)
cleanup() {
  podman rm -f seclume-maria >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
cp "$jars"/seclume-core.jar "$jars"/seclume-mysql.jar "$(dirname "$0")/MariaRoleProbe.java" "$work/"
head -c 18 /dev/urandom | base64 | tr -d '/+=\n' > "$work/pw"
chmod 644 "$work/pw"
rpw=$(head -c 18 /dev/urandom | base64 | tr -d '/+=\n')
podman run -d --name seclume-maria -p 127.0.0.1:3399:3306 -e MARIADB_ROOT_PASSWORD="$rpw" \
  docker.io/library/mariadb:11.4 >/dev/null
sleep 5
for i in $(seq 1 90); do
  podman logs seclume-maria 2>&1 | grep -q "ready for connections.*port: 3306" \
    && podman exec seclume-maria mariadb -uroot -p"$rpw" -e "select 1" >/dev/null 2>&1 && break
  sleep 1
done
sleep 2
root() { podman exec seclume-maria mariadb -uroot -p"$rpw" -e "$1"; }
root "create user prober@'%' identified by '$(cat "$work/pw")'; create role probe_role;
      grant select on mysql.* to probe_role; grant probe_role to prober@'%';"
probe() {
  podman run --rm --network host -v "$work":/work:Z docker.io/library/eclipse-temurin:25-jdk \
    java --enable-native-access=ALL-UNNAMED -Dseclume.secret.providers=file \
    -cp /work/seclume-core.jar:/work/seclume-mysql.jar /work/MariaRoleProbe.java "$1" | grep PROOF
}
echo "== a login without a role; the borrower sets probe_role"
probe probe_role
root "set default role probe_role for prober@'%'"
echo "== a login with the default role probe_role; the borrower sets none"
probe none
