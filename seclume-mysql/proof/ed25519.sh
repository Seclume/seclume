#!/bin/sh
# A MariaDB with its two key-based logins, for LocalMariaDbEd25519Test:
#
#   ed25519.sh up [port]   MariaDB 11.8 on <port> (default 3309) with auth_ed25519 and
#                          auth_parsec, users ed_user (client_ed25519) and parsec_user
#                          (parsec), both with one password written to $D/password,
#                          to be copied unread
#   ed25519.sh down        all of it removed
set -eu
D=/tmp/seclume-mariadb-ed25519
NAME=seclume-mariadb-ed25519
case "$1" in
up)
  PORT=${2:-3309}
  mkdir -p $D && chmod 700 $D
  head -c 18 /dev/urandom | base64 | tr -d '/+=' > $D/password
  head -c 18 /dev/urandom | base64 | tr -d '/+=' > $D/root
  chmod 600 $D/password $D/root
  printf 'MARIADB_ROOT_PASSWORD=%s\nMARIADB_DATABASE=seclume\n' "$(cat $D/root)" > $D/env
  chmod 600 $D/env
  podman run -d --name $NAME -p $PORT:3306 --env-file $D/env docker.io/library/mariadb:11.8 \
    >/dev/null
  shred -u $D/env
  for i in $(seq 1 60); do
    podman exec -e MYSQL_PWD="$(cat $D/root)" $NAME mariadb -uroot -e 'select 1' \
      >/dev/null 2>&1 && break
    sleep 2
  done
  # The statements go in on stdin: no password on a command line.
  { printf "INSTALL SONAME 'auth_ed25519';\nINSTALL SONAME 'auth_parsec';\n"
    printf "CREATE USER ed_user@'%%' IDENTIFIED VIA ed25519 USING PASSWORD('%s');\n" \
      "$(cat $D/password)"
    printf "CREATE USER parsec_user@'%%' IDENTIFIED VIA parsec USING PASSWORD('%s');\n" \
      "$(cat $D/password)"
    printf "GRANT ALL ON seclume.* TO ed_user@'%%', parsec_user@'%%';\n"
    # so the test can read which plugin the server holds for the session's user
    printf "GRANT SELECT ON mysql.global_priv TO ed_user@'%%', parsec_user@'%%';\n"
  } | podman exec -i -e MYSQL_PWD="$(cat $D/root)" $NAME mariadb -uroot
  echo "up: MariaDB 11.8 on $PORT, ed_user (ed25519) and parsec_user (parsec)"
  ;;
down)
  podman rm -f $NAME >/dev/null 2>&1 || true
  find $D -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf $D
  echo "removed"
  ;;
esac
