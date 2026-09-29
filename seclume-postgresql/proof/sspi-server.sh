#!/bin/sh
# The server side for proof/sspi.ps1 - a PostgreSQL login by Kerberos from
# Windows through SSPI, on a machine outside any domain:
#
#   sspi-server.sh up      an MIT KDC for SECLUME.TEST on the host's port 88
#                          (TCP and UDP) with alice and postgres/pg.seclume.test,
#                          and PostgreSQL 16 on port 15432 taking alice by gss.
#                          alice's password is written to $D/alice.pw, for the
#                          Windows side to hand to the LSA (runas /netonly).
#   sspi-server.sh down    all of it removed
#
# An MIT KDC and not Active Directory: Windows 11 24H2 and later, outside the
# domain, gets a TGT from a Samba AD KDC but no service ticket with it (seen
# with Samba 4.17 and 4.22 on 29.09.2026, klist get failing the same way) -
# from an MIT KDC it gets both.
set -eu
D=/tmp/seclume-sspi
NET=seclume-sspi
case "$1" in
up)
  mkdir -p $D && chmod 755 $D
  head -c 18 /dev/urandom | base64 | tr -d '/+=' > $D/alice.pw
  chmod 644 $D/alice.pw
  printf '[libdefaults]\n default_realm = SECLUME.TEST\n[realms]\n SECLUME.TEST = {\n  kdc = localhost\n }\n' > $D/krb5.conf
  printf '#!/bin/sh\nsed -i "1i host all alice all gss include_realm=0" "$PGDATA/pg_hba.conf"\npsql -U postgres -c "create role alice login"\n' > $D/init-gss.sh
  chmod 644 $D/krb5.conf $D/init-gss.sh
  podman network create $NET >/dev/null
  podman run -d --name seclume-sspi-kdc --network $NET -p 88:88/tcp -p 88:88/udp \
    -v $D:/shared:z docker.io/library/alpine:3.22 sh -c '
      apk add -q krb5-server krb5 >/dev/null
      cp /shared/krb5.conf /etc/krb5.conf
      kdb5_util create -s -r SECLUME.TEST -P "$(head -c 24 /dev/urandom | base64)" >/dev/null 2>&1
      kadmin.local -q "addprinc -pw $(cat /shared/alice.pw) alice" >/dev/null 2>&1
      kadmin.local -q "addprinc -randkey postgres/pg.seclume.test" >/dev/null 2>&1
      kadmin.local -q "ktadd -k /shared/pg.keytab postgres/pg.seclume.test" >/dev/null 2>&1
      chmod 644 /shared/pg.keytab
      exec krb5kdc -n' >/dev/null
  for i in $(seq 1 60); do [ -f $D/pg.keytab ] && break; sleep 1; done
  podman run -d --name seclume-sspi-pg --network $NET -p 15432:5432 -v $D:/shared:z \
    -e POSTGRES_PASSWORD="$(head -c 24 /dev/urandom | base64)" \
    -v $D/init-gss.sh:/docker-entrypoint-initdb.d/init-gss.sh:z \
    docker.io/library/postgres:16 -c krb_server_keyfile=/shared/pg.keytab >/dev/null
  for i in $(seq 1 60); do podman exec seclume-sspi-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
  sleep 3
  echo "up: KDC for SECLUME.TEST on 88, PostgreSQL on 15432 taking alice by gss"
  ;;
down)
  podman rm -f seclume-sspi-kdc seclume-sspi-pg >/dev/null 2>&1 || true
  podman network rm $NET >/dev/null 2>&1 || true
  find $D -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf $D
  echo "removed"
  ;;
esac
