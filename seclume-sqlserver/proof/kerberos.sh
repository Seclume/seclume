#!/bin/bash
# SQL Server's integrated login (Kerberos) against an Active Directory - all
# in containers, rootless podman, nothing on the host changed:
#   a Samba AD domain controller for SECLUME.TEST, SQL Server 2022 knowing the
#   domain through a keytab and a privileged account, and a client that holds
#   a ticket for "alice" and no password of any database.
#   kerberos.sh up | run <seclume-core.jar> <seclume-sqlserver.jar> | down
# Run on 26.09.2026: logged in as SECLUME\alice, the server reports
# auth_scheme KERBEROS; without a ticket, refused.
#
# What it took, so nobody has to find it again:
#  - rootless podman may not write security.NTACL: provision with
#    acl_xattr:security_acl_name = user.NTACL
#  - SQL Server resolves the NetBIOS name (SECLUME) through DNS with the search
#    domain - seclume.seclume.test must exist - and wants reverse DNS for the DC
#  - no SSSD in the container: network.disablesssd = true
#  - /var/opt/mssql/secrets must be writable (the service master key lives there)
#  - /var/opt/mssql/logger.ini with security.kerberos/ldap at Debug says why
set -e
D=/tmp/seclume-ad
NET=sadnet
case "$1" in
up)
  mkdir -p $D/secrets && chmod 700 $D && cd $D
  pw() { head -c 18 /dev/urandom | base64 | tr -d '/+=' | sed 's/^/Aa1-/' > $1; chmod 600 $1; }
  pw admin.pw; pw sqlsvc.pw; pw alice.pw; pw sa.pw
  printf 'FROM docker.io/library/debian:12\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq samba winbind krb5-user dnsutils >/dev/null && rm -f /etc/samba/smb.conf\n' > Dcfile
  printf 'FROM docker.io/library/eclipse-temurin:25-jdk\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq krb5-user libgssapi-krb5-2 >/dev/null\n' > Clientfile
  podman build -q -t seclume-samba-dc -f Dcfile . >/dev/null
  podman build -q -t seclume-krb-client -f Clientfile . >/dev/null
  podman network exists $NET || podman network create --subnet 10.98.0.0/24 --disable-dns $NET >/dev/null
  podman run -d --name seclume-dc --hostname dc.seclume.test --network $NET:ip=10.98.0.10 \
    --dns 10.98.0.10 seclume-samba-dc sleep infinity >/dev/null
  for f in admin sqlsvc alice; do podman cp $f.pw seclume-dc:/$f.pw; done
  podman exec seclume-dc sh -c '
    A="$(cat /admin.pw)"
    samba-tool domain provision --realm=SECLUME.TEST --domain=SECLUME --server-role=dc \
      --dns-backend=SAMBA_INTERNAL --adminpass="$A" --host-ip=10.98.0.10 \
      --option="acl_xattr:security_acl_name = user.NTACL" >/dev/null 2>&1
    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf; samba -D; sleep 5
    for u in sqlsvc alice; do samba-tool user create $u "$(cat /$u.pw)" >/dev/null
      samba-tool user setexpiry $u --noexpiry >/dev/null; done
    samba-tool spn add MSSQLSvc/sql.seclume.test:1433 sqlsvc
    samba-tool spn add MSSQLSvc/sql.seclume.test sqlsvc
    samba-tool dns zonecreate 127.0.0.1 0.98.10.in-addr.arpa -U Administrator --password="$A" >/dev/null 2>&1
    for r in "sql 20" "client 30" "seclume 10"; do set -- $r
      samba-tool dns add 127.0.0.1 seclume.test $1 A 10.98.0.$2 -U Administrator --password="$A" >/dev/null 2>&1; done
    for r in "10 dc" "20 sql" "30 client"; do set -- $r
      samba-tool dns add 127.0.0.1 0.98.10.in-addr.arpa $1 PTR $2.seclume.test -U Administrator --password="$A" >/dev/null 2>&1; done
    for p in sqlsvc@SECLUME.TEST MSSQLSvc/sql.seclume.test:1433@SECLUME.TEST MSSQLSvc/sql.seclume.test@SECLUME.TEST; do
      samba-tool domain exportkeytab /mssql.keytab --principal=$p >/dev/null; done
    rm /admin.pw /sqlsvc.pw'
  podman cp seclume-dc:/mssql.keytab secrets/mssql.keytab
  chmod 777 secrets; chmod 644 secrets/mssql.keytab
  printf '[libdefaults]\n default_realm = SECLUME.TEST\n dns_lookup_kdc = false\n rdns = false\n[realms]\n SECLUME.TEST = {\n  kdc = dc.seclume.test\n }\n[domain_realm]\n .seclume.test = SECLUME.TEST\n' > krb5.conf
  printf '[network]\nprivilegedadaccount = sqlsvc\nkerberoskeytabfile = /var/opt/mssql/secrets/mssql.keytab\ndisablesssd = true\nenablekdcfromkrb5conf = true\n' > mssql.conf
  printf '[Output:sql]\nType = File\nFilename = /var/opt/mssql/log/security.log\n[Logger]\nLevel = Silent\n[Logger:security.kerberos]\nLevel = Debug\nOutputs = sql\n[Logger:security.ldap]\nLevel = Debug\nOutputs = sql\n' > logger.ini
  printf 'ACCEPT_EULA=Y\nMSSQL_SA_PASSWORD=%s\n' "$(cat sa.pw)" > sql.env; chmod 600 sql.env
  chmod 644 krb5.conf mssql.conf logger.ini
  podman run -d --name seclume-sql --hostname sql.seclume.test --network $NET:ip=10.98.0.20 \
    --dns 10.98.0.10 --dns-search seclume.test --env-file sql.env --memory 2g \
    -v $D/krb5.conf:/etc/krb5.conf:ro,z -v $D/mssql.conf:/var/opt/mssql/mssql.conf:ro,z \
    -v $D/logger.ini:/var/opt/mssql/logger.ini:ro,z -v $D/secrets:/var/opt/mssql/secrets:z \
    mcr.microsoft.com/mssql/server:2022-latest >/dev/null
  sleep 35
  podman cp sa.pw seclume-sql:/tmp/sa.pw
  podman exec seclume-sql bash -c 'S=$(ls -d /opt/mssql-tools*/bin | head -1)
    $S/sqlcmd -C -S localhost -U sa -P "$(cat /tmp/sa.pw)" -b -Q "CREATE LOGIN [SECLUME\alice] FROM WINDOWS; GRANT VIEW SERVER STATE TO [SECLUME\alice]" >/dev/null; rm /tmp/sa.pw'
  podman run -d --name seclume-krb-client --hostname client.seclume.test \
    --network $NET:ip=10.98.0.30 --dns 10.98.0.10 --dns-search seclume.test \
    -v $D/krb5.conf:/etc/krb5.conf:ro,z seclume-krb-client sleep infinity >/dev/null
  echo "up: domain SECLUME.TEST, sql.seclume.test knows SECLUME\\alice"
  ;;
run)
  for j in "$2" "$3" "$(dirname "$0")/KerberosProof.java"; do podman cp "$j" seclume-krb-client:/tmp/; done
  podman cp $D/alice.pw seclume-krb-client:/tmp/alice.pw
  CP=/tmp/$(basename "$2"):/tmp/$(basename "$3")
  J="java --enable-native-access=ALL-UNNAMED -cp $CP /tmp/KerberosProof.java"
  podman exec seclume-krb-client bash -c "kinit alice < /tmp/alice.pw >/dev/null; rm /tmp/alice.pw
    echo '== with a ticket for alice'; $J 2>&1 | grep PROOF
    kdestroy; echo '== without a ticket'; $J 2>&1 | grep PROOF"
  ;;
down)
  podman rm -f seclume-krb-client seclume-sql seclume-dc >/dev/null 2>&1 || true
  podman network rm $NET >/dev/null 2>&1 || true
  shred -u $D/*.pw $D/sql.env $D/secrets/mssql.keytab 2>/dev/null || true
  rm -rf $D
  echo "removed"
  ;;
esac
