#!/bin/bash
# aurora=true against a stand-in: no Aurora here, but what the driver relies on
# - aurora_replica_status() on every instance, a cluster endpoint that is a DNS
# name for the writer - built from a PostgreSQL primary and a streaming replica.
#   aurora.sh run <seclume-core.jar> <seclume-postgresql.jar>    aurora.sh down
# The failover: inst-a (the writer, and what cluster.aur.test resolves to) is
# stopped, inst-b promoted and marked the writer in the stand-in's table.
set -e
D=/tmp/seclume-aurora
NET=aurnet
IMG=docker.io/library/postgres:17
case "$1" in
run)
  mkdir -p $D && chmod 700 $D
  head -c 18 /dev/urandom | base64 | tr -d '/+=' > $D/pw; chmod 644 $D/pw
  podman network exists $NET || podman network create $NET >/dev/null
  podman run -d --name inst-a --network $NET --network-alias inst-a.aur.test \
    --network-alias cluster.aur.test -e POSTGRES_PASSWORD_FILE=/pw -v $D/pw:/pw:ro,z $IMG \
    -c cluster_name=inst-a -c wal_level=replica -c password_encryption=scram-sha-256 >/dev/null
  sleep 6
  cat > $D/standin.sql <<'SQL'
create table aurora_standin (server_id text, session_id text);
insert into aurora_standin values ('inst-a', 'MASTER_SESSION_ID'), ('inst-b', 'replica');
create function aurora_replica_status() returns table (server_id text, session_id text,
    last_update_timestamp timestamptz) language sql as
  $$ select server_id, session_id, now() from aurora_standin $$;
SQL
  cat > $D/failover.sql <<'SQL'
update aurora_standin set session_id = case server_id when 'inst-b'
    then 'MASTER_SESSION_ID' else 'replica' end;
SQL
  chmod 644 $D/*.sql
  podman cp $D/standin.sql inst-a:/tmp/standin.sql
  podman exec -u postgres inst-a sh -c 'echo "host replication all all scram-sha-256" >> $PGDATA/pg_hba.conf
    psql -qc "select pg_reload_conf()" >/dev/null; psql -q -f /tmp/standin.sql'
  podman run -d --name inst-b --network $NET --network-alias inst-b.aur.test \
    -v $D/pw:/pw:ro,z --entrypoint bash $IMG -c '
      export PGPASSWORD=$(cat /pw)
      until pg_basebackup -h inst-a.aur.test -U postgres -D /var/lib/postgresql/data -R -X stream 2>/dev/null; do sleep 1; done
      chown -R postgres /var/lib/postgresql/data; chmod 700 /var/lib/postgresql/data
      exec gosu postgres postgres -c cluster_name=inst-b' >/dev/null
  sleep 8
  podman run -d --name aur-client --network $NET -v $D/pw:/pw:ro,z \
    docker.io/library/eclipse-temurin:25-jdk sleep infinity >/dev/null
  for f in "$2" "$3" "$(dirname "$0")/AuroraProof.java"; do podman cp "$f" aur-client:/tmp/; done
  CP=/tmp/$(basename "$2"):/tmp/$(basename "$3")
  podman exec -d aur-client sh -c "java --enable-native-access=ALL-UNNAMED -cp $CP /tmp/AuroraProof.java > /tmp/out 2>&1"
  until podman exec aur-client test -f /tmp/ready; do sleep 1; done
  podman stop -t 2 inst-a >/dev/null
  podman cp $D/failover.sql inst-b:/tmp/failover.sql
  podman exec -u postgres inst-b sh -c 'pg_ctl promote -D /var/lib/postgresql/data >/dev/null; sleep 3
    psql -q -f /tmp/failover.sql'
  podman exec aur-client touch /tmp/go
  sleep 12
  podman exec aur-client grep PROOF /tmp/out
  ;;
down)
  podman rm -f aur-client inst-b inst-a >/dev/null 2>&1 || true
  podman network rm $NET >/dev/null 2>&1 || true
  rm -rf $D
  echo removed
  ;;
esac
