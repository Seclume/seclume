#!/bin/sh
# Does revoking a Vault database lease end the sessions already open with it?
# A throwaway Vault (dev mode) and PostgreSQL in one podman pod, random
# secrets that are never printed, everything removed at the end.
#
# Two roles: "plain" with Vault's default revocation, "terminating" with
# pg_terminate_backend in its revocation_statements. For each, a session runs
# a statement a second for 15 s; its lease is revoked after 2 s.
#
# Measured 27.11.2026 (Vault 1.20, PostgreSQL 17): "plain" - the user is
# dropped and new logins fail, but the running session carries on to its end;
# "terminating" - the session is ended at the revocation.
set -u
n=seclume-vrev
cleanup() {
  podman rm -f "$n-pg" "$n-vault" >/dev/null 2>&1
  podman pod rm -f "$n" >/dev/null 2>&1
}
cleanup
trap cleanup EXIT
pw=$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')
tok=$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')
podman pod create --name "$n" >/dev/null
podman run -d --pod "$n" --name "$n-pg" -e POSTGRES_PASSWORD="$pw" \
  docker.io/library/postgres:17@sha256:97fb53376be3e4fb1a8a61421daa69dcc3bf2fa39bda3259f5245f9a455af1a9 >/dev/null
podman run -d --pod "$n" --name "$n-vault" --cap-add IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID="$tok" docker.io/hashicorp/vault:1.20@sha256:268bb80aa9c6d13d65fcfa05c0c268caca068952240a8087291a6ce0b66e3a10 >/dev/null
for i in $(seq 1 30); do
  podman exec "$n-pg" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done
sleep 3
v() { podman exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$tok" "$n-vault" vault "$@"; }
v secrets enable database >/dev/null
v write database/config/pg plugin_name=postgresql-database-plugin allowed_roles='*' \
  connection_url='postgresql://{{username}}:{{password}}@127.0.0.1:5432/postgres?sslmode=disable' \
  username=postgres password="$pw" >/dev/null
create="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT pg_read_all_data TO \"{{name}}\";"
v write database/roles/plain db_name=pg creation_statements="$create" default_ttl=1h >/dev/null
v write database/roles/terminating db_name=pg creation_statements="$create" default_ttl=1h \
  revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";" >/dev/null

# The running session's work, as a file: no quoting through three shells.
cat > "${TMPDIR:-/tmp}/vrev-work.sql" <<'SQL'
DO $$ BEGIN FOR i IN 1..15 LOOP PERFORM pg_sleep(1); PERFORM count(*) FROM pg_class; END LOOP; END $$;
SQL
podman cp "${TMPDIR:-/tmp}/vrev-work.sql" "$n-pg:/tmp/work.sql"
rm -f "${TMPDIR:-/tmp}/vrev-work.sql"

field() { python3 -c "import sys, json; print(json.load(sys.stdin)$1)"; }
for role in plain terminating; do
  out=$(v read -format=json "database/creds/$role")
  user=$(echo "$out" | field '["data"]["username"]')
  lease=$(echo "$out" | field '["lease_id"]')
  upw=$(echo "$out" | field '["data"]["password"]')
  podman exec -d -e PGPASSWORD="$upw" "$n-pg" sh -c \
    "psql -h 127.0.0.1 -U '$user' -d postgres -f /tmp/work.sql > /tmp/$role.out 2>&1; echo exit=\$? >> /tmp/$role.out"
  sleep 2
  v lease revoke "$lease" >/dev/null
  sleep 2
  newlogin=$(podman exec -e PGPASSWORD="$upw" "$n-pg" \
    psql -h 127.0.0.1 -U "$user" -d postgres -tAc "select 'login works'" 2>&1 | tail -1 | cut -c1-60)
  sleep 14
  session=$(podman exec "$n-pg" tail -1 "/tmp/$role.out")
  echo "$role: new login after revoke: $newlogin | running session: $session"
done
