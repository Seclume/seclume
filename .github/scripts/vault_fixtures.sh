#!/usr/bin/env bash
# HashiCorp Vault with its database secrets engine in front of a PostgreSQL of
# its own: Vault in dev mode with TLS on 8210, PostgreSQL 17 with TLS on 5440,
# the role "app" creating a database user per credential (default_ttl 20s,
# max_ttl 60s - short, so that a test sees a renewal and a cap).
#
# Writes .local-vault-token (Vault's root token for this throwaway server) into
# the working directory; the PostgreSQL password stays in the work directory,
# read by Vault from its file and by nobody else.
#
#   .github/scripts/vault_fixtures.sh <work directory> [address the tests use]
set -euo pipefail
work=$(mkdir -p "${1:?usage: vault_fixtures.sh <work directory> [address]}" && cd "$1" && pwd)
address=${2:-127.0.0.1}
vault_image=docker.io/hashicorp/vault:1.20
pg_image=docker.io/library/postgres:17
net=slm-vault

cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=seclume CI vault pg CA" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=slm-vault-pg" \
  -keyout pg.key -out pg.csr 2>/dev/null
san="DNS:localhost,IP:127.0.0.1,DNS:slm-vault-pg"
case "$address" in
  *[!0-9.]*) san="$san,DNS:$address" ;;
  127.0.0.1) ;;
  *) san="$san,IP:$address" ;;
esac
printf 'subjectAltName=%s\n' "$san" > ext
openssl x509 -req -in pg.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile ext -out pg.crt 2>/dev/null
rm -f ca.key pg.csr ext ca.srl
# No trailing newline: Vault reads the password file as it is (@file), the
# postgres entrypoint drops the newline - and the two would not agree.
head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > pgpw
head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > token
chmod 400 pg.key pgpw token
chmod 444 pg.crt ca.pem
# postgres runs as 999 and wants its key to itself; Vault (100) reads the password
# and the token through group 1000, which both containers are given.
sudo chown 999:1000 pg.key
sudo chown 100:1000 pgpw token
sudo chmod 440 pgpw token
cd - >/dev/null

docker network create "$net" >/dev/null 2>&1 || true
docker run -d --name slm-vault-pg --hostname slm-vault-pg --network "$net" -p 5440:5432 \
  --group-add 1000 -v "$work":/certs:ro,z -e POSTGRES_PASSWORD_FILE=/certs/pgpw "$pg_image" \
  -c ssl=on -c ssl_cert_file=/certs/pg.crt -c ssl_key_file=/certs/pg.key >/dev/null
docker run -d --name slm-vault --network "$net" -p 8210:8200 --cap-add IPC_LOCK \
  --group-add 1000 -v "$work":/certs:ro,z --entrypoint sh "$vault_image" -c \
  'exec vault server -dev -dev-tls -dev-listen-address=0.0.0.0:8200 \
     -dev-root-token-id="$(cat /certs/token)"' >/dev/null

vault() { # vault CLI inside the container, the token from its file
  docker exec slm-vault sh -c 'VAULT_TOKEN=$(cat /certs/token) VAULT_ADDR=https://127.0.0.1:8200 \
    VAULT_SKIP_VERIFY=1 vault "$@"' vault "$@"
}
for _ in $(seq 1 60); do
  vault status >/dev/null 2>&1 && break
  sleep 1
done
for _ in $(seq 1 60); do
  docker exec slm-vault-pg pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done
sleep 2

vault secrets enable database >/dev/null
# The admin password goes in from its file (@), never on a command line.
vault write database/config/pg plugin_name=postgresql-database-plugin \
  connection_url='postgresql://{{username}}:{{password}}@slm-vault-pg:5432/postgres?sslmode=require' \
  allowed_roles=app username=postgres password=@/certs/pgpw >/dev/null
vault write database/roles/app db_name=pg default_ttl=20s max_ttl=60s \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT pg_read_all_data TO \"{{name}}\";" \
  revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";" >/dev/null

sudo cat "$work/token" > .local-vault-token
cp "$work/ca.pem" .local-vault-pg-ca.pem
echo "Vault on 8210 (dev, TLS), database/creds/app for PostgreSQL 17 on 5440"
