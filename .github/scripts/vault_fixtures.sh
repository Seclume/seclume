#!/usr/bin/env bash
# HashiCorp Vault with its database secrets engine in front of a PostgreSQL of
# its own: Vault in dev mode with TLS on 8210, PostgreSQL 17 with TLS on 5440,
# the role "app" creating a database user per credential (default_ttl 20s,
# max_ttl 60s - short, so that a test sees a renewal and a cap).
#
# Two login methods besides the root token, for VaultLogin: AppRole (the role
# "app") and JWT (the role "app", trusting an RSA key made here), both with a
# policy that may read database/creds/app and nothing else, and a token TTL of
# 30s (max 90s) so that a test sees the token renewed and replaced.
#
# Writes into the working directory: .local-vault-token (the root token of
# this throwaway server), .local-vault-role-id and .local-vault-secret-id (the
# AppRole login), .local-vault-jwt (a JWT the JWT mount accepts),
# .local-vault-pki-ca.pem (the root of the PKI engine at pki/, whose role
# "client" signs client certificates under seclume.test - and which
# PostgreSQL trusts for orders.seclume.test's certificate login). The
# PostgreSQL password stays in the work directory, read by Vault from its file
# and by nobody else.
#
# VAULT_IMAGE and VAULT_CLI choose the server: HashiCorp Vault by default,
# OpenBao with VAULT_IMAGE=quay.io/openbao/openbao:2.7.2 VAULT_CLI=bao - the same
# API, the same fixture.
#
#   .github/scripts/vault_fixtures.sh <work directory> [address the tests use]
set -euo pipefail
work=$(mkdir -p "${1:?usage: vault_fixtures.sh <work directory> [address]}" && cd "$1" && pwd)
address=${2:-127.0.0.1}
vault_image=${VAULT_IMAGE:-docker.io/hashicorp/vault:1.20}
vault_cli=${VAULT_CLI:-vault}
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
# The JWT login: an RSA key whose public half Vault's JWT mount trusts, and one
# RS256 token signed with it here (an hour, audience "vault"). openssl's
# PKCS#1 v1.5 signature is already the form a JWT carries.
b64url() { base64 | tr -d '=\n' | tr '/+' '_-'; }
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt.key 2>/dev/null
openssl pkey -in jwt.key -pubout -out jwt.pub
now=$(date +%s)
jwt_head=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
jwt_body=$(printf '{"iss":"seclume-ci","sub":"ci-app","aud":"vault","iat":%d,"nbf":%d,"exp":%d}' \
  "$now" "$((now - 60))" "$((now + 3600))" | b64url)
jwt_sig=$(printf '%s.%s' "$jwt_head" "$jwt_body" | openssl dgst -sha256 -sign jwt.key -binary | b64url)
printf '%s.%s.%s' "$jwt_head" "$jwt_body" "$jwt_sig" > jwt
rm -f jwt.key
chmod 400 pg.key pgpw token jwt
chmod 444 jwt.pub
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
  --group-add 1000 -v "$work":/certs:ro,z -e CLI="$vault_cli" --entrypoint sh "$vault_image" -c \
  'exec "$CLI" server -dev -dev-tls -dev-listen-address=0.0.0.0:8200 \
     -dev-root-token-id="$(cat /certs/token)"' >/dev/null

vault() { # the CLI inside the container, the token from its file; both spellings
          # of the environment, Vault's and OpenBao's
  docker exec -i slm-vault sh -c 'T=$(cat /certs/token); VAULT_TOKEN=$T BAO_TOKEN=$T \
    VAULT_ADDR=https://127.0.0.1:8200 BAO_ADDR=https://127.0.0.1:8200 \
    VAULT_SKIP_VERIFY=1 BAO_SKIP_VERIFY=1 '"$vault_cli"' "$@"' vault "$@"
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

# The login methods. Their tokens may read the credential, renew and give back
# its lease - nothing else; renew-self and revoke-self come with the default
# policy.
vault policy write db-app - >/dev/null <<'POLICY'
path "database/creds/app" { capabilities = ["read"] }
path "sys/leases/renew"   { capabilities = ["update"] }
path "sys/leases/revoke"  { capabilities = ["update"] }
path "pki/sign/client"    { capabilities = ["update"] }
POLICY
vault auth enable approle >/dev/null
vault write auth/approle/role/app token_policies=db-app token_ttl=30s token_max_ttl=90s \
  secret_id_ttl=1h >/dev/null
vault auth enable jwt >/dev/null
vault write auth/jwt/config jwt_validation_pubkeys=@/certs/jwt.pub bound_issuer=seclume-ci >/dev/null
vault write auth/jwt/role/app role_type=jwt user_claim=sub bound_audiences=vault \
  bound_subject=ci-app token_policies=db-app token_ttl=30s token_max_ttl=90s >/dev/null

# The PKI engine, for seclume-keys' certificates: a root CA made inside Vault
# and a role that signs client certificates under seclume.test, for a key
# whose request it is given (pki/sign) - an hour at most.
vault secrets enable pki >/dev/null
vault secrets tune -max-lease-ttl=24h pki >/dev/null
vault write -field=certificate pki/root/generate/internal common_name="seclume CI PKI" \
  ttl=24h > .local-vault-pki-ca.pem
vault write pki/roles/client allowed_domains=seclume.test allow_subdomains=true \
  max_ttl=1h client_flag=true server_flag=false key_type=any >/dev/null
# And PostgreSQL trusts that root for client certificates: orders.seclume.test
# logs in by its certificate alone (cert), before every other hba line.
install -m 444 .local-vault-pki-ca.pem "$work/pki-ca.pem"
pg() { docker exec -u postgres slm-vault-pg psql -v ON_ERROR_STOP=1 -tAq "$@"; }
pg -c "ALTER SYSTEM SET ssl_ca_file = '/certs/pki-ca.pem'" \
  -c 'CREATE ROLE "orders.seclume.test" LOGIN'
hba=$(pg -c 'SHOW hba_file')
docker exec -u postgres slm-vault-pg sed -i \
  '1i hostssl all "orders.seclume.test" all cert' "$hba"
pg -c 'SELECT pg_reload_conf()' >/dev/null

sudo cat "$work/token" > .local-vault-token
sudo cat "$work/jwt" > .local-vault-jwt
vault read -field=role_id auth/approle/role/app/role-id > .local-vault-role-id
vault write -f -field=secret_id auth/approle/role/app/secret-id > .local-vault-secret-id
cp "$work/ca.pem" .local-vault-pg-ca.pem
echo "$vault_cli on 8210 (dev, TLS), database/creds/app for PostgreSQL 17 on 5440," \
  "logins: approle, jwt; pki/sign/client"
