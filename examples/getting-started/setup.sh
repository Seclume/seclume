#!/usr/bin/env bash
# Starts PostgreSQL and Vault with a random database password, stored in Vault.
# The password and the Vault token are in ./secrets, made here and never printed.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p secrets
# Readable by the containers' users; the folder is this example's own.
[ -s secrets/db-password ] || head -c 24 /dev/urandom | base64 | tr -d '\n=+/' > secrets/db-password
[ -s secrets/vault-token ] || head -c 24 /dev/urandom | base64 | tr -d '\n=+/' > secrets/vault-token
chmod 755 secrets && chmod 644 secrets/db-password secrets/vault-token
# Vault writes its dev CA here; its user is not ours.
mkdir -p secrets/vault-tls && chmod 777 secrets/vault-tls
docker compose up -d --wait db vault
docker compose exec -T vault sh -c 'VAULT_ADDR=https://127.0.0.1:8200 \
  VAULT_CACERT=/vault-tls/vault-ca.pem VAULT_TOKEN="$(cat /secrets/vault-token)" \
  vault kv put secret/app password=@/secrets/db-password' >/dev/null
# The application trusts Vault's dev CA, and nothing else is special about it.
rm -f secrets/vault-ca.p12
keytool -importcert -noprompt -alias vault -storetype PKCS12 -storepass changeit \
  -file secrets/vault-tls/vault-ca.pem -keystore secrets/vault-ca.p12 >/dev/null
echo "PostgreSQL on localhost:5432 and Vault on https://127.0.0.1:8200; the password is in Vault at secret/app"
