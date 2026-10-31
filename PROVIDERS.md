# Where the secret comes from

Fourteen providers, and the README only names them without saying what separates them. The
differences that decide which one you want are not "which store" but three others:

- **does the credential expire**, because that is what the pool has to know about;
- **does it need a second provider underneath**, because that doubles the configuration;
- **what does it cost per connection**, because a provider is read on every physical connect.

This file is the one place all of that is written down. Every setting here works in three
spellings of the same thing: a JDBC URL option, a `seclume.datasources.<name>.secret.*`
property, and — for the simple ones — a `secret-uri`.

## The one rule that is never bent

**A secret is never a setting.** `password=`, `secret=` and `value=` are refused with a
message saying why: a password in the configuration is a `String` in the environment and
stays on the heap for the life of the application, which is what this library exists to
prevent. Settings say *where* a secret lives, never what it is. That is also why anything
secret a provider needs — a Vault token, a bearer token, an AWS session token — is itself a
nested provider rather than a value.

## The providers

| Provider | Reads from | Expires | Needs a provider underneath | Per connect |
|---|---|---|---|---|
| `file` | a mounted file | no | — | one read |
| `env-file` | the file a `_FILE` variable points at | no | — | one read |
| `process` | a command's standard output | no | — | a fork |
| `unix-socket` | a local agent | no | — | a round trip |
| `dpapi` | Windows DPAPI, bound to the account | no | — | one decrypt |
| `credential-manager` | the Windows Credential Manager | no | — | one lookup |
| `libsecret` | the Linux desktop keyring (Secret Service: GNOME Keyring, KWallet, KeePassXC) | no | — | one D-Bus lookup |
| `keychain` | the macOS Keychain, a generic password | no | — | one lookup |
| `encrypted` | an AES-GCM ciphertext | no | **two**: `cipher-`, `key-` | one decrypt |
| `rds-iam` | built, not stored — a signed RDS token | 15 min (AWS fixes it) | `key-` | four HMACs |
| `vault` | HashiCorp Vault or OpenBao over HTTPS | **yes**, with its lease | `token-`, or a login: `jwt-` / `secret-id-` / `aws-` / the cloud's metadata | one HTTPS request |
| `vault-transit` | a ciphertext Vault's transit engine decrypts — a [field encryption](ENCRYPTION.md) data key | no | `token-`, or a login as for `vault` | one HTTPS request |
| `kms-decrypt` | a ciphertext AWS KMS, Cloud KMS or Azure Key Vault decrypts (`kms=`) — a [field encryption](ENCRYPTION.md) data key | no | the service's credentials: `key-` / `credentials=` (AWS), `token-` (Google, Azure) | one HTTPS request |
| `shamir` | `k` of `n` Shamir shares, each from a provider of its own — a secret nobody holds alone | no | **one per share**: `share.1.*` … `share.n.*` | one read per share until `k` |
| `aws-secrets-manager` | AWS Secrets Manager | no | `key-`, optional `session-token-` | one HTTPS request |
| `azure-key-vault` | Azure Key Vault | **yes**, when the secret has `exp` | `token-` | one HTTPS request |
| `gcp-secret-manager` | Google Secret Manager | no | `token-` | one HTTPS request |
| `azure-managed-identity` | nothing stored — the VM's Entra token, from IMDS | not reported (see below) | — | one local HTTP request |
| `gcp-metadata` | nothing stored — the workload's Google token, from the metadata server | not reported (see below) | — | one local HTTP request |
| `spiffe-jwt` | nothing stored — a JWT-SVID for an audience, from the SPIFFE Workload API | **yes**, its `exp` | — | one local gRPC call |

`callback` is one more and is not configuration: it is the interface your own code
implements, handed native memory to write into.

### What "expires" buys

A provider that implements `ExpiringCredentials` tells the pool when its credential stops
being valid, and the pool retires connections **before** that rather than discovering it
afterwards. Each connection carries the deadline of the credential it was opened with, so a
rotation does not empty the pool — the old connections run out on their own schedule while
new ones start on the new one. One minute of margin by default
(`seclume.datasources.<name>.pool.credential-margin`).

Without it the usual arrangement is to set `maxLifetime` shorter than the TTL by hand, in a
second place, and to remember it when the TTL changes.

Two details decide whether "does not empty the pool" holds in practice. **The replacement is
opened before the old connection is retired**, not after. Otherwise there is a moment with
nothing in the pool, and every caller arriving in it pays a full handshake plus the round trip
to fetch the password. And **the deadlines are spread out** (`credential-spread`, the margin
by default). Connections opened in one burst share an expiry to the second, so without it a
whole cohort would reach its deadline in the same housekeeping round.

### What "needs a provider underneath" costs

`encrypted`, `rds-iam`, `vault` and the three cloud vaults all need a secret of their own to
get at your secret. That inner source is configured with a prefix, so one block of settings
holds both without them getting in each other's way:

```properties
secret.provider=vault
secret.address=https://vault.internal:8200
secret.path=database/creds/app
secret.token-provider=file            # the inner provider, by prefix
secret.token-path=/var/run/secrets/vault-token
```

The prefixes are `key-` (a key or an AWS access key), `cipher-` (a ciphertext),
`token-` (a bearer or Vault token) and `session-token-` (AWS temporary credentials). An inner
provider can be any of the twelve, including another one with a prefix of its own.

## Every setting, per provider

### Local sources

```properties
provider=file             path=/run/secrets/db-password

provider=env-file         path=/run/secrets/app.env      key=DB_PASSWORD

provider=process          command=/usr/local/bin/get-secret --name db

provider=unix-socket      path=/run/agent.sock           request=db-password   # request optional

provider=dpapi            path=/run/secrets/db.dpapi     entropy=optional-extra

provider=credential-manager   target=AppDb

provider=libsecret        attribute.service=orders-db    attribute.account=app
                          # as stored by: secret-tool store --label=... service orders-db account app

provider=keychain         service=orders-db              account=app   # account optional
                          # as stored by: security add-generic-password -s orders-db -a app -w
```

`libsecret` reads the item as libsecret's own `SecretValue`, which lives in libsecret's
non-pageable memory and is wiped when released; the bytes go from there into the target. It
matches the attributes only, so an item stored under any schema is found. Tested against
gnome-keyring in a container. `keychain` reads through `SecItemCopyMatching` from
Security.framework; it is written against Apple's documented API and **not yet tested on a
Mac**.

`max-length` works on all of them and defaults to 256 bytes, which is longer than any database
password.

### Encrypted at rest

```properties
provider=encrypted
cipher-provider=file      cipher-path=/run/secrets/db.enc
key-provider=dpapi        key-path=/run/secrets/kek
aad=main                                                  # optional
```

Both halves are Base64; the ciphertext is `[12-byte nonce][ciphertext][16-byte tag]`, the key
is 16, 24 or 32 bytes, and **a nonce is used once**. The optional `aad` binds a ciphertext to
where it belongs, so the reporting database's secret cannot be pasted over the production
one and quietly work.

**Worth saying plainly:** whoever can read the ciphertext can usually read the key beside it.
The gain is against copying, screenshots, backups and accidental commits — not against
somebody who already has the machine. It exists for the case where a password may not stand
in the configuration in the clear and there is no secret store either.

### Built rather than stored

```properties
provider=rds-iam
region=eu-central-1
credentials=instance                  # or container, web-identity; or a key pair:
access-key-id=AKIA...
key-provider=file                     key-path=/run/secrets/aws-secret-key
session-token-provider=file           # optional, for temporary credentials
session-token-path=/run/secrets/aws-session-token
host=db.abc.eu-central-1.rds.amazonaws.com    port=5432    db-user=app   # default to the URL's
```

No password exists anywhere: a fifteen-minute token is signed locally for each connection,
and neither the AWS secret key nor the session token ever leaves native memory. `host`, `port`
and `db-user` default to the connection's own URL and user; set them explicitly only when
dialling through a local tunnel whose address differs from the RDS endpoint.

### Vault

```properties
provider=vault
address=https://vault.internal:8200
path=secret/data/app                  # or database/creds/app for a dynamic credential
field=password                        # default: password
token-provider=file       token-path=/var/run/secrets/vault-token
namespace=team-a                      # optional, Vault Enterprise
verify=true                           # default
timeout-millis=10000                  # default
```

Both engines. Under `database/creds/...` Vault creates a database user with a lease, and the
lease is what feeds the pool machinery above. The user comes with the password: the drivers
(PostgreSQL, MySQL, SQL Server, Oracle) log in as the user Vault created, whatever the URL's
`user` says. One credential serves every connection of the data source. Halfway through the
lease it is **renewed** (`sys/leases/renew`) - the same user, no new one in the database - for
as long as Vault extends it; when the role's `max_ttl` caps the renewal, a new credential is
fetched. **Closing the provider revokes the lease**, and Vault drops the user at once.
Tested against a real Vault and PostgreSQL (`.github/scripts/vault_fixtures.sh`), and the
same fixture against OpenBao.

#### Logging in instead of a token file

The Vault token is the secret that unlocks the others, and a file holding it is only as
good as whatever keeps it fresh - usually a Vault Agent sidecar. `auth-method` lets the
provider log in itself, with an identity the workload already has, and hold the token it
gets in native memory:

```properties
# Kubernetes: the pod's service-account token against a role bound to it
auth-method=kubernetes
auth-role=app
auth-mount=kubernetes                          # default: the method's name
jwt-provider=file  jwt-path=/var/run/secrets/kubernetes.io/serviceaccount/token   # the default

# JWT: any token the mount trusts - a projected token with its own audience, a
# SPIFFE JWT-SVID, a CI system's OIDC token
auth-method=jwt
auth-role=app                                  # optional: the mount's default role
jwt-provider=file  jwt-path=/var/run/secrets/tokens/vault

# AppRole: the role id is an identifier, the secret id a secret
auth-method=approle
auth-role-id=8d4b5e2c-...
secret-id-provider=file  secret-id-path=/run/secrets/vault-secret-id
```

`auth-method=token`, the default, is the token from `token-` as before; both at once are
refused. The JWT and the secret id go into the login request from native memory; the answer
is parsed off the heap and only `auth.client_token` is kept, locked and wiped when replaced.
Halfway through the token's TTL it is renewed (`auth/token/renew-self`); when Vault will not
renew it, or grants less than half a TTL more, the login is done again - with the JWT read
anew, since the kubelet rotates it. Closing the provider revokes the lease first and then the
token (`auth/token/revoke-self`). A request Vault refuses with 403 gets one new login before
the provider gives up: a token revoked from outside is replaced, a path the role may not read
still fails.

**The token bounds the credential.** Vault revokes a lease together with the token that
created it. So the provider reports the earlier of the two ends to the pool, renews both
halfway through the shorter one, and a credential fetched under a token that has since been
replaced is fetched again under the new one rather than renewed. Give the login role a token
TTL at least as long as the database role's, and a `token_max_ttl` well above it; otherwise
every new login also means a new database user.

#### Logging in with the cloud's identity

On a cloud machine the workload already has an identity, and Vault can take it as it is:

```properties
# AWS, iam type: an sts:GetCallerIdentity request signed with the workload's
# credentials, which Vault replays to AWS to learn who is asking
auth-method=aws
auth-role=app                                  # optional: the role named after the IAM principal
aws-credentials=instance                       # or container, web-identity - as for rds-iam
# or a key pair:  aws-access-key-id=AKIA...  aws-key-provider=file  aws-key-path=...
#                 aws-session-token-provider=file  aws-session-token-path=...
aws-iam-server-id=vault.example.com            # optional: Vault's iam_server_id_header_value
aws-sts-endpoint=sts.amazonaws.com             # the default; must match Vault's sts_endpoint
aws-sts-region=us-east-1                       # the default; must match Vault's sts_region

# GCP, gce type: the VM's identity token from the metadata server
auth-method=gcp
auth-role=app
gcp-account=default                            # the default
gcp-audience=http://vault/app                  # the default: http://vault/<auth-role>

# Azure: the managed identity's token from IMDS, and where the machine lives
auth-method=azure
auth-role=app
azure-resource=https://management.azure.com/   # the default; Vault's azure auth resource
azure-client-id=...                            # optional, for a user-assigned identity
# subscription, resource group and VM (or scale set) name come from IMDS, or all of:
# azure-subscription-id=...  azure-resource-group=...  azure-vm-name=... | azure-vmss-name=...
```

The AWS settings carry their own `aws-` prefix, so that the Vault's settings - `verify=false`
for a development server, say - never reach the AWS side. **The signed request is itself a
credential**: anyone holding it can log in to a Vault that accepts it for fifteen minutes. So
not only the secret access key but the session token, the signature and the base64 header
document Vault receives are all assembled in native memory; a new login signs anew. Set
`aws-iam-server-id` and Vault's `iam_server_id_header_value` to tie a request to one Vault.
GCP's `gce` login and Azure's take the token the platform hands out; what the Azure login
also needs - subscription, resource group, VM or scale set name - is no secret and is read
from IMDS once and kept.

The `iam` type of GCP (a JWT signed through the IAM API) is not supported; on GCE the `gce`
type needs nothing but the VM.

The heap half is proven by `VaultLoginHeapTest`: Vault in another JVM, a JWT login and an AWS
login, a credential read, lease and token revoked - and neither the JWT, nor the AWS secret
key or session token, nor the token Vault handed out, nor the password in this JVM's heap,
with a control that puts the token there on purpose and is found. The fake Vault checks the
AWS signature as AWS would. The AWS, GCP and Azure logins are tested against stand-ins for
Vault and the metadata services, and the AWS signature additionally against an independent
SigV4 implementation; a live run needs the cloud and is not part of CI.

### Vault transit: a data key only Vault can open

```properties
provider=vault-transit
address=https://vault:8200
key-name=field-data
ciphertext=vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==
token-provider=file     token-path=/var/run/secrets/vault-token     # or auth-method=... as for vault
# transit-mount=transit  context=<Base64, for a derived key>  namespace=  verify=true  max-length=1024
```

`POST transit/decrypt/<key-name>` with the ciphertext; Vault's answer - the plaintext in
Base64, inside JSON - is read where it lies and decoded into the target, never a `String`.
The ciphertext is what `transit/datakey/wrapped/<key-name>` or `transit/encrypt/<key-name>`
handed out, and it is no secret: only Vault opens it. That makes it the envelope for
[field encryption](ENCRYPTION.md)'s data keys, read once when the key ring is built. The
token needs `update` on `transit/decrypt/<key-name>` and nothing else; a 400 from Vault
means a ciphertext of another key or a context that does not match.

Tested against Vault and OpenBao in CI (`LocalVaultTransitFieldKeyTest`, with a token that
may open this key and no other) and against a stand-in for every answer that is not a
plaintext (`VaultTransitSecretProviderTest`).

### Cloud KMS: a data key only the cloud can open

```properties
provider=kms-decrypt
kms=aws-kms                      # or gcp-kms, azure-key-vault, vault-transit
ciphertext=<Base64 the service handed out>
```

| `kms=` | Settings | The request | The principal needs |
|---|---|---|---|
| `aws-kms` | `key` (ARN, id or alias), `region`; `credentials=instance\|container\|web-identity`, or `access-key-id` with `key-provider` (and `session-token-provider`); `endpoint` | `TrentService.Decrypt` with `CiphertextBlob` and `KeyId` - a ciphertext of another key is refused by AWS | `kms:Decrypt` |
| `gcp-kms` | `key` = `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>` (the version is in the ciphertext); `token-provider`, e.g. `gcp-metadata`; `endpoint` | `POST /v1/<key>:decrypt` | `cloudkms.cryptoKeyVersions.useToDecrypt` |
| `azure-key-vault` | `vault-uri`, `key-name`, `key-version` (the one it was wrapped with), `algorithm` (`RSA-OAEP-256`; `RSA-OAEP`; `A128KW`..`A256KW` on Managed HSM); `token-provider`, e.g. `azure-managed-identity` with `token-resource=https://vault.azure.net` | `POST /keys/<name>/<version>/unwrapkey` | the `unwrapKey` key permission |
| `vault-transit` | as `provider=vault-transit` above | | |

Each answer carries the plaintext in Base64 (Key Vault: Base64url) inside JSON; both are read
where the answer lies, in native memory, and the decoded secret is written into the target.
The ciphertext is no secret: it stands in the configuration because only the service can open
it. Made for [field encryption](ENCRYPTION.md)'s data keys, read once when the key ring is
built; any other secret stored this way works the same.

Tested against stand-ins for the three services: the request each is sent, the plaintext
decoded from each answer, every refusal with what the principal needs, every malformed answer
(`KmsDecryptSecretProviderTest`). A live run needs the cloud and is not part of CI.

### Shamir: a secret nobody holds alone

```properties
provider=shamir
threshold=3                       # optional: refuses shares of a split that needs fewer
share.1.provider=file
share.1.path=/run/secrets/share-alice
share.2.provider=keychain
share.2.service=seclume-share
share.3.provider=vault
share.3.address=https://vault:8200
share.3.path=secret/data/shares/carol
share.3.token-provider=file
share.3.token-path=/run/secrets/vault-token
share.4.provider=file
share.4.path=/mnt/usb/share-dave
share.5.provider=file
share.5.path=/run/secrets/share-erin
```

The secret - a master key, the field encryption ring's data key, a database password - is
split once into `n` shares, any `k` of which give it back and any `k - 1` of which say nothing
about it (Shamir's scheme over GF(2^8), byte by byte):

```
java -jar seclume-verify.jar --split "file:/root/master.key" 3 5 /root/shares
```

Each share is one line in an owner-only file, `seclume-share-1.<split>.<k>.<x>.<value>.<crc>`.
Each holder keeps theirs where only they can reach it; the application reads shares in the
order configured until it has `k`, passing over the ones that cannot be read - that a holder is
away is the point - and fails, naming which shares were missing and why, when fewer than `k`
are there. A share that is there but wrong is refused outright rather than passed over: a
mistyped digit (the CRC-32), a share of another split, the same share twice, or a combination
that does not give back what was split (16 bytes of SHA-256 over the secret are shared with
it and checked in constant time).

Shares are read, parsed and combined in native memory; the field arithmetic has no tables and
no branches on data. Tested with a known answer from an independent implementation, every
choice of `k` of `n`, perfect secrecy below the threshold shown exhaustively for one byte,
every single-character change to a share refused, and a fuzz target on the share format
(`ShamirTest`, `ShamirSharesTest`, `ShamirShareFuzzTest`).

### The three cloud vaults

```properties
provider=aws-secrets-manager
region=eu-central-1       secret-id=prod/db     field=password    # field optional
access-key-id=AKIA...
key-provider=file         key-path=/run/secrets/aws-secret-key
session-token-provider=file                                       # temporary credentials
session-token-path=/var/run/secrets/aws/session-token

provider=azure-key-vault
vault-uri=https://my-vault.vault.azure.net    name=db-password    version=...   # optional
token-provider=file       token-path=/var/run/secrets/azure/token

provider=gcp-secret-manager
project=my-project        name=db-password     version=latest                   # optional
token-provider=file       token-path=/var/run/secrets/gcp/token
```

Each shape is where an SDK would have put the password on the heap: AWS wraps a JSON document
inside a JSON string, Azure puts the expiry in a sibling object, Google Base64-encodes the
payload. All three go through the same two pieces — `SecretFetch` for the HTTPS, `JsonOff` for
the answer — so nothing is ever a `String`, and none of the three SDKs is a dependency.

**AWS temporary credentials** (IRSA, an instance role, `AssumeRole`) work through
`session-token-`. The token is not merely sent as `X-Amz-Security-Token`, it is *signed*,
which puts it inside the canonical request — so the canonical request is assembled in native
memory rather than concatenated. This was documented as an unsupported gap for a while rather
than closed badly; the note is kept in `internal/docs` because the reasoning is worth more
than the outcome.

**Which TLS carries the fetch.** Vault and the three cloud vaults are asked over seclume's own
TLS 1.3 client, so their answer is decrypted into native memory only. The JDK's `SSLEngine`
decrypts through short-lived heap arrays, which put the answer, and the password in it, on
the heap until the next collection. For a server that cannot do TLS 1.3 with P-256,
`-Dseclume.secretFetch.tlsStack=jsse` switches back to JSSE, with that exposure. The trust
store, `tlsRootCert` and `verify` behave the same on both stacks.

### Workload identity: no stored credential at all

```properties
provider=azure-managed-identity                       # Azure Database for PostgreSQL / MySQL
resource=https://ossrdbms-aad.database.windows.net
client-id=...                                         # a user-assigned identity; optional

provider=gcp-metadata                                 # Cloud SQL IAM authentication
account=default                                       # or another attached service account
audience=api://...                                    # optional: the identity token (a JWT) for
                                                      # this audience, not an access token
```

The database accepts the machine's own identity. Azure's Instance Metadata Service and
Google's metadata server hand an access token to whatever runs on the host, and that token is
the password - there is nothing to store, rotate, leak or forget to revoke. The SDKs return
it as a `String` (`AccessToken.getToken()`, `getTokenValue()`); here it goes from the socket
into native memory, and only `access_token` is copied out of the answer.

Both endpoints are **plain HTTP on the link-local address** `169.254.169.254`, which is how
they are meant to be reached: the packet never leaves the host. `SecretFetch` allows plain
HTTP to a link-local or loopback address and **refuses it for anything else** - checked on the
resolved address, before a byte is sent - so a configuration that points one of these at a
real host fails instead of handing a token across a network.

**Expiry is not reported, on purpose.** The database checks the token at login and never
again, so an open connection outlives it; reporting the hour would have the pool retire
healthy connections for nothing. Each new connection asks for a token, and both services cache
it locally. `rds-iam` does the same, for the same reason.

Both also work as the `token-` of a vault: `token-provider=azure-managed-identity` with
`token-resource=https://vault.azure.net` reads Key Vault with the machine's identity, and
`token-provider=gcp-metadata` does the same for Secret Manager.

**PostgreSQL 18's OAuth login** takes any of these tokens: with `oauth` in `pg_hba.conf` the
server asks for `OAUTHBEARER`, and the driver sends the provider's secret as the bearer token -
from `azure-managed-identity`, `gcp-metadata`, a `file` that a sidecar keeps fresh, or any other
provider. Only to a server that proved who it is (`tls=verify-full` or `tlsPin`): with
`tls=require` or no TLS the driver refuses before reading the token. Azure SQL's token login
likewise refuses `trustServerCertificate=true` unless a `tlsPin` names the key. Which tokens the server accepts is its validator's business
(`oauth_validator_libraries`); PostgreSQL ships none.

**Azure SQL** takes the token in LOGIN7's `FEDAUTH` feature: `authentication=token` with
`provider=azure-managed-identity` and `resource=https://database.windows.net/`. No user name and
no password go out. The wire format is checked against a SQL Server 2022, which reads it and
answers with an ordinary "Login failed"; a live Azure SQL login has not been run yet.

**App Service, Functions and Container Apps** have no IMDS. They give the process its own
endpoint on loopback (`IDENTITY_ENDPOINT`) and a header value to send with it
(`IDENTITY_HEADER`). When both are set, `azure-managed-identity` asks that endpoint instead, as
the Azure SDK does; nothing else changes in the configuration.

**Azure Arc** machines set `IDENTITY_ENDPOINT` and `IMDS_ENDPOINT` without a header. Their agent
first answers 401 and names a challenge file that only an administrator or the `himds` group can
read; its content goes back as `Authorization: Basic ...`, written from native memory. Only a
file in the agent's token directory, ending in `.key` and at most 4 KiB, is read - an endpoint
cannot make the provider read any other file. Tested against a stand-in agent; not yet on a real
Arc machine.

### SPIFFE: a JWT-SVID for an audience

```properties
provider=spiffe-jwt
audience=https://api.example.com          # comma separated
socket=unix:///run/spire/agent.sock        # optional: else SPIFFE_ENDPOINT_SOCKET
spiffe-id=spiffe://example.org/orders      # optional: which of the workload's identities
```

Where SPIRE hands out workload identities, the JWT-SVID is the bearer token a service of that
audience accepts - an API behind a JWT check, Kafka's OAUTHBEARER, PostgreSQL 18's `oauth`
login with a validator that knows the trust domain. It comes from the agent's socket
(`FetchJWTSVID`, the same small HTTP/2 client as the X.509-SVIDs) through native memory into
wherever it is sent; every SPIFFE library hands it out as a `String`. Each read asks the agent,
which caches, so the token is the one valid now, and its `exp` - read where it lies, decoded in
native memory - is when a pool replaces the connections opened with it.

### No password: the certificate is the login

```properties
provider=none
clientCert=/var/run/secrets/svid.pem          # or clientCertThumbprint=... on Windows
clientKey-provider=file
clientKey-path=/var/run/secrets/svid_key.pem
```

For PostgreSQL's `cert` method (`hostssl all app 0.0.0.0/0 cert` in `pg_hba.conf`; the
certificate's CN is the user) and for a MySQL account created with an empty password and
`REQUIRE SUBJECT '/CN=app' AND ISSUER '/CN=your-ca'`. Needs `tls=require` or stricter and
`tlsStack=seclume`, like every client certificate here.

`none` is a word rather than an absent setting so that a forgotten password still fails.
PostgreSQL refuses before sending anything if the server asks for a password after all; MySQL
sends the empty password, because that is how its certificate-only accounts are written.

## One line instead of four

With the starter, `secret-uri` expands to the `secret.*` keys. It is the same spelling the JDBC
URL takes, so a deployment needs one environment variable per data source rather than four
that have to agree:

```properties
seclume.datasources.main.secret-uri=file:/run/secrets/db
seclume.datasources.main.secret-uri=env-file:/run/secrets/app.env?key=DB_PASSWORD
seclume.datasources.main.secret-uri=credential-manager?target=AppDb
seclume.datasources.main.secret-uri=encrypted:/run/secrets/db.enc?key-provider=dpapi&key-path=/run/secrets/kek&aad=main
```

If a data source gives both `secret-uri` and `secret.*`, it is refused rather than resolved by
precedence.

## The guard: plaintext passwords elsewhere in the application

At startup the starter reads the whole `Environment` and names every property that holds a
password in plain text: `spring.mail.password`, and whatever the application invented for
itself. It reports and does not forbid, because much of what it finds has no off-heap
alternative yet, and a guard that blocks what cannot be fixed gets switched off. **Names are
logged, never values.**

```properties
seclume.secret-guard=warn                     # warn (default), fail, off
seclume.secret-guard-allow=spring.mail.password
```

The allow-list is the point. It turns "we have three plaintext passwords and nobody knows"
into three that are written down and decided on, and it is meant to get shorter.

## Which one to pick

The option that makes all of this unnecessary is **Kerberos**: there is no secret in the
process at all, only a ticket the operating system holds. It works for all four databases:
on Linux through the system's GSSAPI library, with `kinit` or a keytab providing the ticket;
on Windows through SSPI, with the logon session's credentials.

- **PostgreSQL:** `provider=none`, and `gss` in `pg_hba.conf`.
- **MariaDB:** `provider=none`, and the user created `IDENTIFIED VIA gssapi`.
- **SQL Server and Oracle:** `authentication=kerberos`. For Oracle, the database user is
  `IDENTIFIED EXTERNALLY AS 'alice@REALM'`.

Against an Oracle database on Windows, `authentication=nts` does the same with the Windows
logon session (NTLM through SSPI; the user is `"OPS$HOST\ALICE" IDENTIFIED EXTERNALLY`).
NTLM does not prove who the server is, so prefer Kerberos where there is a domain.
Everywhere else:

- **A container platform with secret mounts** — `file`. It is the shortest path and the one
  with nothing to go wrong.
- **A Vault estate** — `vault` with a dynamic credential. The lease handling is the part
  nobody else has and the reason it is worth the extra configuration.
- **RDS** — `rds-iam`. No password exists to be stolen.
- **Azure Database, Cloud SQL** — `azure-managed-identity`, `gcp-metadata`. The same, with
  the cloud's own workload identity.
- **A SPIFFE agent or cert-manager already issuing certificates** — `none`, with the client
  certificate as the login.
- **Windows, no orchestration** — `dpapi` or `credential-manager`.
- **A password that may not stand in the configuration, and no store** — `encrypted`, having
  read the paragraph about what it does not buy.
- **A master key that no one person may hold, and no KMS** — `shamir`, `k` of `n` holders.
- **Something else entirely** — `callback`, and write the twenty lines yourself.

## Writing one

`SecretProvider` is one method: write the secret into the segment you are given and return how
many bytes. Everything else in this library is arranged so that a provider never has to make
a `String`, and the tests will tell you if you do — `NoSecretInHeap` takes a heap dump and
looks.

```java
public interface SecretProvider extends AutoCloseable {
    int maxSecretLength();
    int writeSecret(MemorySegment target);
}
```

Implement `ExpiringCredentials` beside it if your credential has a deadline; the pool picks
it up without anything else being configured.
