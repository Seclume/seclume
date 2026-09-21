# Where the secret comes from

Twelve providers, and the README's table names them without saying what separates them. The
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

## The twelve

| Provider | Reads from | Expires | Needs a provider underneath | Per connect |
|---|---|---|---|---|
| `file` | a mounted file | no | — | one read |
| `env-file` | the file a `_FILE` variable points at | no | — | one read |
| `process` | a command's standard output | no | — | a fork |
| `unix-socket` | a local agent | no | — | a round trip |
| `dpapi` | Windows DPAPI, bound to the account | no | — | one decrypt |
| `credential-manager` | the Windows Credential Manager | no | — | one lookup |
| `encrypted` | an AES-GCM ciphertext | no | **two**: `cipher-`, `key-` | one decrypt |
| `rds-iam` | built, not stored — a signed RDS token | 15 min (AWS fixes it) | `key-` | four HMACs |
| `vault` | HashiCorp Vault over HTTPS | **yes**, with its lease | `token-` | one HTTPS request |
| `aws-secrets-manager` | AWS Secrets Manager | no | `key-`, optional `session-token-` | one HTTPS request |
| `azure-key-vault` | Azure Key Vault | **yes**, when the secret has `exp` | `token-` | one HTTPS request |
| `gcp-secret-manager` | Google Secret Manager | no | `token-` | one HTTPS request |

`callback` is a thirteenth and is not configuration: it is the interface your own code
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
```

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
access-key-id=AKIA...     region=eu-central-1
host=db.abc.eu-central-1.rds.amazonaws.com    port=5432    db-user=app
key-provider=file         key-path=/run/secrets/aws-secret-key
```

No password exists anywhere: a fifteen-minute token is signed locally for each connection,
and the AWS secret key never leaves native memory.

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
lease is what feeds the pool machinery above.

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

## Which one to pick

- **A container platform with secret mounts** — `file`. It is the shortest path and the one
  with nothing to go wrong.
- **A Vault estate** — `vault` with a dynamic credential. The lease handling is the part
  nobody else has and the reason it is worth the extra configuration.
- **RDS** — `rds-iam`. No password exists to be stolen.
- **Windows, no orchestration** — `dpapi` or `credential-manager`.
- **A password that may not stand in the configuration, and no store** — `encrypted`, having
  read the paragraph about what it does not buy.
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
