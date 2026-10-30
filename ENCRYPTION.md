# Field encryption

Columns encrypted in the application, before they are bound and after they are read. The
database, its backups, its replicas, its logs and whoever administers them see only
ciphertext; the keys are in locked native memory of the application and never on its heap.

```java
try (FieldKeys keys = FieldKeys.builder()
        .key(1, SecretProviders.fromUri("vault-transit?address=https://vault:8200"
                + "&key-name=field-data&ciphertext=vault:v1:...&auth-method=kubernetes&..."))
        .build()) {

    EncryptedColumn token = keys.column("tenant.api_token", Mode.RANDOMIZED);
    EncryptedColumn ssn = keys.column("patient.ssn", Mode.DETERMINISTIC);

    // Write: from native memory, as ciphertext.
    try (SecretScope issued = SecretScope.fromProvider(generator);
         PreparedStatement insert = connection.prepareStatement(
                 "insert into tenant (id, api_token) values (?, ?)")) {
        insert.setLong(1, id);
        token.set(insert, 2, issued.secret());
        insert.executeUpdate();
    }

    // Read: into native memory, never a String.
    try (SecretScope value = SecretScope.allocate(256);
         ResultSet rows = select.executeQuery()) {
        rows.next();
        value.length(token.readInto(rows, 1, value.segment()));
    }

    // Search a deterministic column, through its index.
    List<byte[]> terms = ssn.searchTerms(MemorySegment.ofArray(number));
}
```

It is in `seclume-core` (`space.seclume.field`) and needs nothing else. The ciphertext is an
ordinary binary value bound with `setBytes` and read with `getBytes`, so it works on **every
JDBC driver**, seclume's or not, and the format is the same everywhere: a value written
through PostgreSQL decrypts after a move to SQL Server.

| Database | Column type |
|---|---|
| PostgreSQL, CockroachDB, YugabyteDB | `bytea` |
| MySQL, MariaDB | `varbinary(n)` or `blob` |
| SQL Server | `varbinary(n)` or `varbinary(max)` |
| Oracle | `raw(n)` or `blob` |

A value takes 34 bytes more than its plaintext, so `n` is the longest plaintext plus 34.

## Randomized or deterministic

| | `RANDOMIZED` | `DETERMINISTIC` |
|---|---|---|
| The same plaintext twice | two different ciphertexts | the same ciphertext |
| `where col = ?`, unique index, join | no | yes, with `searchTerms` |
| What the database learns | the length of each value | the length, and which rows are equal |
| For | tokens, keys, notes, anything only read back | identifiers that are looked up: national IDs, account numbers, e-mail addresses |

Choose it per column. A deterministic column with few possible values - a gender, a blood
group, a yes/no - gives away its distribution and, with one known row, every row: keep those
randomized. Range queries, ordering and `like` are not possible on either.

Both are **AES-256-GCM-SIV** ([RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)):
randomized with a fresh 96-bit nonce from the operating system, deterministic with a fixed
one. GCM-SIV is built to survive a repeated nonce: it then reveals that two messages are
equal and nothing else - which is exactly the deterministic mode's contract, so both modes
are the same construction and the same code. A sixteen-byte tag authenticates every value.

## Keys

A **ring** of 256-bit data keys, each under a number; the highest is primary unless another
is named. Each key is read once, when the ring is built, from any
[secret provider](PROVIDERS.md) into locked memory, and is either the 32 bytes themselves or
their Base64:

```bash
openssl rand -base64 32           # a key for a file or a secret manager
```

The envelope is better: the key is made in Vault's transit engine and only its ciphertext
leaves Vault, which goes into the configuration - it is no secret there.
`provider=vault-transit` opens it at start-up, with a token that may do nothing else:

```bash
vault write -f transit/keys/field-data type=aes256-gcm96
vault write -f -field=ciphertext transit/datakey/wrapped/field-data bits=256
# vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==
```

```hcl
path "transit/decrypt/field-data" { capabilities = ["update"] }
```

Revoking the token or disabling the transit key stops every new start from opening the data
key - one switch for the whole column set. Settings in [PROVIDERS.md](PROVIDERS.md#vault-transit-a-data-key-only-vault-can-open).

### One key per column

A column encrypts with a key derived from the data key, its **name** and its mode
(HKDF-SHA-256). The same value in two columns has two ciphertexts, even deterministically,
and a value copied from one column into another does not decrypt there. The name is part of
the key: keep it stable (`table.column` is the convention), and renaming a column in the
database does not need renaming it here.

### Rotation

1. Add the new key under a new number; it becomes primary. New values are written under it,
   old ones still read.
2. Move the rows over, at your pace: `needsReencryption(value)` says which, and
   `reencrypt(value)` returns the value under the primary key - the plaintext only in locked
   native memory on the way.
3. While rows are under both keys, look up deterministic columns with
   `where col in (?, ?, ...)` and `searchTerms(value)`: one ciphertext per key, the primary's
   first. A unique index holds within a key, not across two, until the move is done.
4. Drop the old key from the ring when nothing is under it.

`LocalEncryptedColumnTest` does exactly this against all four databases, with the table in use.

## Context: a value bound to its row

`encrypt(value, context)`, `set(..., context)`, `readInto(..., context, ...)`: the context - a
row's primary key, a tenant's id - is authenticated with the value but not stored. A
ciphertext copied into another row then fails there instead of turning up as that row's
value. A deterministic value with a context is equal only within the same context, so a
column that is searched across rows takes none.

## What stays off the heap

| | Where |
|---|---|
| Data keys, column keys | locked native memory, excluded from core dumps, wiped on `close()` |
| A value bound with `set(..., MemorySegment)` and read with `readInto` | native memory only |
| A value bound with `setString` and read with `getString` | the heap: these are for data that is a `String` in the application anyway - a name, a date of birth - and keep it from the database, not from a heap dump |
| The ciphertext | the heap, and that is fine: it is what the database holds |

Proven by a child JVM that reads a value with `readInto` and dumps its heap: neither the
value nor the key, in any encoding; and with the control that reads it as a `String` and
must be found.

## What it does not hide, and does not do

- **The length** of every value, to the byte, and whether it is NULL - SQL NULL is stored as
  NULL.
- **Equality**, in deterministic columns.
- **Access patterns**: which rows a query touches, how often.
- **The application.** Whoever runs code in the application process can decrypt, as the
  application does. Field encryption protects the data from the database side: a stolen
  backup, a read-only replica given to analytics, a DBA, an SQL injection in another
  application on the same database that reads but cannot run code here.
- **Queries on the plaintext** in SQL: functions, ranges, sorting, full-text. They need the
  plaintext, which the server does not have.
- **Key loss.** A data key that is lost makes its values unreadable. Keep the wrapped key (or
  the key) backed up like the database itself.

## The format

```
[ 1 version = 1 ][ 1 flags ][ 4 key number, big endian ][ 12 nonce ][ ciphertext ][ 16 tag ]
```

- **Flags:** bit 0 set for deterministic. No other bit is defined; a value with one set is
  refused.
- **Associated data:** the first six bytes, followed by the context if there is one.
- **Column key:** `HKDF-SHA-256(salt = "seclume field encryption v1", IKM = data key,
  info = flag byte || 0x00 || UTF-8 column name)`, 32 bytes.
- **Deterministic nonce:** twelve zero bytes.

This is pinned by `FieldEncryptionTest` against vectors made by a separate implementation in
Python (`cryptography`'s HKDF and AES-GCM-SIV): one writes, the other reads. Version 1 will
always be read; a later format will have another version byte.

## How it is tested

- **The primitive:** AES-GCM-SIV in Java on native memory, built on seclume's constant-time
  AES and GHASH (POLYVAL is GHASH turned around, RFC 8452 appendix A). All 202 Wycheproof
  vectors, RFC 8452's own, every flipped bit and every truncation refused with the output
  wiped (`AesGcmSivTest`, `WycheproofTest`).
- **The laws, at random:** thousands of rings, column names in five scripts, values from
  empty to 3 KB with AES's block boundaries over-represented, contexts or none - everything
  encrypted decrypts to itself and to nothing else, deterministic is equal exactly when the
  plaintext is, randomized never repeats, rotation and every search term decrypt alike, and
  every mutation is refused (`FieldEncryptionPropertyTest`).
- **Coverage-guided fuzzing:** any stored value at all ends in a value this column wrote or a
  `FieldEncryptionException`; AES-GCM-SIV round-trips any key, nonce, AAD and message and
  refuses any flipped bit (`EncryptedValueFuzzTest`, a minute per pull request, longer at
  night).
- **Four real databases:** ciphertext only on the server, a unique index on a deterministic
  column, rotation in use, a value copied into another row or tampered with refused, the
  heap dump - PostgreSQL 15, 18 and 19 RC, MySQL 8.4, 9.7 and 26.10, MariaDB 11.4, 12.3 and
  13.0, SQL Server 2022 and 2025, Oracle Free 23 (`LocalEncryptedColumnTest`).
- **Vault and OpenBao:** a data key made by transit, opened by `vault-transit` with a token
  that may decrypt that key and no other (`LocalVaultTransitFieldKeyTest`); every answer that
  is not a plaintext refused (`VaultTransitSecretProviderTest`).
- **The release gate:** these tests are in [`.github/security-gate.json`](.github/security-gate.json),
  so a build in which one did not run, or skipped, does not pass.
