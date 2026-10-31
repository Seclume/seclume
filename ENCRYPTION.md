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

It is in `seclume-core` (`space.seclume.field`) and needs nothing else; `seclume-jpa` adds JPA
converters and the Spring Boot starter a ring from `application.properties`. The ciphertext is an
ordinary binary value bound with `setBytes` and read with `getBytes`, so it works on **every
JDBC driver**, seclume's or not, and the format is the same everywhere: a value written
through PostgreSQL decrypts after a move to SQL Server.

| Database | Column type |
|---|---|
| PostgreSQL, CockroachDB, YugabyteDB | `bytea` |
| MySQL, MariaDB | `varbinary(n)` or `blob` |
| SQL Server | `varbinary(n)` or `varbinary(max)` |
| Oracle | `raw(n)` or `blob` |

A value takes 66 bytes more than its plaintext, so `n` is the longest plaintext plus 66.

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

The clouds' key management services do the same with `provider=kms-decrypt`: AWS KMS
(`GenerateDataKeyWithoutPlaintext`), Cloud KMS (`encrypt` a key made with `openssl rand`) and
Azure Key Vault (`wrapKey` with an RSA key):

```bash
aws kms generate-data-key-without-plaintext --key-id alias/field-data --key-spec AES_256 \
    --query CiphertextBlob --output text
```

```properties
provider=kms-decrypt
kms=aws-kms
key=alias/field-data          region=eu-central-1
ciphertext=AQIDAHh...==
credentials=web-identity      # or instance, container; or access-key-id with key-provider
```

The principal needs `kms:Decrypt` (AWS), `cloudkms.cryptoKeyVersions.useToDecrypt` (Google)
or the `unwrapKey` permission (Azure), and nothing else. Settings in
[PROVIDERS.md](PROVIDERS.md#cloud-kms-a-data-key-only-the-cloud-can-open).

### One key per column

A column encrypts with a key derived from the data key, its **name** and its mode
(HKDF-SHA-256). The same value in two columns has two ciphertexts, even deterministically,
and a value copied from one column into another does not decrypt there. The name is part of
the key: keep it stable (`table.column` is the convention), and renaming a column in the
database does not need renaming it here.

### Rotation

1. Add the new key under a new number; it becomes primary. New values are written under it,
   old ones still read.
2. Move the rows over, at your pace - with `ColumnRotation` (below), or by hand:
   `needsReencryption(value)` says which, and `reencrypt(value)` returns the value under the
   primary key - the plaintext only in locked native memory on the way.
3. While rows are under both keys, look up deterministic columns with
   `where col in (?, ?, ...)` and `searchTerms(value)`: one ciphertext per key, the primary's
   first. A unique index holds within a key, not across two, until the move is done.
4. Drop the old key from the ring when nothing is under it.

`LocalEncryptedColumnTest` does exactly this against all four databases, with the table in use.

#### The rotation job

```java
ColumnRotation rotation = ColumnRotation.builder(keys)
        .table("patient").id("id")
        .column("ssn", "patient.ssn", Mode.DETERMINISTIC, Context.NONE)
        .column("diagnosis", "patient.diagnosis", Mode.RANDOMIZED, Context.ROW_ID)
        .batchSize(500)
        .listener(p -> log.info("{} rows, {} moved, {} conflicts", p.rows(), p.rotated(), p.conflicts()))
        .build();

ColumnRotation.Census before = rotation.census(connection);   // per column: values per key
ColumnRotation.Progress done = rotation.run(connection);       // to the end
rotation.census(connection).remaining();                        // 0: the old key can go
```

Rows are read in the order of `id` - unique, best the primary key - a batch at a time after the
last id of the one before (`where id > ?`, the same SQL on all four databases, no offsets), one
transaction per batch. A value is written back only `where id = ? and column = <its old value>`:
a row the application changed in the meantime is left as the application wrote it - under the
primary key, since it writes with the same ring - and counted as a conflict. A value already
under the primary key is not touched, so a second run writes nothing, and a stopped one continues
from `Progress.lastId()` with `.after(lastId)`. `Context.ROW_ID` is for columns whose values are
bound to their row's id ([Context](#context-a-value-bound-to-its-row)). The columns must compare
by value in a `where` - `bytea`, `varbinary`, `raw`, not an Oracle `BLOB`.

Tested against the four databases - batches of five, stopped after the first and continued
while the application writes, a census before and after, a second run with nothing to do
(`EncryptedColumnContract`) - and against a table in memory that changes a row behind the
job's back, fails a batch, ends exactly on a batch boundary and refuses what cannot be an SQL
identifier (`ColumnRotationTest`).

## Crypto-shredding: a key per subject

```java
SubjectKeys subjects = SubjectKeys.of(ring, SubjectKeyStore.jdbc(dataSource, "subject_keys"));

EncryptedColumn email = subjects.column("customer-4711", "customer.email", Mode.DETERMINISTIC);
email.set(insert, 3, address);                      // as with any column

subjects.existingColumn("customer-4711", ...);      // to read: refuses a subject without a key
subjects.shred("customer-4711");                    // erasure: every value of theirs is noise
```

Each subject - a customer, a patient, a tenant - gets 32 random bytes of its own the first time
something is written for it, stored **wrapped**: encrypted under the ring's primary key and bound
to the subject's name, in a table of two columns (`subject` primary key, `wrapped` binary). Its
values are encrypted with a ring built from that key, in the usual format, key commitment
included - one subject's value never opens under another's key. `shred` deletes the wrapped key
and wipes the cached ring: the subject's values stay wherever they were copied - the table, its
indexes, replicas, exports, logs - and open nothing ever again. Deterministic columns stay
searchable within a subject.

**Backups.** A backup of the *key table* still holds the wrapped key, and the ring still opens
it - so a restored backup brings a shredded subject back as long as the ring key that wrapped it
exists. Rotate the ring regularly - `ColumnRotation` over the key table with
`Context.ROW_ID` rewraps every live key without touching the subjects' own keys or values - and
destroy the old ring key once the backups older than the rotation have expired: from then on a
shredded subject stays shredded in every backup too. `SubjectKeysTest` shows both halves.

Subject rings are not listed one by one in the cryptography inventory - the ring that wraps
them is. Tested in memory (`SubjectKeysTest`: isolation between subjects, shredding, a key copied
to another subject, a second instance, another ring, rewrapping, the backup case, the cache, two
writers making a key at once) and against the four databases (`EncryptedColumnContract`: two
subjects in one table, one shredded, a duplicate key refused by the table's primary key).

## Spring Boot

With the starter, the ring comes from `application.properties` - each key a provider's
settings under its number, or one `uri` line - and is a bean, installed for seclume-jpa's
converters and wiped when the context closes:

```properties
seclume.field-encryption.keys.1.provider=vault-transit
seclume.field-encryption.keys.1.address=https://vault:8200
seclume.field-encryption.keys.1.key-name=field-data
seclume.field-encryption.keys.1.ciphertext=vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==
seclume.field-encryption.keys.1.auth-method=kubernetes
seclume.field-encryption.keys.1.auth-role=app
# seclume.field-encryption.keys.2.uri=kms-decrypt?kms=aws-kms&key=alias/field-data&...
# seclume.field-encryption.primary=2        # the highest number when left out
```

```java
@Autowired FieldKeys keys;
EncryptedColumn token = keys.column("tenant.api_token", Mode.RANDOMIZED);
```

A key that cannot be read - a wrong number, a key that is not 32 bytes, a provider Vault
refuses - stops the start, with the reason; nothing half-built is left in memory.

## Quarkus

The same properties in `application.properties` of a Quarkus application with
`seclume-quarkus`: the ring is a `@Singleton` `FieldKeys` to inject, built at start-up -
a key that cannot be read stops it - installed for the JPA converters, and wiped when the
application stops.

## JPA entities

`seclume-jpa` has the converters, for Hibernate, EclipseLink or any Jakarta Persistence 3
provider:

```java
@Entity
class Patient {

    @Converter
    public static class SsnConverter extends EncryptedStringConverter {
        public SsnConverter() { super("patient.ssn", Mode.DETERMINISTIC); }
    }

    @Convert(converter = SsnConverter.class)
    @Column(length = 100, unique = true)
    String ssn;                      // encrypted in the database, a String in the entity

    @Convert(converter = SealedConverter.class)
    @Column(length = 300)
    Sealed apiToken;                 // ciphertext in the entity too; opened into native memory
}

em.createQuery("from Patient where ssn = :ssn", Patient.class)
        .setParameter("ssn", "078-05-1120");      // the parameter is encrypted like the attribute
```

- **`EncryptedStringConverter`, `EncryptedBytesConverter`**: one small subclass per column,
  because a converter is not told which attribute it converts, and the column's name is part of
  its key. They take the ring installed by the starter (or `FieldKeys.install`) at the first
  value, or one handed in by a container that injects converters. The attribute is a `String`
  or `byte[]` in the entity, so it is on the heap like any other: this keeps it from the
  database, not from a heap dump.
- **`Sealed`** with **`SealedConverter`** (named with `@Convert`, or listed with the entities -
  `@EntityScan(basePackageClasses = {App.class, SealedConverter.class})` - and then applied by
  itself): for secrets the application
  only passes on - a token, a TOTP seed. The entity holds the ciphertext; `column.seal(...)`
  makes one from native memory and `column.open(sealed, target)` writes the plaintext into
  native memory. Nothing on the heap is ever the plaintext.
- A deterministic attribute is searched by `=` and `in`, also in derived queries
  (`findBySsn`). During a rotation that finds the values under the primary key; use
  `column.searchSealed(value)` with `in` on a `Sealed` attribute, or re-encrypt first.

Hibernate generates the schema for these attributes as it does for any `byte[]`: `bytea`,
`varbinary(n)`, `raw(n)` - with `length` the plaintext's longest plus 66.

## R2DBC and MongoDB

The same columns, in the same format, from the reactive API and from documents:

```java
// R2DBC (seclume-r2dbc): a ByteBuffer any R2DBC driver binds and reads
EncryptedValues.bind(statement, 1, token, issued.secret());
row -> EncryptedValues.readInto(row, "api_token", token, value.segment());

// MongoDB (seclume-mongodb-driver, also with the official driver): BSON binary, subtype 0x80
patients.insertOne(new Document("_id", 7).append("ssn", EncryptedFields.encrypt(ssn, number)));
Document found = patients.find(EncryptedFields.eq("ssn", ssn, number)).first();
value.length(EncryptedFields.readInto(found, "ssn", ssn, value.segment()));
```

`EncryptedFields.eq` searches with `$in` over the value under every key of the ring, so a
document not yet moved to the primary key is found during a rotation. It is not MongoDB's own
client-side field level encryption: that needs libmongocrypt, keeps its keys in a key vault
collection and holds them as Java objects; this keeps them in locked native memory and needs
nothing on the server. A value written through JDBC and one written through R2DBC are the same
bytes.

## Kafka, Redis, Elasticsearch: the same format beyond databases

The ring, the format and the rotation are the same; only what carries the ciphertext changes.

```java
// Kafka - seclume-kafka: the broker, its log segments and a mirror see ciphertext.
new KafkaProducer<>(properties, new EncryptingSerializer<>(new StringSerializer(), keys, Mode.DETERMINISTIC),
        new EncryptingSerializer<>(new OrderSerializer(), keys, Mode.RANDOMIZED));
new KafkaConsumer<>(properties, new DecryptingDeserializer<>(new StringDeserializer(), keys),
        new DecryptingDeserializer<>(new OrderDeserializer(), keys));

// Redis through Lettuce - seclume-redis: the server, RDB, AOF and MONITOR see ciphertext.
StatefulRedisConnection<String, String> redis =
        client.connect(EncryptedCodec.of(StringCodec.UTF8, keys, "sessions"));

// Elasticsearch and OpenSearch - seclume-elasticsearch: chosen fields of a document.
EncryptedDocument patients = EncryptedDocument.of(keys, "patients")
        .field("ssn", Mode.DETERMINISTIC).field("diagnosis", Mode.RANDOMIZED);
es.index(i -> i.index("patients").document(patients.encrypt(document)));
// terms query on ssn.keyword with patients.searchTerms("ssn", value); patients.decrypt(hit.source())
```

| | Column key | Bound to | Searchable |
|---|---|---|---|
| Kafka | `kafka.<topic>.value` / `.key` | the topic - a record copied to another topic does not open | a deterministic key keeps its partition |
| Redis | `redis.<name>.value` (`.key` with `withEncryptedKeys`) | the name | an encrypted key is found by `GET` again, not by a pattern |
| Elasticsearch | `search.<index>.<field>` | index and field | a deterministic field by an exact `terms` query, through a rotation |

A `null` - a Kafka tombstone, a missing field - stays `null`. A record or value that does not open
with the ring is an error (`SerializationException` for Kafka, so a consumer can dead-letter it),
never a wrong value. Lettuce does not hand the key to the value codec, so a Redis value is not
bound to its key; Elasticsearch values are bound to their field, not their document.

Tested on their own (`EncryptedRecordsTest`, `EncryptedCodecTest`, `EncryptedDocumentTest`: back as
they went, never in the clear, other topic, name, index, field or ring refused, a rotation read
through) and against the real servers in CI - a Kafka broker, Redis and Elasticsearch 9 hold the
canary only as ciphertext, and the value comes back through the ring (`LocalKafkaSaslSslTest`,
`LocalLettuceTest`, `LocalSearchTest`).

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
[ 1 version = 1 ][ 1 flags ][ 4 key number, big endian ][ 12 nonce ][ 32 commitment ][ ciphertext ][ 16 tag ]
```

- **Flags:** bit 0 set for deterministic. No other bit is defined; a value with one set is
  refused.
- **Associated data:** the first six bytes, followed by the context if there is one.
- **Column keys:** `HKDF-SHA-256(salt = "seclume field encryption v1", IKM = data key,
  info = flag byte || 0x00 || UTF-8 column name)`, 64 bytes: the first 32 are the AES-GCM-SIV
  key, the last 32 the commitment key.
- **Commitment:** `HMAC-SHA-256(commitment key, version || flags || key number || nonce)`,
  checked in constant time before anything is decrypted. AES-GCM-SIV, like every AEAD built on
  a polynomial MAC, does not bind a ciphertext to one key: someone who knows two keys can make
  one value that opens under both. With the commitment a value opens under the key it was made
  with and no other - which matters as soon as a ring holds two keys, or a key is not chosen by
  the operator.
- **Deterministic nonce:** twelve zero bytes.

This is pinned by `FieldEncryptionTest` against vectors made by a separate implementation in
Python (`cryptography`'s HKDF, HMAC and AES-GCM-SIV): one writes, the other reads. Version 1 will
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
- **Hibernate on the four databases:** generated schema, ciphertext only on the server, a
  JPQL query and a unique constraint on a deterministic attribute, `in`, NULLs, an update, a
  `Sealed` token opened into native memory and used as a query parameter, and a heap dump of a
  process that loaded the entity: the sealed token and the key are not in it, the `String`
  attribute is - the control, and the documented difference (`JpaFieldEncryptionCase`).
- **Spring Boot:** the ring from the properties, its primary, the `uri` form, installed while
  the context lives, wiped when it closes, every misconfiguration refused at start with
  nothing left in memory (`FieldEncryptionAutoConfigurationTest`).
- **Quarkus:** the ring from the configuration, injected and installed; an unreadable key stops
  the start (`FieldKeysTest`, `FieldKeyRefusedTest`).
- **An AWS KMS emulator:** moto, in CI's brokers job - a data key `Encrypt` made under a real
  key ARN, opened by a SigV4-signed `Decrypt`, keying a ring; an altered ciphertext refused by
  the service (`LocalAwsKmsDecryptTest`).
- **Cloud KMS:** AWS KMS, Cloud KMS and Key Vault against stand-ins - the request each
  service is sent, the plaintext decoded from its answer (Key Vault's Base64url too), every
  refusal and malformed answer (`KmsDecryptSecretProviderTest`). A live run needs the cloud
  and is not part of CI.
- **Vault and OpenBao:** a data key made by transit, opened by `vault-transit` with a token
  that may decrypt that key and no other (`LocalVaultTransitFieldKeyTest`); every answer that
  is not a plaintext refused (`VaultTransitSecretProviderTest`).
- **R2DBC and MongoDB:** values bound and read through `EncryptedValues` against stand-ins and,
  in CI, PostgreSQL over TLS (`EncryptedValuesTest`, `LocalEncryptedR2dbcTest`); documents with
  ciphertext fields of subtype 0x80, found by `EncryptedFields.eq` also during a rotation, on
  MongoDB 8.0 and 9.0 (`LocalEncryptedFieldsTest`).
- **The release gate:** these tests are in [`.github/security-gate.json`](.github/security-gate.json),
  so a build in which one did not run, or skipped, does not pass.
