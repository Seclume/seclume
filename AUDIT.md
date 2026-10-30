# Audit guide

seclume has not had an external security review yet. This page is for whoever does one. It
says what to look at first, what is implemented here rather than taken from a library, what
the tests already show, and which questions are open. The threat model behind it is
[THREAT-MODEL.md](THREAT-MODEL.md).

## The claim under review

> No credential or private key a seclume component handles is ever on the Java heap, and
> every byte a peer sends is treated as hostile.

Everything below is either part of keeping that claim, or a component that replaces a library
precisely so that the claim can hold. A JCA `Cipher` takes `byte[]`, and so does a JDBC
driver's login.

## Where to start - in order of risk

1. **The TLS client** (`seclume-core`, `space.seclume.tls`). It makes the trust decision for every
   database and secret manager connection:
   - `ClientHandshake`, `Tls12Handshake`;
   - `CertificateTrust` (the JDK's `X509TrustManager` or a pin), `HostnameMatch` with
     `PublicSuffixes`;
   - `StrictExtensions`, `KeySchedule`, `RecordProtection`, `RecordStream`;
   - `HandshakeSignature`, `Finished`, `TlsMigration`.

   The last one moves a live connection between processes (detach/resume). Its security
   resets belong at the end of a borrow, never during migration.
2. **Primitives computed in Java**, on native memory (table below). A mistake in any of these is a
   mistake in every connection that uses it.
3. **Decoders of hostile input:** every server protocol, the HTTP and JSON of secret managers,
   the SPIFFE agent's HTTP/2 and protobuf, KMS answers, and the files the tools read (heap dumps,
   recordings, key files).
4. **The secret lifecycle:**
   - `SecretScope` and `MemoryLock` (`mlock`, `MADV_DONTDUMP`, zeroing on close);
   - `Entropy`, `Base64Off`, `Utf`, `WireBuffer`;
   - the secret providers, which read secrets into native memory.
5. **The heap rule itself.** `ForbiddenApiTest` lists the constructs that put bytes on the heap.
   Every exception is marked `seclume-allow:` with a reason: `grep -rn "seclume-allow" --include=*.java`
   lists them all for review.

## Cryptography implemented here

Everything else is the platform's: OpenSSL 3 on Linux, CNG on Windows, or the JDK.

| Component | What | Why not a library | Evidence |
|---|---|---|---|
| `Aes`, `AesKey`, `AesSubBytes`, `AesTables` | AES-128/192/256, CBC and CFB; S-box computed in constant time, no table lookups | Oracle O5LOGON; JCA keys are `byte[]` | FIPS-197 vectors (`AesTest`, `AesSubBytesTest`); `ConstantTimeLeakageTest` |
| `AesGcm`, `Ghash`, `JavaAesGcm` | AES-GCM for TLS records, branch- and table-free GHASH | fallback where OpenSSL/CNG AES-GCM is missing | Wycheproof `aes_gcm_test.json`; `GhashTest`; tag check in `ConstantTimeLeakageTest` |
| `Sha1Digest`, `Sha256Digest`, `Sha384Digest`, `Sha512Digest`, `Md5Digest`, `BlockDigest` | FIPS 180-4 and RFC 1321 hashes, state off-heap | the JCA copies input into `byte[]` | `DigestTest` (FIPS vectors) |
| `Hmac`, `Hkdf`, `Pbkdf2` | RFC 2104, RFC 5869, RFC 8018 | the key is the password or derived from it | Wycheproof HMAC, HKDF and PBKDF2 suites; `Rfc8448VectorsTest` |
| `Ed25519` | RFC 8032 signing only, TweetNaCl structure, masked ladder | MariaDB `client_ed25519` expands the password itself; CNG has no Ed25519 | RFC 8032 vectors and the JDK's Ed25519 (`Ed25519Test`) |
| `Rsa`, `RsaPublicKey`, `BigWords`, `Der` | RSA encryption with a *public* key (the password is the plaintext) | MySQL `caching_sha2_password` / `sha256_password` | `RsaTest`, `AuthPluginsTest`; the MySQL CI jobs |
| `DiffieHellman`, `BigWords.modPowSecret` | finite-field DH over the group the server names, secret exponent in constant time | Oracle Native Network Encryption | `DiffieHellmanTest` |
| `ConstantTime` | comparisons of server proofs, MACs and Finished | - | `ConstantTimeLeakageTest` (dudect's method, negative control) |
| `AesGcmSiv`, `space.seclume.field` | AES-GCM-SIV (RFC 8452) on `Aes` and `Ghash`; field encryption's format, HKDF column keys, key ring and rotation | the data key must stay off-heap; the JCA has no GCM-SIV | Wycheproof `aes_gcm_siv_test.json`, `AesGcmSivTest`, `FieldEncryptionTest` (vectors from an independent implementation), `FieldEncryptionPropertyTest`, `LocalEncryptedColumnTest` |
| `Scram`, `ChannelBinding` | SCRAM-SHA-256/512 client, `tls-server-end-point` | the salted password must stay off-heap | `ScramTest`, `ScramFuzzTest`, `ChannelBindingTest`, live servers |
| `AwsSigV4`, `AwsSigV4a`, `CanonicalRequest` | AWS request signing with the secret key in native memory | the AWS SDK holds the key as a `String` | `SigV4EquivalenceTest`, `CanonicalRequestTest`, `SigV4aTest` |
| `KeySchedule`, `Tls12Prf`, `TranscriptHash` | TLS 1.3 key schedule, TLS 1.2 PRF | traffic secrets stay off-heap | `Rfc8448VectorsTest`, interop with five TLS stacks |

**Taken from the platform, not computed here:**
- ECDHE (P-256, P-384, X25519) and ML-KEM-768 (`NativeEcdh`, `NativeP256`, `HybridMlKem`);
- ECDSA and RSA signing with a private key (`OpenSslSigningKey`, `CngSigningKey`, `EcdsaSigner`);
- the fast AES-GCM path (`OpenSslAesGcm`, `CngAesGcm`) and PBKDF2 where available (`NativePbkdf2`);
- X.509 parsing and path validation (the JDK);
- randomness (`Entropy`: the operating system on every call).

## Fuzzing

The fuzz targets use [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer).
- **Every build** replays a fixed, deterministic sample of each target.
- **`mvn -Pfuzz test`** runs the whole corpus, as the nightly `fuzz` workflow does.
- **`JAZZER_FUZZ=1 ./mvnw -pl <module> -am test -Dtest='<Class>#<method>'`** searches for new
  inputs; CI does this for a minute per target on every pull request.

| Input | Targets |
|---|---|
| TLS | `TlsRecordFuzzTest`, `ServerHelloFuzzTest` (with the encrypted flight), `HostnameMatchFuzzTest`, `HandshakeFuzzTest` (seclume-diff) |
| PostgreSQL | `PgDecoderFuzzTest`, `PostgresAnswersFuzzTest`, `LoginFuzzTest` |
| MySQL / MariaDB | `MyDecoderFuzzTest`, `MySqlAnswersFuzzTest`, `MyLoginFuzzTest` |
| SQL Server | `TdsDecoderFuzzTest`, `SqlServerAnswersFuzzTest`, `TdsLoginFuzzTest` |
| Oracle | `OracleDecoderFuzzTest`, `OracleAnswersFuzzTest`, `OracleLoginFuzzTest` |
| MongoDB | `OpMsgFuzzTest`, `MongoLoginFuzzTest`, `SrvFuzzTest` |
| LDAP | `LdapResponseFuzzTest` |
| SCRAM | `ScramFuzzTest` |
| Secret managers | `SecretFetchFuzzTest` (HTTP), `JsonOffFuzzTest` (JSON) |
| SPIFFE agent | `WorkloadApiAnswerFuzzTest` (X.509-SVID and JWT-SVID answers) |
| KMS answers | `KmsAnswerFuzzTest` (raw ECDSA signatures to DER, public key PEM) |
| Stored field values | `EncryptedValueFuzzTest` (any stored value; AES-GCM-SIV round trips and flipped bits) |
| Key files | `KeyFilesFuzzTest`, `NKeyFilesFuzzTest` |
| JDBC text values | `TextParsersFuzzTest` |
| Heap dumps | `BrokenDumpTest` (attribution, redaction, heapcheck's scanner; a seeded sample) |
| Contracts across protocols | `BoundaryContractTest` with `HostileTransport` (seclume-tck) |

**Found while preparing this page, and fixed with it:**
- **A heap dump could exhaust memory.** A record length in a broken dump could make attribution,
  and with it the redaction, allocate up to 2 GB. A length beyond the file is now an
  `IOException`.
- **Broken dumps failed with unchecked exceptions.** heapcheck's HPROF scanner ended them in
  `BufferUnderflowException`, `IndexOutOfBoundsException` and similar, where callers expect an
  `IOException`.
- **A SPIFFE agent's unreadable key threw the wrong exception.** It surfaced as an
  `IllegalArgumentException` instead of a broken answer.
- **A Workload API length could pass the bounds check.** A protobuf length close to 2^63 in
  the SPIFFE agent's answer wrapped the bounds check `at + length > end`, and reading it ended
  in an `IndexOutOfBoundsException`. The check is now `length > end - at`. The `parser-fuzz` job
  found this within its first minute.
- **A federated bundle without a trust domain threw the wrong exception.** In an agent's
  answer, a bundle whose trust domain was empty surfaced as an `IllegalArgumentException`
  instead of a broken answer. Found by `parser-fuzz` on its second run.

Both inputs are in the fuzz target's seed corpus (`WorkloadApiAnswerFuzzTestInputs`), so every
build replays them.

## Open questions for a reviewer

- **Constant time on a JIT.** `AesSubBytes`, `Ghash`, `ConstantTime`, `BigWords.modPowSecret`
  and the Ed25519 ladder are written branch-free and measured with dudect's method. The C2
  compiler gives no guarantee. Is the measurement adequate, and what should it cover in
  addition?
- **RSA with the password as plaintext.** `Rsa` encrypts with a public key, so the exponent is
  public, but the message is the secret. Is `BigWords`' multiplication independent of the
  operand values?
- **`TlsMigration`.** It hands a live TLS session, keys included, to another process. Review the
  transfer format, who may take it up, and that resets happen at the end of a borrow.
- **Downgrade and fallback.** TLS 1.2 is spoken where a server needs it. Check the downgrade
  sentinel, the cipher suites offered, and renegotiation being refused.
- **Field encryption.** Deterministic mode is AES-GCM-SIV with a fixed nonce per column key.
  Is the derivation of column keys (HKDF over the column's name and mode) adequate, and should
  the format carry a commitment to the key, so that one ciphertext cannot be made to open under
  two keys of the ring? The ring holds few keys chosen by the operator, which limits that.
- **Allowed exceptions.** Each `seclume-allow:` reason should be checked to really be public
  data: certificates, public keys, names, structure.
- **Native interop.** The Foreign Function & Memory calls into OpenSSL and CNG
  (`OpenSsl*`, `Cng*`, `MemoryLock`). Check lifetimes, sizes, and error paths that could leave
  a secret unzeroed.

## Reproducing

```sh
./mvnw -B -pl seclume-core,seclume-tck,seclume-heapdump,seclume-heapcheck -am test
./mvnw -B -Pfuzz -pl seclume-core -am test -Dtest='*Fuzz*'      # the whole corpus
JAZZER_FUZZ=1 ./mvnw -B -pl seclume-core -am test -Dtest='TlsRecordFuzzTest'
grep -rn "seclume-allow" --include=*.java seclume-*/src/main      # every heap exception
```

The database, broker and cluster tests need the servers that CI starts. `.github/workflows/ci.yml`
lists them job by job, with the scripts that set them up.
