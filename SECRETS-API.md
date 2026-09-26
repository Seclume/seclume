# Keeping a secret off the heap in your own library

The drivers are one use of `seclume-core`. The same few classes serve any Java code that holds
a secret: a mail client's password, an API key, a webhook's signing key, a Kafka SASL
credential. Depend on `seclume-core` alone. It has no dependency beyond the JDK, as its SBOM
states.

```xml
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-core</artifactId>
  <version>0.9.0</version>
</dependency>
```

## The four classes

| Class | What it is for |
|---|---|
| `SecretProviders.fromUri("file:/run/secrets/key")` | Where the secret comes from, in one line. Every provider in [PROVIDERS.md](PROVIDERS.md) works: files, Vault, the cloud vaults, DPAPI, workload identity |
| `SecretProvider` | The same, as an object: your users configure it, or implement it themselves |
| `SecretScope.fromProvider(provider)` | The secret in native memory that is locked against swapping and left out of crash dumps. It is wiped on `close()` |
| `space.seclume.crypto.Hmac`, `Pbkdf2`, `AesGcm`, … | Cryptography that works on `MemorySegment`, so the secret is used where it lies |

## The pattern

Read the secret, use it, and wipe it, all in native memory and inside one `try`:

```java
static String sign(SecretProvider source, byte[] payload) {
    try (SecretScope key = SecretScope.fromProvider(source);
         Hmac mac = new Hmac(HashAlgorithm.SHA_256, key.secret());
         Arena arena = Arena.ofConfined()) {
        MemorySegment data = arena.allocate(payload.length);
        MemorySegment.copy(payload, 0, data, ValueLayout.JAVA_BYTE, 0, payload.length);
        mac.update(data);
        MemorySegment out = arena.allocate(mac.macLength());
        mac.doFinal(out, 0);
        return HexFormat.of().formatHex(out.toArray(ValueLayout.JAVA_BYTE));   // public
    }
}

String signature = sign(SecretProviders.fromUri("file:/run/secrets/webhook-key"), body);
```

Three rules make the difference:
- **Never let the secret become a `String` or a `char[]`.** Neither can be wiped, and a
  `String` may be interned or copied by the JVM.
- **Take configuration that says where the secret is, not what it is.**
  `SecretProviders` refuses a `password=` setting for exactly this reason.
- **Send the secret as bytes from native memory, not as a string built for the purpose.**
  A socket or a TLS channel can take a `MemorySegment`.

## Prove it in your tests

`seclume-tck` holds `NoSecretInHeap`. It takes a real heap dump and searches it, in a process
of its own, for the secret in a file:

```java
NoSecretInHeap.assertAbsent(Path.of("/run/secrets/webhook-key"));
```

The example above is a test in this repository (`LibraryUseTest`), with the control that
makes it mean something: the same key, held as a `String` on purpose, is found.

## What stays stable

From 1.0 on, these follow semantic versioning:
- in `space.seclume.secret`: `SecretProvider`, `SecretProviders`, `SecretScope`, and
  `ExpiringCredentials`;
- the algorithm classes in `space.seclume.crypto`.

`mvn -Papicheck verify` checks each release against the last one. `space.seclume.internal` is
not part of that promise.
