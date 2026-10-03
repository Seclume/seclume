# TLS

Everything about encryption and server authentication: the four modes, trusting a CA the JVM
does not know, the two TLS stacks, SQL Server's strict encryption, PostgreSQL 17's direct
TLS, and client certificates with the key off the heap.

## The mode, and the difference said out loud

```properties
jdbc:seclume:postgresql://db:5432/app?tls=verify-full
```

| `tls` | What it does |
|---|---|
| `off` | no encryption |
| `prefer` | encrypt if offered — stops a listener, not a man in the middle |
| `require` | encrypt or refuse; still no certificate check |
| `verify-full` | encrypt **and** check the certificate against the trust store and the host dialled |

Only `verify-full` authenticates the server. A driver that offers the first three and calls
the result secure is lying by omission. On PostgreSQL the login is additionally bound to the
connection (SCRAM-SHA-256-PLUS), and when the server offers no binding the client says so
rather than staying silent.

## A CA the JVM does not know, without switching the check off

A server whose CA the JVM does not know (an internal CA, a cloud provider's, a self-signed
certificate) fails `verify-full` with "PKIX path building failed". The answer usually found is
to switch the check off. Two ways that keep it:

```properties
# the CA for this connection alone, as libpq's sslrootcert - the JVM's trust store untouched
jdbc:seclume:postgresql://db:5432/app?tls=verify-full&tlsRootCert=/etc/tls/db-ca.pem
# the server's key itself: no CA, no chain, no host name - compared byte for byte
jdbc:seclume:postgresql://db:5432/app?tls=verify-full&tlsPin=sha256/<base64>
```

**Amazon RDS needs no file at all:** `tlsRootCert=aws-rds` uses RDS's global CA bundle, which
ships with seclume (108 certificates, every region, fetched 25.09.2026). Azure Database chains to
a root the JVM already trusts. Cloud SQL has a CA per instance, which you download from the
console and name as a file.

`java -jar seclume-verify.jar --print-pin "<url>"` connects once without checking and prints
the pin, with the certificate's subject, issuer and expiry. Compare it with what the server's
owner says before it goes into the URL. Both options work on all four drivers and both TLS
stacks, SQL Server's TDS 7.4 handshake included (until 25.09.2026 it ignored them and checked
no host name). A pin is the trust on its own, even with `trustServerCertificate=true`. A wrong
pin is refused before a byte of the protocol, naming the pin the server did present.

## Which TLS carries it: a separate question

```properties
jdbc:seclume:postgresql://db:5432/app?tls=require&tlsStack=seclume
```

| `tlsStack` | What provides the encryption |
|---|---|
| `auto` | the default: `seclume`, and `jsse` for a server that cannot speak it |
| `seclume` | this project's own TLS 1.3 client, and nothing else |
| `jsse` | the JDK's `SSLEngine`, what every JDBC driver does |

**`auto`** connects with the own stack first. A server that refuses it before its ServerHello -
TLS 1.2 only, no group in common, or hanging up on the ClientHello - is connected to again
through JSSE, and a warning names the server: from then on its password passes through the heap.
The server is remembered for an hour, so a pool does not try twice per connection, and is then
tried on the own stack again. Nothing else changes stack: an untrusted certificate, a wrong host
name or a refused login fails as before. With a client certificate there is no fallback, since
its key is reachable only from the own stack. The fallback can be provoked by anyone on the path
who answers the ClientHello with an alert; what that gains them is JSSE's TLS with the
certificate still checked, the password on this process's heap rather than on the wire.
`tlsStack=seclume` closes that too, and refuses servers without TLS 1.3. SQL Server reaches
the own stack only with `tds=8.0`; TDS 7.4 nests TLS 1.2 in its pre-login and always uses JSSE.

Every mode above works on either stack, so this is a capability setting, not a security one.
The own stack gives up resumption, TLS 1.2 and every key exchange group but two. It offers P-256
and, where the operating system has ML-KEM, the post-quantum hybrid
**X25519MLKEM768** beside it: OpenSSL 3.5 or later on 64-bit Linux, CNG on Windows 11 with
the post-quantum update (tested on build 26200.9457), against traffic recorded now and decrypted
later. A server without the hybrid picks P-256 at once, and `-Dseclume.tls.postQuantum=false`
switches the hybrid off. A CI job proves the hybrid end to end against OpenSSL 3.5's `s_server`
(`HybridHandshakeTest`); the CNG path is checked against the JDK's own ML-KEM and X25519
(`HybridMlKemTest`). Only the key exchange is post-quantum; certificates and signatures are
classical, as everywhere in TLS today. In return
it gains two things JSSE cannot offer at any price: **the traffic secrets never become Java
objects**, and the encryption state can be frozen and taken up elsewhere, which is what a
connection that survives moving host needs. Since the external audit of 30.09.2026 (SEC-04)
that is why it is tried first.

**All four drivers are proven on it against real servers**: PostgreSQL and MySQL with channel
binding, Oracle over a TCPS listener, and SQL Server with `tds=8.0` (see below).

**What the own stack is, and what it is not.** It is new code, and it has not been through an
independent review. That is why it is not the default. It keeps the risky parts small:

- The **server certificate** is checked by the JDK: its `X509TrustManager`, and `Signature`
  for CertificateVerify.
- The **key exchange** runs in the operating system's crypto library: P-256 and ML-KEM
  through OpenSSL on Linux and CNG on Windows.
- **AES-GCM** for the records goes through the same libraries, which is constant time and
  hardware-accelerated. A platform without them falls back to a constant-time Java AES,
  which is much slower.

Written here, in Java, are the handshake state machine, the HKDF key schedule, the record
framing and the transcript. Everything a server can send before a key exists is fuzzed
(`ServerHelloFuzzTest`).

## SQL Server: `tds=8.0`

**SQL Server needs `tds=8.0` as well**, and that is not a detail. Its ordinary handshake runs
*inside* TDS packets and is TLS 1.2 by construction. TLS 1.3 moves handshake messages past the
point where that nesting would have to invert. TDS 8.0 (Microsoft calls it strict encryption)
puts TLS around the whole connection from the first byte instead:

```properties
jdbc:seclume:sqlserver://db:1433/app?tds=8.0&tlsStack=seclume
```

Proven against SQL Server 2025. **SQL Server 2022 on Linux does not accept strict encryption
at all**, and Microsoft's own driver fails against it the same way. So `tds=7.4` stays the
default and nothing changes for anybody who does not ask.

## PostgreSQL 17: direct TLS, one round trip fewer

```properties
jdbc:seclume:postgresql://db:5432/app?tls=verify-full&tlsNegotiation=direct
```

The handshake starts at once, with ALPN `postgresql`, instead of first sending an
`SSLRequest` and waiting for its one-byte answer. That is one round trip fewer on every
connect, which is most of what a pool's warm-up and a serverless cold start pay. libpq's
spelling, `sslnegotiation=direct`, is accepted too. It needs PostgreSQL 17 or later. An older
server refuses it and the connect fails; it does not quietly fall back. Both stacks.

## Mutual TLS, with the client key off the heap too

A password held carefully protects nothing while the private key that authenticates the
*same* connection sits in an unwipeable `PrivateKey`: whoever has that key does not need the
password. So seclume signs the client `CertificateVerify` with a P-256 key that never becomes
a Java object. The key file goes through a secret provider into native memory,
`EcPrivateKeyFile` picks the scalar out of the PKCS#8 or SEC1 structure in place, and CNG or
OpenSSL keeps it from there. Only the certificate chain and the signature, both public, are
ordinary objects.

Two settings say it, in a URL or in `application.properties`:

```properties
jdbc:seclume:postgresql://db:5432/app?tls=verify-full&tlsStack=seclume&clientCert=/etc/tls/client.crt&clientKey-provider=file&clientKey-path=/etc/tls/client.key
```

The certificate is a path because it is public. The key is a **provider**: the same
`clientKey-`-prefixed block accepts `vault`, `dpapi`, `encrypted` or anything else that works
for a password, so the key can arrive the way the rest of your secrets do. Or hand one in
directly, when the application builds it itself:

```java
try (ClientIdentity me = new P256ClientIdentity(Path.of("/etc/tls/client.crt"),
                                                SecretProviders.of(Map.of(
                                                    "provider", "file",
                                                    "path", "/etc/tls/client.key")))) {
    dataSource.setClientIdentity(me);
}
```

The identity is built **once per configuration** and shared. A pool of fifty connections
loads one key, because loading it is what puts it in native memory, and there it stays until
the identity is closed.

**A rotated certificate is picked up without a restart.** The configured identity follows its
certificate file: when cert-manager renews it or a SPIFFE agent writes a new SVID, the next
handshake loads the new pair. A certificate that lands before its key is refused by the pair
check and the working identity carries on; the replaced key leaves native memory after a
short grace period.

**Or a key that never enters the process at all.** On Windows, `clientCertThumbprint=...`
names a certificate in the certificate store, and its key is used through CNG by handle. With
a non-exportable key not even the owning account can read it out, and enrolled with the
Microsoft Platform Crypto Provider it lives in the TPM and never leaves it.

**And no password at all.** `provider=none` with a client certificate is a login by the
certificate alone: PostgreSQL's `cert` method, or a MySQL account with an empty password and
`REQUIRE SUBJECT`. The only credential left is the key, and it need not be in the process.

Two things are refused rather than worked around:

- **P-256 only.** An RSA client certificate would mean the JCA, and the JCA means the key on
  the heap.
- **`tlsStack=seclume` is required.** Presenting a certificate through the JDK's TLS needs a
  `KeyManager`, which hands out a `PrivateKey`. So that combination fails with a message
  saying so, instead of connecting quietly without the certificate the configuration asked
  for.

All four drivers can present a client certificate with the key off the heap. SQL Server needs
`tds=8.0` for it, and Oracle a TCPS listener, for the reasons above.
