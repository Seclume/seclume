# Micronaut, from `application.yml` alone

A Micronaut application whose database password lives in Vault. The pool reads it into native
memory, logs in and wipes it. There is no line of seclume code in the application: it asks
Micronaut for a `DataSource` and gets seclume's pool.

You need Docker with Compose, JDK 25 and Maven. seclume-micronaut is new in 0.14.0.

## 1. A database and a Vault

The same as for [getting-started](../getting-started/README.md#1-a-database-and-a-vault):

```sh
../getting-started/setup.sh
```

## 2. The two dependencies

```xml
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-micronaut</artifactId>
  <version>0.14.0</version>
</dependency>
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-postgresql</artifactId>
  <version>0.14.0</version>
</dependency>
```

and [`application.yml`](src/main/resources/application.yml):

```yaml
seclume:
  datasources:
    default:
      url: "jdbc:seclume:postgresql://localhost:5432/app?user=app&tls=off\
        &provider=vault&address=https://127.0.0.1:8200&path=secret/data/app\
        &token-provider=file&token-path=../getting-started/secrets/vault-token"
      pool:
        maximum-pool-size: 4
        warmup: true
```

Every `seclume.datasources.<name>` is a `SeclumePool` bean named `<name>`, `default` the
unqualified one; `pool.*` takes the pool's settings under their usual names. A key ring under
`seclume.field-encryption.keys.<n>.*` becomes an injectable `FieldKeys`
([ENCRYPTION.md](../../ENCRYPTION.md)). `password` anywhere - under `seclume.datasources`,
beside a seclume URL in `datasources.*`, or in the URL - stops the start, and the message names
the property, never its value.

## 3. Run it, and the proof

```sh
mvn -q package -DskipTests
java --enable-native-access=ALL-UNNAMED -Djavax.net.ssl.trustStore=../getting-started/secrets/vault-ca.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit -cp "target/classes:target/lib/*" example.Application
```

```sh
../check-example.sh micronaut example.Application seclume-heapcheck.jar
```

```
== micronaut: from the configuration file alone
connected as app on PostgreSQL 17...
== a heap dump of process 5120, searched for the password
NOT FOUND - the secret from ../getting-started/secrets/db-password is not in the heap of process 5120.
== a password in the configuration
seclume.datasources.default.password ...

micronaut: connected through Vault, no password in the heap, a configured password refused.
```

[`check-example.sh`](../check-example.sh) starts the application, has
[seclume-heapcheck](../../seclume-heapcheck) search a heap dump of it for the password in every
encoding, then starts it again with `-Dseclume.datasources.default.password=...` and checks
that it refuses to start without printing the value. CI runs it on every pull request.
