# Helidon MP, from `microprofile-config.properties` alone

A Helidon MP application whose database password lives in Vault. The application injects a
`DataSource`; seclume's CDI extension, found on the class path, makes it a pool that reads the
password into native memory, logs in and wipes it. There is no line of seclume code in the
application.

You need Docker with Compose, JDK 25 and Maven. seclume-helidon is new in 0.14.0.

## 1. A database and a Vault

The same as for [getting-started](../getting-started/README.md#1-a-database-and-a-vault):

```sh
../getting-started/setup.sh
```

## 2. The two dependencies

```xml
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-helidon</artifactId>
  <version>0.14.0</version>
</dependency>
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-postgresql</artifactId>
  <version>0.14.0</version>
</dependency>
```

and [`META-INF/microprofile-config.properties`](src/main/resources/META-INF/microprofile-config.properties):

```properties
seclume.datasources.default.url=jdbc:seclume:postgresql://localhost:5432/app?user=app&tls=off\
  &provider=vault&address=https://127.0.0.1:8200&path=secret/data/app\
  &token-provider=file&token-path=../getting-started/secrets/vault-token
seclume.datasources.default.pool.maximum-pool-size=4
seclume.datasources.default.pool.warmup=true
```

The application ([`Hello.java`](src/main/java/example/Hello.java)):

```java
@ApplicationScoped
public class Hello {
    @Inject
    DataSource dataSource;     // seclume's pool; @Named("orders") for seclume.datasources.orders
    ...
}
```

Every `seclume.datasources.<name>` is a `DataSource` and `SeclumePool` bean with `@Named("<name>")`,
`default` also the `@Default` one; a key ring under `seclume.field-encryption.keys.<n>.*` is an
injectable `FieldKeys`. A password in the configuration - under `seclume.datasources`, as
Helidon's own `javax.sql.DataSource.<name>.password` beside a seclume URL, or in the URL - is a
deployment error, named by its property, never by its value.

**Helidon SE** has no CDI: `SeclumeHelidon seclume = SeclumeHelidon.create(Config.create())`
reads the same keys from `application.yaml` and hands out `seclume.dataSource("default")`.

## 3. Run it, and the proof

```sh
mvn -q package -DskipTests
java --enable-native-access=ALL-UNNAMED -Djavax.net.ssl.trustStore=../getting-started/secrets/vault-ca.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit -cp "target/classes:target/lib/*" example.Main
```

```sh
../check-example.sh helidon example.Main seclume-heapcheck.jar
```

[`check-example.sh`](../check-example.sh) starts the application, has
[seclume-heapcheck](../../seclume-heapcheck) search a heap dump of it for the password in every
encoding, then starts it again with `-Dseclume.datasources.default.password=...` and checks that
it refuses to start without printing the value. CI runs it on every pull request.
