# Getting started in five minutes

A Spring Boot application whose database password lives in Vault. With seclume the
password is read into native memory, used for the login and wiped. It is never a `String`,
and no heap dump can show it. `compare.sh` proves that on your machine, against the usual way.

You need Docker with Compose, JDK 25 (for `keytool` too) and Maven.

## 1. A database and a Vault

```sh
./setup.sh
```

This starts PostgreSQL 17 and a Vault dev server with TLS on localhost. The database password
is random and is put into Vault at `secret/app`. Vault makes a CA of its own, and `setup.sh`
turns it into the trust store the application uses (`secrets/vault-ca.p12`). It and Vault's token are in `./secrets`, and
neither is ever printed.

## 2. The two dependencies

The whole integration is two dependencies in [`pom.xml`](pom.xml):

```xml
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-spring-boot-starter</artifactId>
  <version>0.13.1</version>
</dependency>
<dependency>
  <groupId>space.seclume</groupId>
  <artifactId>seclume-postgresql</artifactId>
  <version>0.13.1</version>
</dependency>
```

Add one block of configuration, in
[`application-seclume.properties`](src/main/resources/application-seclume.properties):

```properties
seclume.datasources.main.url=jdbc:seclume:postgresql://localhost:5432/app?tls=off
seclume.datasources.main.username=app
seclume.datasources.main.secret.provider=vault
seclume.datasources.main.secret.address=https://127.0.0.1:8200
seclume.datasources.main.secret.path=secret/data/app
seclume.datasources.main.secret.token-provider=file
seclume.datasources.main.secret.token-path=secrets/vault-token
```

Spring gets a pooled `DataSource`, and `JdbcTemplate`, Spring Data, Hibernate and Flyway use
it as they would any other. There is no `password=` anywhere: a secret is always a provider,
never a value. Vault is reached over HTTPS with its certificate checked; seclume refuses to
fetch a secret over plain `http://`. `tls=off` for the database is only acceptable here,
because it runs on this machine. In production, use
`tls=verify-full&tlsRootCert=/etc/ssl/db-ca.pem`.

## 3. Run it

```sh
mvn -q package -DskipTests
java --enable-native-access=ALL-UNNAMED -Djavax.net.ssl.trustStore=secrets/vault-ca.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit -jar target/seclume-getting-started-1.0.jar
```

```
connected as app on PostgreSQL 17...
running as pid 4711
```

`--enable-native-access` lets seclume use native memory without a warning. The trust store
holds Vault's dev CA, which is public; `changeit` is its customary password, not a secret.

## 4. The proof

```sh
curl -sLo seclume-heapcheck.jar \
  https://repo1.maven.org/maven2/space/seclume/seclume-heapcheck/0.13.1/seclume-heapcheck-0.13.1.jar
./compare.sh seclume-heapcheck.jar
```

`compare.sh` starts the same application twice:
- the usual way, with HikariCP and pgjdbc and the password from the environment (profile
  `plain`, which switches seclume off, since seclume refuses `spring.datasource.password`);
- with seclume.

It then has [seclume-heapcheck](../../seclume-heapcheck) take a heap dump of each JVM and
search it for the password in every encoding:

```
== the usual way: HikariCP and pgjdbc, the password from the environment
FOUND - the secret from secrets/db-password is in the heap of process 5120, 3 time(s):
  raw file: UTF-8 match of 32 bytes at 9184213
  ...

== seclume: the password from Vault into native memory
NOT FOUND - the secret from secrets/db-password is not in the heap of process 5188.

The usual way leaves the password in every heap dump; seclume does not.
```

The secret is named by its file, never by its value. This is a statement about one moment in
one process; seclume's own test suite repeats the search after logins, reconnects and
rotation, with a negative control that has to find the secret
([SECURITY.md](../../SECURITY.md#what-is-proven-and-how)).

## 5. Clean up

```sh
docker compose down -v && rm -rf secrets target
```

## Next

- **Other databases:** `seclume-mysql`, `seclume-sqlserver`, `seclume-oracle`, the same way.
- **Other secret sources:** files, AWS, Azure, GCP, Kubernetes, SPIFFE and more
  ([PROVIDERS.md](../../PROVIDERS.md)).
- **Coming from HikariCP:** `java -jar seclume-verify.jar --migrate application.properties`
  translates your settings ([MIGRATING.md](../../MIGRATING.md)).
- **Heap dumps written on `OutOfMemoryError`** can be redacted where they lie
  ([DIAGNOSTICS.md](../../DIAGNOSTICS.md)).
