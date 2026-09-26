# Does your heap dump contain your database password?

A side-by-side run of the same application, once with the usual stack and once with seclume,
followed by a search of both heaps.

```
./run.sh <dir with seclume-core.jar, seclume-postgresql.jar, seclume-heapcheck.jar, postgresql.jar>
```

Needs a Linux host with podman. Everything runs in one pod:

- **PostgreSQL 17**, whose password is a random value made for this run;
- **a Vault dev server** (with TLS) that holds that password at `secret/app`; its root token is
  random too;
- **`VendorApp`**: reads the password from Vault over HTTPS, as Spring Cloud Vault or any HTTP
  client would, which makes it a `String`, and connects with **pgjdbc**;
- **`SeclumeApp`**: connects with **seclume**, whose Vault provider reads the answer into native
  memory, uses the password for the login and wipes it.

Both applications connect, run a query, drop their own references, call `System.gc()` and keep
running, like a service with an open connection. Then
[`seclume-heapcheck`](../../seclume-heapcheck) asks each JVM for a heap dump and searches it for
the password and for the Vault token, as UTF-8, UTF-16 and Latin-1, in `String`s, arrays and
the raw file.

## Result (25.09.2026, JDK 25, pgjdbc 42.7.13)

![recording](heap-dump.gif)

The recording is also here as an asciicast (`heap-dump.cast`, `asciinema play heap-dump.cast`).
It was made with `script` and rendered with `agg`; it holds no secret, only the output below.


```
== pgjdbc - the password from Vault as a String
  database password:
    FOUND - the secret is in the heap of process 26, 2 time(s):
      raw file: UTF-8 match of 31 bytes at 8175627
      byte[] 30308835136: UTF-8 match of 31 bytes at 132
  Vault token:
    FOUND - the secret is in the heap of process 26, 2 time(s):
      raw file: UTF-8 match of 31 bytes at 8179605
      byte[] 30308837096: UTF-8 match of 31 bytes at 0

== seclume - the password from Vault into native memory
  database password:
    NOT FOUND - the secret from /shared/db-password is not in the heap of process 46.
  Vault token:
    NOT FOUND - the secret from /shared/vault-token is not in the heap of process 46.
```

The `byte[]` on the pgjdbc side is the inside of a `String`: since Java 9 a Latin-1 string keeps
its characters in a `byte[]`. Setting the variable to `null` and asking for a GC did not remove
it. The driver keeps its own reference to the password for reconnecting, and the garbage
collector does not zero memory it frees in any case.

## What this does and does not show

- It shows one moment in one process. `heapcheck` says the same: "a statement about this moment,
  not a guarantee". seclume's own test suite repeats the search after logins, failed logins,
  reconnects, pool refills and credential rotation, with a negative control that must fail.
- The native memory seclume uses is not part of a heap dump. It is also kept out of crash dumps
  (`MADV_DONTDUMP` on Linux, `WerRegisterExcludedMemoryBlock` on Windows), locked against
  swapping where the limits allow it, and wiped after use. See
  [SECRETS-API.md](../../SECRETS-API.md).
- The Vault token is found on the pgjdbc side because the application read it into a `String`,
  not because of pgjdbc. That is the point: with the usual libraries, every secret that passes
  through them ends up there.
