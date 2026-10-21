# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub's Report a vulnerability form](https://github.com/Seclume/seclume/security/advisories/new).
Private vulnerability reporting is enabled for this repository.

Include the affected version or commit, relevant module, prerequisites,
expected and observed behavior, and a minimal reproduction using synthetic
credentials. Explain the potential security impact, including any effect on
credential handling or session isolation.

Do not include real credentials, TLS traffic secrets, heap dumps containing
secrets, or other sensitive application data.

Use a private report for security-sensitive details rather than a public issue
or pull request. Public issues remain suitable for ordinary bugs that do not
expose a vulnerability or sensitive data.

## Verifying a release

From 0.11.0 on, every release tag and every published file (jar, sources,
javadoc, POM and SBOM) is signed with this OpenPGP key - on Maven Central
(from 0.13.1) and in GitHub Packages alike:

```
seclume <dev@seclume.space>
ed25519  F232 56B6 5A0A 24B7 082A  FEE6 5A49 F7C9 2B09 AFF5
```

The public key is on `keys.openpgp.org` and `keyserver.ubuntu.com`, and in
[`KEYS`](KEYS) in this repository. To check a downloaded file:

```
gpg --recv-keys F23256B65A0A24B7082AFEE65A49F7C92B09AFF5
gpg --verify seclume-core-0.11.0.jar.asc seclume-core-0.11.0.jar
git verify-tag v0.11.0
```

Compare the full fingerprint, not just the name or the short key id.

## What is proven, and how

Claims about secrets in memory are easy to make. These are the ones the test suite proves,
each with a negative control that has to fail (see [TESTING.md](TESTING.md#proving-the-promises-not-only-the-paths)):

- **No password in a heap dump** (`HeapDumpTest`), and **none anywhere in the process**
  after a TLS login with SCRAM, with the connection closed or still open
  (`ProcessMemoryTest`, Linux: every readable region through `/proc/<pid>/mem`, about 400 MB).
  While a login runs, the password is in native memory for that moment; that moment is not
  what these tests cover.
- **No timing leak** in the comparisons of server proofs and TLS Finished, in the Java AES-GCM
  tag check, or in the Java AES (`ConstantTimeLeakageTest`, dudect's method).
- **No session state handed to the next borrower** (`SessionResetTest` on all four databases,
  and the pool as a state machine, single- and multi-threaded).
- **The own TLS agrees with OpenSSL, GnuTLS, Go, rustls and JSSE**, and refuses what it must
  (`TlsInteropTest`, and TLS-Anvil weekly).

What is not proven here is listed in the README under *What it protects, and what it does
not*.
