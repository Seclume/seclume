# Contributing to seclume

Use [GitHub issues](https://github.com/Seclume/seclume/issues) for ordinary bug
reports, feature requests and design discussions. English reports and comments
are welcome. Include the affected version, module, expected and observed
behavior, and a small reproduction with synthetic data.

Report suspected vulnerabilities privately using the process in
[SECURITY.md](SECURITY.md). Do not attach production credentials or dumps
containing secrets to public issues or pull requests.

## Pull requests

Work on a dedicated branch and open a pull request against `main`. Explain the
problem, the resulting behavior, and how the change was verified. Keep changes
focused and preserve existing public API behavior unless an intentional change
is described. Include relevant user-facing changes in [CHANGELOG.md](CHANGELOG.md).

The repository requires successful CI and security checks before merging.
Documentation-only pull requests also run the required checks. A change is
ready when its current commit passes; a failed check needs investigation.

Add automated regression tests for fixes and tests for substantial new
behavior. A useful regression exercises a concrete failure and passes after
the fix; for security checks, include a failing control where practical.
Database behavior must also be exercised against the relevant real servers
in CI. See [TESTING.md](TESTING.md) for the testing approach.

## Building and checking a change

Use Java 25 and the checked-in Maven wrapper:

```sh
./mvnw -B test
./mvnw -B -pl seclume-postgresql -am test
```

On Windows, use `mvnw.cmd`. Tests needing a database or another service can be
skipped locally when it is unavailable; that does not replace the corresponding
CI integration tests. See [README.md](README.md#building-and-testing) for build
profiles and local service settings.

Follow the surrounding Java style. The build enables compiler warnings and
treats them as errors. Address warnings and confirmed findings from CodeQL,
Semgrep and the dependency checks rather than broadly suppressing them.

Keep credentials and traffic secrets out of Java heap objects. Use the existing
secret-handling APIs, keep bounds checks and cleanup intact, and do not add a
runtime dependency to a driver without discussing the effect on its design.

For cryptographic changes, identify the protocol or algorithm specification,
the interoperability requirements, and the test vectors used. Preserve peer
authentication and fail-closed behavior. Check [TLS.md](TLS.md) and
[PROVENANCE.md](PROVENANCE.md) when changing protocol implementations.

## Releases and vulnerability fixes

Release versions and tags are unique and follow the numbering described in
[CHANGELOG.md](CHANGELOG.md). Release notes describe behavior changes and their
effect on users. When a release fixes a publicly known vulnerability in seclume
with an assigned CVE or advisory identifier, include that identifier and the
affected and fixed versions in the release notes. Coordinate disclosure of
non-public reports through the private reporting process first.
