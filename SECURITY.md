# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub's Report a vulnerability form](https://github.com/Seclume/seclume/security/advisories/new).
Private vulnerability reporting is enabled for this repository.

Include the affected version or commit, relevant module, prerequisites,
expected and observed behavior, and a minimal reproduction using synthetic
credentials. Explain the potential security impact, including any effect on
credential handling, session isolation, or connection migration.

Do not include real credentials, TLS traffic secrets, heap dumps containing
secrets, or live connection migration blobs. Do not publish source, tests or
artifacts from the separately licensed private TCP transport in this public
repository. Describe transport-related issues in the private report without
attaching private implementation material.

Use a private report for security-sensitive details rather than a public issue
or pull request. Public issues remain suitable for ordinary bugs that do not
expose a vulnerability or sensitive data.
