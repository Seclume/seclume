# Bundled Public Suffix List

`public_suffix_list.dat` is an unmodified snapshot of the Mozilla Public
Suffix List, including both ICANN and PRIVATE sections. It is distributed
under MPL-2.0; the full license is in `public-suffix-LICENSE.txt`.

- Upstream: https://publicsuffix.org/list/
- Source commit: `6cd82aff889e3d64e5e03bc5c1f43da1934a960a` (2026-10-01)
- Source: https://github.com/publicsuffix/list/blob/6cd82aff889e3d64e5e03bc5c1f43da1934a960a/public_suffix_list.dat
- SHA-256: `102b252c18b5f87f4c81f017e75282a82c18e00cd0c2e601b5b02a0f7a601f2c`

The TLS hostname matcher uses the ICANN section to reject certificate wildcards
at public suffix boundaries. PRIVATE hosting entries are not certificate
issuance boundaries and may legitimately have provider wildcard certificates,
including RDS endpoints. This matches OpenJDK's ICANN restriction for its
public-CA wildcard boundary check. PSL exceptions remain eligible wildcard bases.
There is no download during a connection or build.

Review updates before releases: obtain the upstream list, record its source
commit and SHA-256 here, retain its license notices, and run
`HostnameMatchTest`, `PublicSuffixesTest` and `CertificateTrustTest` against
the new snapshot. Review the diff for newly protected hosting boundaries
and changed exceptions before merging.
