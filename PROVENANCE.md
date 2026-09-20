# Where the protocol knowledge came from

Four wire protocols are implemented here from scratch. This page says, for each of them, what
that knowledge rests on — because "we wrote it ourselves" is a claim, and a reader is entitled
to see what stands behind it.

**In one sentence:** no vendor source code, no vendor headers, and nothing decompiled. Three
of the four protocols have published specifications and were implemented from them. The
fourth, Oracle, has none — and the largest single source there is Oracle's **own** driver,
which Oracle publishes under a permissive licence that expressly allows reimplementation.

At runtime no vendor driver is present: not used, not wrapped, not delegated to. There is no
`ojdbc`, `mssql-jdbc`, `Connector/J` or `pgjdbc` on the class path, and none is needed.

## PostgreSQL

Implemented from the **Frontend/Backend Protocol** chapter of the official PostgreSQL
documentation, which specifies every message type and field. SCRAM-SHA-256 and its channel
binding follow RFC 5802 and RFC 7677.

Nothing here required observation: the specification is complete enough to write a driver
against, and where behaviour was checked it was checked against a running server — not against
another client's code.

## MySQL and MariaDB

Implemented from the **client/server protocol** documentation that MySQL and MariaDB both
publish, including the descriptions of `caching_sha2_password` and `mysql_native_password`.

## Microsoft SQL Server

Implemented from **[MS-TDS], Tabular Data Stream Protocol**, which Microsoft publishes as part
of its Open Specifications and places under the Microsoft Open Specification Promise. That
document specifies the packet framing, the login exchange, the token stream and the type
encodings.

## Oracle

Oracle is the exception: **there is no published specification** of TNS/NS or TTC. Four
sources were used, and which one supplied which field is documented — source by source — in
the project's internal notes.

| Source | What it is | What it supplied |
|---|---|---|
| **`python-oracledb`** | Oracle's own thin driver, published by Oracle under **UPL-1.0 or Apache-2.0** — licences that permit an independent reimplementation | The verifier types, the 12c password hash, session key length, combo key derivation, the layout of `AUTH_PASSWORD` |
| **Oracle's own documentation** on 12c password versions | vendor documentation | Confirms the PBKDF2 and final SHA-512 structure |
| **A published 2012 analysis** of CVE-2012-3137 | a public mailing-list post describing the method in prose | Confirms the 11g key derivation and AES-192-CBC with a zero IV |
| **Observation of a running server** | our own instance of Oracle Database Free, which we license | The fixed fields of the CONNECT packet, and several places where the derived values were wrong |

**The method, and its limits, stated plainly.** Descriptions of behaviour were read; **no
source code was taken**. The implementation works on `MemorySegment` rather than on Python
objects, is structured differently, and is cross-checked against the JDK's own cryptography.
Where a value could not be derived it is treated as observed rather than explained — such
places are marked as unestablished rather than given an invented reason.

No Oracle server source, no Oracle headers, and no decompilation of `ojdbc` or of any other
Oracle binary went into this.

## Why observation is a legitimate source

For the part that rests on watching a server behave rather than on reading a specification,
the basis is the European interoperability regime:

- **Directive 2009/24/EC, Article 5(3)** — a person entitled to use a program may observe,
  study and test its functioning in order to determine the ideas and principles underlying it.
- **Directive 2009/24/EC, Article 6** — decompilation is permitted where indispensable to
  obtain the information necessary for interoperability with an independently created program.
- **Directive 2009/24/EC, Article 8** — contractual provisions contrary to Article 6, or to
  the exceptions in Article 5(2) and (3), are **null and void**. A licence term forbidding
  what those articles allow does not take the right away.
- In Germany these are **§ 69d(3) and § 69e UrhG**.

Interoperability is exactly the purpose: the point of this project is to let an application
talk to a database it already owns and already licenses.

Two honest caveats. First, this is a statement of the basis on which the work was done, not
legal advice, and it has not been reviewed by a lawyer. Second, the strongest ground is the
Oracle part that comes from `python-oracledb`, because that is Oracle's own code under a
licence that permits reimplementation — the interoperability provisions are the backstop for
the remainder, not the main support.

If you are evaluating this for use somewhere that needs a firmer answer than a page in a
repository, ask, and the detailed record will be produced.

## Trade marks

Oracle, MySQL, MariaDB, Microsoft, SQL Server and PostgreSQL are the trade marks of their
respective owners. They are used here only to say which database a driver speaks to. No
affiliation with, or endorsement by, any of them is claimed or implied.
