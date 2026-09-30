# Repository workflow

- Work on a dedicated branch and submit changes through pull requests.
- Add careful unit tests and regression tests wherever practical.
- Check the pull request's build jobs and resolve failures before reporting it as ready.
- Preserve migration of a live TCP socket and its JDBC connection, including
  session state and in-flight transactions across detach/resume and pool detach/adopt.
  Security resets belong at the end of a borrow, never during migration.
- Never copy or publish anything from the private `seclume-tcp-core` repository
  into this public repository: no source, tests, fixtures, documentation or artifacts.
  Public regression tests must be independently written for this repository's APIs.
