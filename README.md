# Static-only public workflow patch

Replace `.github/workflows/update.yml` in the public repository with the file
in this package.

This keeps the public repository responsible only for:

- fetching upstream sources,
- static filtering,
- unfiltered remark rewriting,
- static filter reports.

It intentionally removes:

- Xray installation,
- active geo verification on GitHub-hosted runners,
- writes to `subscriptions_verified`,
- writes to legacy geo verification reports.

The VPS-backed private repository will become the only writer for verified
subscription outputs.
