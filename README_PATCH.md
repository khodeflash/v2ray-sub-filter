# Public repository all-countries patch

Apply this patch to `khodeflash/v2ray-sub-filter`.

Changed behavior:

- Discovers every `.txt` file in `SoliSpirit/v2ray-configs/Countries` on every run.
- New upstream countries are added automatically without editing a hard-coded list.
- Uses the last successful discovered source inventory if GitHub country discovery temporarily fails.
- Fetches country files concurrently with a small worker pool.
- Preserves the existing filtered/unfiltered policy.
- Adds verifier-compatibility preflight checks for transport combinations and legacy VMess alterId.
- Removes stale country output files only after a valid source inventory is available.
- Commits `config/discovered_sources.json` so the fallback inventory stays current.

Run `Update subscriptions` manually once after committing this patch. Review `reports/latest.json` and the `subscriptions/` / `subscriptions_unfiltered/` directories before moving to the private verifier run.
