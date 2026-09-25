# V2Ray Subscription Filter

This project fetches selected country subscription files from
`SoliSpirit/v2ray-configs` and publishes two separate outputs for every country.

## Output type 1: Filtered

Files in:

```text
subscriptions/
```

contain only:

- VLESS with explicit `security=tls`
- VMess with `"tls": "tls"`

Everything else is excluded from the filtered output.

Duplicate configs are removed after ignoring their upstream display names.

Examples:

```text
US-VLESS-001
US-VLESS-002
US-VMESS-001
```

## Output type 2: Unfiltered but renamed

Files in:

```text
subscriptions_unfiltered/
```

preserve every non-empty upstream config line regardless of protocol or
security mode.

No protocol filtering is performed.
No TLS filtering is performed.
No deduplication is performed.
Original order is preserved.

Only the display name / remark is rewritten.

Examples:

```text
US-SS-001
US-TROJAN-001
US-VLESS-001
US-VMESS-001
US-HYSTERIA2-001
```

For VMess, the decoded JSON `ps` field is changed.
For URI-based configs, the fragment after `#` is replaced or added.

If a malformed VMess entry cannot be decoded, it is preserved unchanged rather
than removed from the unfiltered output. This is reported in
`unfiltered_rename_failures`.

## Countries

The configured countries are:

- United Kingdom
- United States
- Japan
- Russia
- Latvia
- India
- China
- Hong Kong
- Lithuania
- Bulgaria
- Turkiye
- United Arab Emirates

## Example files

Filtered United States:

```text
subscriptions/United_States.txt
```

Unfiltered renamed United States:

```text
subscriptions_unfiltered/United_States.txt
```

There is no combined all-countries subscription.

## Reports

Processing statistics are written to:

```text
reports/latest.json
```

The report contains separate counts for filtered and unfiltered outputs.

## Automatic updates

`.github/workflows/update.yml` runs every 15 minutes and can also be started
manually.

The workflow updates both output directories and commits changes only when the
generated files actually changed.

## Raw URL examples

Filtered:

```text
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/subscriptions/United_States.txt
```

Unfiltered renamed:

```text
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/subscriptions_unfiltered/United_States.txt
```

## Local tests

```bash
python -m unittest discover -s tests -v
```

Run the updater:

```bash
python scripts/update_subscriptions.py
```
