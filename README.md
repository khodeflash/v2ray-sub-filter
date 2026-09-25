# V2Ray Subscription Filter

This project fetches selected country subscription files from
`SoliSpirit/v2ray-configs`, keeps only TLS-enabled VLESS and VMess configs,
renames them to a clean standardized format, and publishes one subscription
file per country.

## Filtering policy

Only these configs are published:

- VLESS with explicit `security=tls`
- VMess with `"tls": "tls"`

Everything else is rejected, including:

- Shadowsocks
- Trojan
- VLESS Reality
- VLESS without TLS
- VMess without TLS
- Unsupported protocols
- Malformed configs

## Renaming policy

Published configs are renamed automatically:

```text
US-VLESS-001
US-VLESS-002
US-VMESS-001
JP-VLESS-001
UK-VMESS-001
```

For VLESS, the URI fragment after `#` is replaced.

For VMess, the decoded JSON `ps` field is replaced.

The connection parameters are otherwise preserved.

## Duplicate handling

Duplicate detection ignores the upstream display name.

This means two identical configs with different advertising names are treated
as duplicates and only one is published.

## Countries

The initial configuration includes:

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

Sources and country codes are configured in:

```text
config/sources.json
```

## Output

One file is generated per country:

```text
subscriptions/United_Kingdom.txt
subscriptions/United_States.txt
subscriptions/Japan.txt
subscriptions/Russia.txt
subscriptions/Latvia.txt
subscriptions/India.txt
subscriptions/China.txt
subscriptions/Hong_Kong.txt
subscriptions/Lithuania.txt
subscriptions/Bulgaria.txt
subscriptions/Turkiye.txt
subscriptions/United_Arab_Emirates.txt
```

There is no combined `All.txt` subscription.

If an older version of this project created `subscriptions/All.txt`, the update
script removes it automatically.

## Reports

The latest processing statistics are written to:

```text
reports/latest.json
```

The report includes accepted VLESS and VMess counts as well as rejection
reasons for every country.

## Update schedule

The workflow in `.github/workflows/update.yml` runs every 15 minutes and can
also be started manually from the GitHub Actions page.

## Fail-safe behavior

For each country:

- If the upstream download fails and a previous generated file exists, the
  previous file is preserved.
- If filtering unexpectedly produces zero entries and a previous generated
  file exists, the previous file is preserved.
- Empty responses and HTML error pages are rejected.

## GitHub setup

After replacing the project files in your repository:

1. Commit and push the changes.
2. Open the repository **Actions** tab.
3. Run **Update filtered subscriptions** manually once.
4. Confirm that all country subscription files were updated.
5. Confirm that `subscriptions/All.txt` no longer exists.

If the workflow cannot push:

```text
Settings -> Actions -> General -> Workflow permissions
```

Enable **Read and write permissions**.

## Raw subscription example

```text
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/subscriptions/United_States.txt
```

## Local tests

No third-party Python packages are required.

```bash
python -m unittest discover -s tests -v
```

Run the updater manually:

```bash
python scripts/update_subscriptions.py
```
