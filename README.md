# V2Ray Subscription Filter

A small GitHub Actions project that fetches country subscription files from
`SoliSpirit/v2ray-configs`, validates them, removes unwanted entries, and
publishes clean per-country subscriptions plus one combined subscription.

## Default filtering policy

The default policy is intentionally conservative:

- Shadowsocks (`ss://`) is always rejected.
- VLESS is kept only with explicit `security=tls` or `security=reality`.
- Trojan is kept only with explicit `security=tls` or `security=reality`.
- VMess is kept only when its decoded JSON contains `"tls": "tls"`.
- Unsupported protocols are rejected.
- Malformed entries are rejected.
- Duplicate links are removed while preserving order.

Reality support can be disabled in `config/sources.json` by setting:

```json
"allow_reality": false
```

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

Add or remove countries only in `config/sources.json`. The Python script and
workflow do not need to be duplicated.

## Output

Generated files are written to:

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
subscriptions/All.txt
```

The latest processing statistics are written to:

```text
reports/latest.json
```

## Update schedule

The workflow in `.github/workflows/update.yml` runs every 15 minutes and can
also be started manually from the GitHub Actions page.

The workflow:

1. Checks out the repository.
2. Sets up Python.
3. Runs unit tests.
4. Downloads every configured upstream subscription.
5. Filters, validates, and deduplicates the entries.
6. Generates per-country files and `All.txt`.
7. Writes `reports/latest.json`.
8. Commits only when generated content changed.

## Fail-safe behavior

For each country:

- If the upstream download fails and a previous generated file exists, the
  previous file is kept.
- If filtering unexpectedly produces zero entries and a previous generated
  file exists, the previous file is kept.
- HTML error pages and empty responses are not accepted as subscriptions.

This avoids replacing a working subscription with an empty file during a
temporary upstream problem.

## First GitHub setup

1. Create a new GitHub repository.
2. Upload the contents of this project to the repository root.
3. Open the repository's **Actions** tab.
4. Enable workflows if GitHub asks.
5. Run **Update filtered subscriptions** manually once.
6. Confirm that the `subscriptions` folder and `reports/latest.json` were
   generated and committed.

If the workflow cannot push, open:

```text
Settings -> Actions -> General -> Workflow permissions
```

and allow **Read and write permissions** for `GITHUB_TOKEN`.

## Raw subscription URLs

After the first successful workflow run, a country subscription can be used as:

```text
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/subscriptions/United_States.txt
```

The combined subscription is:

```text
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/subscriptions/All.txt
```

Replace `YOUR_USERNAME` and `YOUR_REPOSITORY` with your repository details.

## Local test

No third-party Python packages are required.

Run tests:

```bash
python -m unittest discover -s tests -v
```

Run the updater:

```bash
python scripts/update_subscriptions.py
```

## Important note

This project does not modify, delete, or push changes to the upstream
`SoliSpirit/v2ray-configs` repository. It only reads public raw subscription
files and publishes filtered copies in your own repository.
