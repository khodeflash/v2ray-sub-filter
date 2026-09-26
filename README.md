# V2Ray Subscription Filter + Geo Verifier

This repository fetches selected country subscriptions from
`SoliSpirit/v2ray-configs` and publishes three outputs for every country.

## 1. Filtered output

Directory:

```text
subscriptions/
```

Contains only:

- VLESS + TLS
- VLESS + REALITY
- VMess + TLS

The existing Xray preflight checks are applied before publication.

## 2. Verified output

Directory:

```text
subscriptions_verified/
```

This is the strictest output.

For each config from `subscriptions/`, the GitHub Action starts a real local
Xray client, routes a request through that outbound, fetches Cloudflare
`cdn-cgi/trace`, reads the exit `ip` and `loc`, and compares the detected
country with the expected ISO country code for that source file.

Only configs that:

1. pass the static filter,
2. pass Xray preflight validation,
3. establish a real proxy tunnel from the GitHub runner,
4. return a usable geo response, and
5. exit from the expected country

are published here.

Examples of expected country mapping:

```text
United Kingdom        -> GB
United States         -> US
Japan                 -> JP
Russia                -> RU
Latvia                 -> LV
India                  -> IN
China                  -> CN
Hong Kong              -> HK
Lithuania              -> LT
Bulgaria               -> BG
Turkiye                -> TR
United Arab Emirates   -> AE
```

## 3. Unfiltered renamed output

Directory:

```text
subscriptions_unfiltered/
```

Preserves all upstream configs and only rewrites their display names.

No protocol filtering, TLS filtering, geo verification, or deduplication is
applied to this output.

## Geo verification cache

Active checks are cached in:

```text
reports/geo_cache.json
```

Default cache policy:

```text
verified          12 hours
wrong country     24 hours
failed             3 hours
unsupported       24 hours
```

This keeps the 15-minute workflow practical. New configs are tested
immediately, while recently tested configs reuse their cached result until the
relevant TTL expires.

Settings are in:

```text
config/sources.json
```

under:

```text
settings.geo_verification
```

## Geo reports

The latest summary is written to:

```text
reports/geo_latest.json
```

It includes per-country counts for:

- verified
- wrong country
- failed
- unsupported
- detected exit countries

It also includes a sample of country mismatches with exit IP and latency.

## Fail-safe behavior

If a country has no successful geo result at all during a run because the
GitHub runner cannot complete the probes, an existing verified file is kept
instead of being wiped.

If the verifier receives definitive results but none match the expected
country, the verified file can legitimately become empty.

## GitHub Actions

The workflow runs every 15 minutes and can also be started manually.

It:

1. checks out the repository,
2. installs Python,
3. downloads the latest stable official Xray Core release,
4. runs unit tests,
5. refreshes filtered/unfiltered subscriptions,
6. performs real Xray geo verification when cache entries are stale,
7. writes the reports and cache,
8. commits changed outputs.

The first run may take longer because every filtered config is new. Later runs
are substantially faster because of the cache.

## Important limitation of GitHub-hosted verification

A config can work from your own 3x-ui VPS but fail from a GitHub-hosted runner
because the network path is different.

For that reason:

- `subscriptions/` remains the statically valid list.
- `subscriptions_verified/` means "verified from the GitHub runner".
- A future self-hosted runner on the 3x-ui VPS can use the same scripts for
  verification from the exact production network.

## Raw URL examples

Filtered US:

```text
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/subscriptions/United_States.txt
```

Geo-verified US:

```text
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/subscriptions_verified/United_States.txt
```

Unfiltered renamed US:

```text
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPOSITORY/main/subscriptions_unfiltered/United_States.txt
```

## Local unit tests

```bash
python -m unittest discover -s tests -v
```

Geo verification additionally requires:

```text
xray
curl
```

in `PATH`.
