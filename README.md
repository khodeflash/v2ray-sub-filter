# V2Ray Subscription Filter + Geo Verifier

This repository creates three country-specific subscription outputs.

## Filtered output

Directory:

```text
subscriptions/
```

Contains only:

- VLESS + TLS
- VLESS + REALITY
- VMess + TLS

The static filter rejects known Xray-invalid cases before publication.

Version 7 also rejects JSON-shaped `fm` or XHTTP `extra` parameters when they
are truncated or malformed. This prevents a broken unescaped `#` inside
upstream query data from silently truncating a VLESS URI.

## Geo-verified output

Directory:

```text
subscriptions_verified/
```

For each unique filtered config, the GitHub Action:

1. Converts the share link into a local Xray client config.
2. Runs `xray run -test` before starting the client.
3. Checks basic TCP reachability to the proxy endpoint.
4. Starts Xray with an isolated local SOCKS port.
5. Sends an HTTP Cloudflare Trace request through that exact outbound.
6. Reads the exit `ip` and `loc`.
7. Publishes the config into the verified file for the detected exit country.

The source country is not used as the final verified destination.

For example:

```text
Source: United_Kingdom.txt
Detected exit country: DE
Result: subscriptions_verified/Germany.txt
Remark: DE-VLESS-001
```

There is no separate reclassification directory. Reclassified configs are
written directly into `subscriptions_verified/` together with configs that
already matched their original source country.

The primary geo probes intentionally use plain HTTP for `/cdn-cgi/trace`.
The proxy transport itself can still be TLS or REALITY, but the destination
probe does not add another TLS handshake. This reduces false negatives caused
by destination-side TLS behavior while still proving that the proxy can carry
a real HTTP request.

If all Cloudflare Trace endpoints fail, a separate HTTP tunnel test is used to
distinguish a general proxy-tunnel failure from a geo-endpoint-only failure.

## Supported active-test details

The verifier preserves the important settings needed by the filtered formats,
including:

- VLESS TLS and REALITY.
- VMess TLS.
- RAW/TCP, WebSocket, gRPC, XHTTP and HTTPUpgrade.
- WebSocket paths including `?ed=...` early-data syntax.
- TLS SNI, ALPN, fingerprint and allow-insecure options.
- TLS ECH through `echConfigList`.
- REALITY public key, server name, fingerprint, short ID and spider path.
- XHTTP mode and JSON `extra`.

Non-core metadata such as fragmentation hints is not treated as a requirement
for the active geo test.

## Failure classification

`reports/geo_latest.json` includes counts by status, stage and reason.

Typical stages:

```text
build
tcp
xray_config
xray_start
geo
proxy_tunnel
```

Typical reasons:

```text
tcp_unreachable
xray_config_rejected
xray_start_failed
country_match
country_mismatch
geo_probe_failed_tunnel_ok
proxy_tunnel_failed
```

This makes it possible to distinguish a bad generated Xray config from an
unreachable server or a probe-specific failure.

## Cache

Cache file:

```text
reports/geo_cache.json
```

Version 7 uses cache schema version 2, so the first v7 run intentionally does
not reuse the v6 results. This forces every current filtered config to be
retested with the improved HTTP probe and parser.

Default TTLs:

```text
verified          12 hours
wrong country     24 hours
failed             3 hours
config invalid    24 hours
unsupported       24 hours
```

## Country mapping

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

## Unfiltered renamed output

Directory:

```text
subscriptions_unfiltered/
```

This output preserves all non-empty upstream configs and only rewrites their
remarks. It does not apply protocol, TLS, Xray or geo filtering.

## Fail-safe

When a country has no definitive geo result during a run, the previous verified
output is preserved only for configs that still exist in the current filtered
file.

This prevents a transient GitHub runner problem from wiping a known verified
list while also preventing removed upstream configs from surviving forever.

## GitHub Actions

The workflow runs every 15 minutes and can also be started manually.

It downloads the latest stable official Xray Core release, runs unit tests,
updates subscriptions, performs active geo checks and commits changed outputs.

## Important limitation

`subscriptions_verified/` means verified from the GitHub-hosted runner network.

A config may still work from the 3x-ui VPS while failing from GitHub because the
source network is different. A self-hosted GitHub runner on the 3x-ui VPS can
use the same verifier later if production-network verification is required.


## Verified country reclassification

`subscriptions_verified/` represents the detected exit country, not the
upstream source filename.

If a config is found in the wrong upstream country file but the active Xray
probe resolves its exit country successfully, the config is retained and moved
to the correct verified country file.

Configured countries keep their existing friendly filenames, for example:

```text
GB -> United_Kingdom.txt
US -> United_States.txt
TR -> Turkiye.txt
AE -> United_Arab_Emirates.txt
```

Other detected countries are created automatically in the same directory, for
example:

```text
DE -> Germany.txt
NL -> Netherlands.txt
FR -> France.txt
```

Verified remarks are also regenerated from the detected country:

```text
DE-VLESS-001
DE-VMESS-001
```

Duplicate configs are collapsed by fingerprint before writing verified country
files.

If a previously geo-resolved config temporarily fails a later probe but still
exists in the current filtered input, its last known verified country is
preserved. If a later successful probe detects a different country, it is
moved to the newly detected country file.
