#!/usr/bin/env python3
import base64
import binascii
import html
import json
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "sources.json"
OUTPUT_DIR = ROOT / "subscriptions"
REPORT_DIR = ROOT / "reports"
REPORT_PATH = REPORT_DIR / "latest.json"


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_link(value):
    return html.unescape(value.strip())


def split_nonempty_lines(text):
    return [normalize_link(line) for line in text.splitlines() if line.strip()]


def safe_port(parsed):
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None or not 1 <= port <= 65535:
        return None
    return port


def query_security(link):
    try:
        parsed = urlsplit(link)
        query = parse_qs(parsed.query, keep_blank_values=True)
        return query.get("security", [""])[0].strip().lower()
    except Exception:
        return ""


def validate_common_uri(link):
    try:
        parsed = urlsplit(link)
        if not parsed.hostname:
            return False
        if safe_port(parsed) is None:
            return False
        return True
    except Exception:
        return False


def decode_vmess_payload(link):
    payload = link[len("vmess://"):].strip()
    if not payload:
        raise ValueError("empty vmess payload")

    payload += "=" * (-len(payload) % 4)
    raw = payload.encode("ascii")

    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(raw)
            return json.loads(decoded.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
            pass

    raise ValueError("invalid vmess payload")


def encode_vmess_payload(config):
    raw = json.dumps(
        config,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def evaluate_vless(link):
    if not validate_common_uri(link):
        return False, "malformed", None

    if query_security(link) != "tls":
        return False, "not_tls", None

    parsed = urlsplit(link)

    # Remove the upstream display name before duplicate comparison.
    canonical = urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.query,
        "",
    ))

    return True, "accepted", canonical


def evaluate_vmess(link):
    try:
        config = decode_vmess_payload(link)
    except Exception:
        return False, "malformed", None, None

    address = str(config.get("add", "")).strip()
    identifier = str(config.get("id", "")).strip()
    port_value = str(config.get("port", "")).strip()

    if not address or not identifier or not port_value:
        return False, "malformed", None, None

    try:
        port = int(port_value)
    except ValueError:
        return False, "malformed", None, None

    if not 1 <= port <= 65535:
        return False, "malformed", None, None

    if str(config.get("tls", "")).strip().lower() != "tls":
        return False, "not_tls", None, None

    # Ignore the original display name for duplicate comparison.
    canonical_config = dict(config)
    canonical_config["ps"] = ""
    canonical = json.dumps(
        canonical_config,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return True, "accepted", canonical, config


def detect_protocol(link):
    lowered = link.lower()
    if lowered.startswith("vless://"):
        return "vless"
    if lowered.startswith("vmess://"):
        return "vmess"
    if lowered.startswith("ss://"):
        return "shadowsocks"
    if lowered.startswith("trojan://"):
        return "trojan"
    return "unsupported"


def evaluate_link(link):
    protocol = detect_protocol(link)

    if protocol == "vless":
        keep, reason, canonical = evaluate_vless(link)
        return keep, reason, protocol, canonical, None

    if protocol == "vmess":
        keep, reason, canonical, config = evaluate_vmess(link)
        return keep, reason, protocol, canonical, config

    if protocol == "shadowsocks":
        return False, "shadowsocks", protocol, None, None

    if protocol == "trojan":
        return False, "trojan", protocol, None, None

    return False, "unsupported_protocol", protocol, None, None


def rename_vless(link, display_name):
    parsed = urlsplit(link)
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.query,
        display_name,
    ))


def rename_vmess(config, display_name):
    renamed = dict(config)
    renamed["ps"] = display_name
    return "vmess://" + encode_vmess_payload(renamed)


def fetch_text(url, timeout, user_agent):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/plain,*/*;q=0.1",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if status != 200:
            raise RuntimeError(f"unexpected HTTP status: {status}")

        content_type = response.headers.get("Content-Type", "").lower()
        raw = response.read()

    if not raw:
        raise RuntimeError("empty response")

    text = raw.decode("utf-8-sig", errors="strict")

    stripped = text.lstrip().lower()
    if "<html" in stripped[:500] or "<!doctype html" in stripped[:500]:
        raise RuntimeError(
            f"unexpected HTML response ({content_type or 'unknown content type'})"
        )

    return text


def process_source(source, settings):
    slug = source["slug"]
    code = source["code"].upper()
    output_path = OUTPUT_DIR / f"{slug}.txt"

    result = {
        "name": source["name"],
        "slug": slug,
        "code": code,
        "source_url": source["url"],
        "status": "ok",
        "fetched": 0,
        "accepted_before_dedup": 0,
        "duplicates_removed": 0,
        "published": 0,
        "published_by_protocol": {},
        "rejected": {},
        "used_previous_output": False,
    }

    try:
        text = fetch_text(
            source["url"],
            settings.get("request_timeout_seconds", 30),
            settings.get("user_agent", "v2ray-sub-filter/2.0"),
        )
    except Exception as exc:
        result["status"] = "fetch_error"
        result["error"] = str(exc)

        if output_path.exists() and output_path.stat().st_size > 0:
            result["used_previous_output"] = True
            previous = split_nonempty_lines(output_path.read_text(encoding="utf-8"))
            result["published"] = len(previous)
            return previous, result

        return [], result

    lines = split_nonempty_lines(text)
    result["fetched"] = len(lines)

    rejected = Counter()
    seen = set()
    accepted_records = []

    for link in lines:
        keep, reason, protocol, canonical, vmess_config = evaluate_link(link)

        if not keep:
            rejected[reason] += 1
            continue

        result["accepted_before_dedup"] += 1

        dedup_key = f"{protocol}:{canonical}"
        if dedup_key in seen:
            result["duplicates_removed"] += 1
            continue

        seen.add(dedup_key)
        accepted_records.append({
            "protocol": protocol,
            "link": link,
            "vmess_config": vmess_config,
        })

    counters = defaultdict(int)
    published_by_protocol = Counter()
    renamed_links = []

    for record in accepted_records:
        protocol = record["protocol"]
        counters[protocol] += 1
        display_name = f"{code}-{protocol.upper()}-{counters[protocol]:03d}"

        if protocol == "vless":
            renamed = rename_vless(record["link"], display_name)
        elif protocol == "vmess":
            renamed = rename_vmess(record["vmess_config"], display_name)
        else:
            continue

        renamed_links.append(renamed)
        published_by_protocol[protocol] += 1

    result["rejected"] = dict(sorted(rejected.items()))
    result["published_by_protocol"] = dict(sorted(published_by_protocol.items()))

    if not renamed_links:
        result["status"] = "empty_after_filter"

        if output_path.exists() and output_path.stat().st_size > 0:
            result["used_previous_output"] = True
            previous = split_nonempty_lines(output_path.read_text(encoding="utf-8"))
            result["published"] = len(previous)
            return previous, result

        return [], result

    output_path.write_text("\n".join(renamed_links) + "\n", encoding="utf-8")
    result["published"] = len(renamed_links)

    return renamed_links, result


def print_source_summary(result):
    print(
        f"{result['slug']}: "
        f"status={result['status']} "
        f"fetched={result['fetched']} "
        f"published={result['published']} "
        f"previous={result['used_previous_output']}"
    )

    if result.get("published_by_protocol"):
        print(
            "  published_by_protocol="
            + json.dumps(result["published_by_protocol"], sort_keys=True)
        )

    if result.get("rejected"):
        print(
            "  rejected="
            + json.dumps(result["rejected"], sort_keys=True)
        )

    if result.get("error"):
        print(f"  error={result['error']}")


def remove_legacy_combined_file():
    combined_path = OUTPUT_DIR / "All.txt"
    if combined_path.exists():
        combined_path.unlink()
        print("Removed legacy subscriptions/All.txt")


def main():
    config = load_config()
    settings = config.get("settings", {})
    sources = config.get("sources", [])

    if not sources:
        print("No sources configured.", file=sys.stderr)
        return 2

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    remove_legacy_combined_file()

    results = []

    for source in sources:
        _, result = process_source(source, settings)
        results.append(result)
        print_source_summary(result)

    totals = {
        "sources_configured": len(sources),
        "sources_ok": sum(1 for item in results if item["status"] == "ok"),
        "sources_using_previous_output": sum(
            1 for item in results if item["used_previous_output"]
        ),
        "fetched": sum(item["fetched"] for item in results),
        "published_country_entries": sum(item["published"] for item in results),
    }

    published_protocol_totals = Counter()
    rejection_totals = Counter()

    for item in results:
        published_protocol_totals.update(item.get("published_by_protocol", {}))
        rejection_totals.update(item.get("rejected", {}))

    totals["published_by_protocol"] = dict(sorted(published_protocol_totals.items()))
    totals["rejected"] = dict(sorted(rejection_totals.items()))

    report = {
        "policy": {
            "allowed_protocols": ["vless", "vmess"],
            "vless_security": ["tls"],
            "vmess_security": ["tls"],
            "trojan": "blocked",
            "shadowsocks": "blocked",
            "reality": "blocked",
            "rename_format": "COUNTRYCODE-PROTOCOL-INDEX",
            "combined_subscription": "disabled",
        },
        "totals": totals,
        "sources": results,
    }

    REPORT_PATH.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if not any(item["published"] > 0 for item in results):
        print("No usable output is available.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
