#!/usr/bin/env python3
import base64
import binascii
import html
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


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


def unique_preserving_order(items):
    return list(dict.fromkeys(items))


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

    errors = []
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(raw)
            return json.loads(decoded.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError) as exc:
            errors.append(exc)

    raise ValueError("invalid vmess payload")


def validate_vmess(link):
    try:
        config = decode_vmess_payload(link)
    except Exception:
        return False, "malformed"

    address = str(config.get("add", "")).strip()
    identifier = str(config.get("id", "")).strip()
    port_value = str(config.get("port", "")).strip()

    if not address or not identifier or not port_value:
        return False, "malformed"

    try:
        port = int(port_value)
    except ValueError:
        return False, "malformed"

    if not 1 <= port <= 65535:
        return False, "malformed"

    if str(config.get("tls", "")).strip().lower() != "tls":
        return False, "no_allowed_security"

    return True, "accepted"


def validate_vless_or_trojan(link, allow_reality):
    if not validate_common_uri(link):
        return False, "malformed"

    security = query_security(link)
    allowed_security = {"tls"}
    if allow_reality:
        allowed_security.add("reality")

    if security not in allowed_security:
        return False, "no_allowed_security"

    return True, "accepted"


def evaluate_link(link, settings):
    lowered = link.lower()

    if lowered.startswith("ss://"):
        return False, "shadowsocks"

    allowed_protocols = set(settings.get("allowed_protocols", []))

    if lowered.startswith("vless://"):
        if "vless" not in allowed_protocols:
            return False, "protocol_disabled"
        return validate_vless_or_trojan(link, settings.get("allow_reality", True))

    if lowered.startswith("trojan://"):
        if "trojan" not in allowed_protocols:
            return False, "protocol_disabled"
        return validate_vless_or_trojan(link, settings.get("allow_reality", True))

    if lowered.startswith("vmess://"):
        if "vmess" not in allowed_protocols:
            return False, "protocol_disabled"
        return validate_vmess(link)

    return False, "unsupported_protocol"


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
        raise RuntimeError(f"unexpected HTML response ({content_type or 'unknown content type'})")

    return text


def process_source(source, settings):
    slug = source["slug"]
    output_path = OUTPUT_DIR / f"{slug}.txt"

    result = {
        "name": source["name"],
        "slug": slug,
        "source_url": source["url"],
        "status": "ok",
        "fetched": 0,
        "accepted_before_dedup": 0,
        "duplicates_removed": 0,
        "published": 0,
        "rejected": {},
        "used_previous_output": False,
    }

    try:
        text = fetch_text(
            source["url"],
            settings.get("request_timeout_seconds", 30),
            settings.get("user_agent", "v2ray-sub-filter/1.0"),
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

    accepted = []
    rejected = Counter()

    for link in lines:
        keep, reason = evaluate_link(link, settings)
        if keep:
            accepted.append(link)
        else:
            rejected[reason] += 1

    result["accepted_before_dedup"] = len(accepted)
    deduped = unique_preserving_order(accepted)
    result["duplicates_removed"] = len(accepted) - len(deduped)
    result["rejected"] = dict(sorted(rejected.items()))

    if not deduped:
        result["status"] = "empty_after_filter"
        if output_path.exists() and output_path.stat().st_size > 0:
            result["used_previous_output"] = True
            previous = split_nonempty_lines(output_path.read_text(encoding="utf-8"))
            result["published"] = len(previous)
            return previous, result
        return [], result

    output_path.write_text("\n".join(deduped) + "\n", encoding="utf-8")
    result["published"] = len(deduped)
    return deduped, result


def build_combined(all_outputs):
    combined = []
    for links in all_outputs:
        combined.extend(links)
    return unique_preserving_order(combined)


def print_source_summary(result):
    print(
        f"{result['slug']}: "
        f"status={result['status']} "
        f"fetched={result['fetched']} "
        f"published={result['published']} "
        f"previous={result['used_previous_output']}"
    )
    if result.get("rejected"):
        print(f"  rejected={json.dumps(result['rejected'], sort_keys=True)}")
    if result.get("error"):
        print(f"  error={result['error']}")


def main():
    config = load_config()
    settings = config.get("settings", {})
    sources = config.get("sources", [])

    if not sources:
        print("No sources configured.", file=sys.stderr)
        return 2

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    outputs = []
    results = []

    for source in sources:
        links, result = process_source(source, settings)
        outputs.append(links)
        results.append(result)
        print_source_summary(result)

    combined_count = 0
    if settings.get("publish_combined", True):
        combined = build_combined(outputs)
        combined_count = len(combined)
        combined_path = OUTPUT_DIR / "All.txt"

        if combined:
            combined_path.write_text("\n".join(combined) + "\n", encoding="utf-8")
        elif combined_path.exists() and combined_path.stat().st_size > 0:
            combined_count = len(split_nonempty_lines(combined_path.read_text(encoding="utf-8")))
            print("Combined output would be empty; preserving previous All.txt.")

    totals = {
        "sources_configured": len(sources),
        "sources_ok": sum(1 for item in results if item["status"] == "ok"),
        "sources_using_previous_output": sum(1 for item in results if item["used_previous_output"]),
        "fetched": sum(item["fetched"] for item in results),
        "published_country_entries": sum(item["published"] for item in results),
        "combined_unique_entries": combined_count,
    }

    rejection_totals = Counter()
    for item in results:
        rejection_totals.update(item.get("rejected", {}))
    totals["rejected"] = dict(sorted(rejection_totals.items()))

    report = {
        "policy": {
            "allow_reality": settings.get("allow_reality", True),
            "allowed_protocols": settings.get("allowed_protocols", []),
            "shadowsocks": "blocked",
            "vless_security": ["tls", "reality"] if settings.get("allow_reality", True) else ["tls"],
            "trojan_security": ["tls", "reality"] if settings.get("allow_reality", True) else ["tls"],
            "vmess_security": ["tls"],
        },
        "totals": totals,
        "sources": results,
    }

    REPORT_PATH.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"Combined unique entries: {combined_count}")

    if not any(item["published"] > 0 for item in results):
        print("No usable output is available.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
