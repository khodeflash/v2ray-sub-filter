#!/usr/bin/env python3
import base64
import binascii
import html
import json
import re
import sys
import urllib.request
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "sources.json"
FILTERED_DIR = ROOT / "subscriptions"
UNFILTERED_DIR = ROOT / "subscriptions_unfiltered"
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


def normalized_query(link):
    try:
        parsed = urlsplit(link)
        raw = parse_qs(parsed.query, keep_blank_values=True)
        return {
            str(key).strip().lower(): values
            for key, values in raw.items()
        }
    except Exception:
        return {}


def query_value(query, *names, default=""):
    for name in names:
        values = query.get(name.lower())
        if values:
            return str(values[0]).strip()
    return default


def query_security(link):
    query = normalized_query(link)
    return query_value(query, "security").lower()


def is_valid_uuid(value):
    try:
        uuid.UUID(str(value).strip())
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def validate_reality_query(query):
    public_key = query_value(query, "pbk", "publicKey", "password")
    server_name = query_value(query, "sni", "serverName")
    fingerprint = query_value(query, "fp", "fingerprint")
    short_id = query_value(query, "sid", "shortId")

    if not public_key:
        return False, "invalid_reality_missing_public_key"

    if not server_name:
        return False, "invalid_reality_missing_server_name"

    if not fingerprint:
        return False, "invalid_reality_missing_fingerprint"

    if short_id:
        if len(short_id) > 16 or len(short_id) % 2 != 0:
            return False, "invalid_reality_short_id"
        if not re.fullmatch(r"[0-9a-fA-F]+", short_id):
            return False, "invalid_reality_short_id"

    return True, "accepted"


def validate_optional_json_parameter(query, name):
    value = query_value(query, name)
    if not value:
        return True

    stripped = value.strip()
    if not stripped.startswith(("{", "[")):
        return True

    try:
        json.loads(stripped)
        return True
    except json.JSONDecodeError:
        return False


def validate_stream_query(query):
    transport = query_value(query, "type", default="tcp").lower() or "tcp"
    header_type = query_value(
        query,
        "headerType",
        "header",
        default="none",
    ).lower() or "none"
    host = query_value(query, "host")

    if transport in {"tcp", "raw"} and header_type == "http" and not host:
        return False, "invalid_http_header_host"

    flow = query_value(query, "flow").lower()
    if flow == "xtls-rprx-vision" and transport not in {"tcp", "raw"}:
        return False, "invalid_vision_transport"

    if not validate_optional_json_parameter(query, "fm"):
        return False, "invalid_fragment_metadata"

    if transport in {"xhttp", "splithttp"}:
        extra = query_value(query, "extra")
        if extra and not validate_optional_json_parameter(query, "extra"):
            return False, "invalid_xhttp_extra"

    return True, "accepted"


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

    parsed = urlsplit(link)
    identifier = parsed.username or ""
    if not is_valid_uuid(identifier):
        return False, "invalid_vless_uuid", None

    query = normalized_query(link)
    security = query_value(query, "security").lower()

    if security not in {"tls", "reality"}:
        return False, "not_allowed_security", None

    stream_ok, stream_reason = validate_stream_query(query)
    if not stream_ok:
        return False, stream_reason, None

    if security == "reality":
        reality_ok, reality_reason = validate_reality_query(query)
        if not reality_ok:
            return False, reality_reason, None

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

    if not is_valid_uuid(identifier):
        return False, "invalid_vmess_uuid", None, None

    try:
        port = int(port_value)
    except ValueError:
        return False, "malformed", None, None

    if not 1 <= port <= 65535:
        return False, "malformed", None, None

    if str(config.get("tls", "")).strip().lower() != "tls":
        return False, "not_tls", None, None

    transport = str(config.get("net", "tcp")).strip().lower() or "tcp"
    header_type = str(config.get("type", "none")).strip().lower() or "none"
    host = str(config.get("host", "")).strip()

    if transport in {"tcp", "raw"} and header_type == "http" and not host:
        return False, "invalid_http_header_host", None, None

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

    known = (
        ("vless://", "vless"),
        ("vmess://", "vmess"),
        ("ss://", "ss"),
        ("trojan://", "trojan"),
        ("hysteria2://", "hysteria2"),
        ("hy2://", "hy2"),
        ("hysteria://", "hysteria"),
        ("tuic://", "tuic"),
        ("socks://", "socks"),
        ("socks5://", "socks5"),
        ("http://", "http"),
        ("https://", "https"),
        ("wireguard://", "wireguard"),
    )

    for prefix, name in known:
        if lowered.startswith(prefix):
            return name

    if "://" in link:
        return link.split("://", 1)[0].strip().lower() or "unknown"

    return "unknown"


def protocol_label(protocol):
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", protocol.upper()).strip("-")
    return cleaned or "UNKNOWN"


def evaluate_link(link):
    protocol = detect_protocol(link)

    if protocol == "vless":
        keep, reason, canonical = evaluate_vless(link)
        return keep, reason, protocol, canonical, None

    if protocol == "vmess":
        keep, reason, canonical, config = evaluate_vmess(link)
        return keep, reason, protocol, canonical, config

    if protocol == "ss":
        return False, "shadowsocks", protocol, None, None

    if protocol == "trojan":
        return False, "trojan", protocol, None, None

    return False, "unsupported_protocol", protocol, None, None


def rename_uri_fragment(link, display_name):
    if "#" in link:
        base = link.split("#", 1)[0]
    else:
        base = link
    return f"{base}#{display_name}"


def rename_vless(link, display_name):
    return rename_uri_fragment(link, display_name)


def rename_vmess(config, display_name):
    renamed = dict(config)
    renamed["ps"] = display_name
    return "vmess://" + encode_vmess_payload(renamed)


def rename_any_config(link, display_name):
    protocol = detect_protocol(link)

    if protocol == "vmess":
        try:
            config = decode_vmess_payload(link)
            return rename_vmess(config, display_name), True
        except Exception:
            # Keep the config instead of dropping it from the unfiltered output.
            return link, False

    return rename_uri_fragment(link, display_name), True


def build_unfiltered_output(lines, country_code):
    counters = defaultdict(int)
    output = []
    rename_failures = 0
    by_protocol = Counter()

    for link in lines:
        protocol = detect_protocol(link)
        counters[protocol] += 1
        display_name = (
            f"{country_code}-{protocol_label(protocol)}-{counters[protocol]:03d}"
        )

        renamed, success = rename_any_config(link, display_name)
        if not success:
            rename_failures += 1

        output.append(renamed)
        by_protocol[protocol] += 1

    return output, dict(sorted(by_protocol.items())), rename_failures


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

    filtered_path = FILTERED_DIR / f"{slug}.txt"
    unfiltered_path = UNFILTERED_DIR / f"{slug}.txt"

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
        "unfiltered_published": 0,
        "unfiltered_by_protocol": {},
        "unfiltered_rename_failures": 0,
        "rejected": {},
        "used_previous_filtered_output": False,
        "used_previous_unfiltered_output": False,
    }

    try:
        text = fetch_text(
            source["url"],
            settings.get("request_timeout_seconds", 30),
            settings.get("user_agent", "v2ray-sub-filter/7.0"),
        )
    except Exception as exc:
        result["status"] = "fetch_error"
        result["error"] = str(exc)

        if filtered_path.exists() and filtered_path.stat().st_size > 0:
            result["used_previous_filtered_output"] = True
            result["published"] = len(
                split_nonempty_lines(filtered_path.read_text(encoding="utf-8"))
            )

        if unfiltered_path.exists() and unfiltered_path.stat().st_size > 0:
            result["used_previous_unfiltered_output"] = True
            result["unfiltered_published"] = len(
                split_nonempty_lines(unfiltered_path.read_text(encoding="utf-8"))
            )

        return result

    lines = split_nonempty_lines(text)
    result["fetched"] = len(lines)

    # Unfiltered output: preserve every non-empty upstream line and only rename.
    unfiltered_links, unfiltered_by_protocol, rename_failures = (
        build_unfiltered_output(lines, code)
    )

    if unfiltered_links:
        unfiltered_path.write_text(
            "\n".join(unfiltered_links) + "\n",
            encoding="utf-8",
        )
        result["unfiltered_published"] = len(unfiltered_links)
        result["unfiltered_by_protocol"] = unfiltered_by_protocol
        result["unfiltered_rename_failures"] = rename_failures
    elif unfiltered_path.exists() and unfiltered_path.stat().st_size > 0:
        result["used_previous_unfiltered_output"] = True
        result["unfiltered_published"] = len(
            split_nonempty_lines(unfiltered_path.read_text(encoding="utf-8"))
        )

    # Filtered output: only VLESS TLS and VMess TLS, with deduplication.
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
    filtered_links = []

    for record in accepted_records:
        protocol = record["protocol"]
        counters[protocol] += 1
        display_name = (
            f"{code}-{protocol_label(protocol)}-{counters[protocol]:03d}"
        )

        if protocol == "vless":
            renamed = rename_vless(record["link"], display_name)
        elif protocol == "vmess":
            renamed = rename_vmess(record["vmess_config"], display_name)
        else:
            continue

        filtered_links.append(renamed)
        published_by_protocol[protocol] += 1

    result["rejected"] = dict(sorted(rejected.items()))
    result["published_by_protocol"] = dict(sorted(published_by_protocol.items()))

    if filtered_links:
        filtered_path.write_text(
            "\n".join(filtered_links) + "\n",
            encoding="utf-8",
        )
        result["published"] = len(filtered_links)
    else:
        result["status"] = "empty_after_filter"

        if filtered_path.exists() and filtered_path.stat().st_size > 0:
            result["used_previous_filtered_output"] = True
            result["published"] = len(
                split_nonempty_lines(filtered_path.read_text(encoding="utf-8"))
            )

    return result


def print_source_summary(result):
    print(
        f"{result['slug']}: "
        f"status={result['status']} "
        f"fetched={result['fetched']} "
        f"filtered={result['published']} "
        f"unfiltered={result['unfiltered_published']}"
    )

    if result.get("published_by_protocol"):
        print(
            "  filtered_by_protocol="
            + json.dumps(result["published_by_protocol"], sort_keys=True)
        )

    if result.get("unfiltered_by_protocol"):
        print(
            "  unfiltered_by_protocol="
            + json.dumps(result["unfiltered_by_protocol"], sort_keys=True)
        )

    if result.get("unfiltered_rename_failures"):
        print(
            f"  unfiltered_rename_failures="
            f"{result['unfiltered_rename_failures']}"
        )

    if result.get("rejected"):
        print(
            "  rejected="
            + json.dumps(result["rejected"], sort_keys=True)
        )

    if result.get("error"):
        print(f"  error={result['error']}")


def remove_legacy_combined_files():
    for path in (
        FILTERED_DIR / "All.txt",
        UNFILTERED_DIR / "All.txt",
    ):
        if path.exists():
            path.unlink()
            print(f"Removed legacy {path.relative_to(ROOT)}")


def main():
    config = load_config()
    settings = config.get("settings", {})
    sources = config.get("sources", [])

    if not sources:
        print("No sources configured.", file=sys.stderr)
        return 2

    FILTERED_DIR.mkdir(parents=True, exist_ok=True)
    UNFILTERED_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    remove_legacy_combined_files()

    results = []

    for source in sources:
        result = process_source(source, settings)
        results.append(result)
        print_source_summary(result)

    filtered_protocol_totals = Counter()
    unfiltered_protocol_totals = Counter()
    rejection_totals = Counter()

    for item in results:
        filtered_protocol_totals.update(item.get("published_by_protocol", {}))
        unfiltered_protocol_totals.update(item.get("unfiltered_by_protocol", {}))
        rejection_totals.update(item.get("rejected", {}))

    totals = {
        "sources_configured": len(sources),
        "sources_ok": sum(1 for item in results if item["status"] == "ok"),
        "fetched": sum(item["fetched"] for item in results),
        "filtered_published": sum(item["published"] for item in results),
        "filtered_by_protocol": dict(sorted(filtered_protocol_totals.items())),
        "unfiltered_published": sum(
            item["unfiltered_published"] for item in results
        ),
        "unfiltered_by_protocol": dict(
            sorted(unfiltered_protocol_totals.items())
        ),
        "unfiltered_rename_failures": sum(
            item["unfiltered_rename_failures"] for item in results
        ),
        "rejected_from_filtered": dict(sorted(rejection_totals.items())),
    }

    report = {
        "policy": {
            "filtered": {
                "allowed_protocols": ["vless", "vmess"],
                "vless_security": ["tls", "reality"],
                "vmess_security": ["tls"],
                "trojan": "blocked",
                "shadowsocks": "blocked",
                "reality": "allowed_for_vless",
                "xray_preflight_validation": {
                    "uuid": "required_for_vless_and_vmess",
                    "tcp_raw_http_host": "required_when_headerType_is_http",
                    "reality_public_key": "required",
                    "reality_server_name": "required",
                    "reality_fingerprint": "required",
                    "reality_short_id": "validated_when_present",
                    "vision_transport": "tcp_or_raw_only",
                    "fragment_metadata_json": "validated_when_json_shaped",
                    "xhttp_extra_json": "validated_when_present"
                },
                "deduplication": "enabled",
            },
            "unfiltered": {
                "filtering": "disabled",
                "deduplication": "disabled",
                "preserve_order": True,
                "remark_only_rewrite": True,
            },
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

    if not any(
        item["published"] > 0 or item["unfiltered_published"] > 0
        for item in results
    ):
        print("No usable output is available.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
