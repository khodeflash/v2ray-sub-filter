#!/usr/bin/env python3
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "sources.json"
FILTERED_DIR = ROOT / "subscriptions"
VERIFIED_DIR = ROOT / "subscriptions_verified"
REPORT_DIR = ROOT / "reports"
CACHE_PATH = REPORT_DIR / "geo_cache.json"
REPORT_PATH = REPORT_DIR / "geo_latest.json"

PORT_LOCK = threading.Lock()


def utc_now():
    return datetime.now(timezone.utc)


def iso_now():
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_json(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def load_config():
    return load_json(CONFIG_PATH, {})


def nonempty_lines(path):
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_bool(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def first_query(query, *names, default=""):
    lowered = {str(k).lower(): v for k, v in query.items()}
    for name in names:
        values = lowered.get(name.lower())
        if values:
            return str(values[0]).strip()
    return default


def split_csv(value):
    return [item.strip() for item in str(value).split(",") if item.strip()]


def decode_vmess(link):
    payload = link[len("vmess://"):].strip()
    payload += "=" * (-len(payload) % 4)
    last_error = None
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(payload.encode("ascii"))
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            last_error = exc
    raise ValueError(f"invalid VMess payload: {last_error}")


def config_fingerprint(link):
    if link.lower().startswith("vless://"):
        canonical = link.split("#", 1)[0]
    elif link.lower().startswith("vmess://"):
        data = decode_vmess(link)
        data = dict(data)
        data["ps"] = ""
        canonical = json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    else:
        canonical = link.split("#", 1)[0]

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def display_name(link):
    if link.lower().startswith("vless://"):
        parsed = urlsplit(link)
        return unquote(parsed.fragment) or "VLESS"
    if link.lower().startswith("vmess://"):
        try:
            return str(decode_vmess(link).get("ps", "VMESS"))
        except Exception:
            return "VMESS"
    return link.split("#", 1)[-1]


def tls_settings(server_name, fingerprint="", allow_insecure=False, alpn=""):
    settings = {
        "allowInsecure": bool(allow_insecure),
    }
    if server_name:
        settings["serverName"] = server_name
    if fingerprint:
        settings["fingerprint"] = fingerprint
    alpn_values = split_csv(alpn)
    if alpn_values:
        settings["alpn"] = alpn_values
    return settings


def raw_settings(header_type, host, path):
    header_type = (header_type or "none").lower()
    if header_type != "http":
        return {"header": {"type": "none"}}

    if not host:
        raise ValueError("RAW/TCP HTTP header requires Host")

    path_values = split_csv(path) or [path or "/"]
    hosts = split_csv(host) or [host]
    return {
        "header": {
            "type": "http",
            "request": {
                "version": "1.1",
                "method": "GET",
                "path": path_values,
                "headers": {
                    "Host": hosts,
                },
            },
        }
    }


def parse_extra_json(value):
    if not value:
        return None
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return None


def build_stream_settings_from_vless(parsed, query):
    transport = first_query(query, "type", default="tcp").lower() or "tcp"
    security = first_query(query, "security").lower()
    host = first_query(query, "host")
    path = first_query(query, "path", default="/") or "/"
    header_type = first_query(query, "headerType", "header", default="none")
    sni = first_query(query, "sni", "serverName")
    fingerprint = first_query(query, "fp", "fingerprint")
    alpn = first_query(query, "alpn")

    method_map = {
        "tcp": "raw",
        "raw": "raw",
        "ws": "websocket",
        "websocket": "websocket",
        "grpc": "grpc",
        "xhttp": "xhttp",
        "splithttp": "xhttp",
        "http": "xhttp",
        "h2": "xhttp",
        "httpupgrade": "httpupgrade",
    }
    method = method_map.get(transport)
    if not method:
        raise NotImplementedError(f"unsupported VLESS transport: {transport}")

    stream = {"method": method, "security": security}

    if method == "raw":
        stream["rawSettings"] = raw_settings(header_type, host, path)
    elif method == "websocket":
        ws = {"path": path}
        if host:
            ws["host"] = host
        stream["wsSettings"] = ws
    elif method == "grpc":
        service_name = first_query(query, "serviceName") or path.lstrip("/")
        grpc = {"serviceName": service_name}
        authority = first_query(query, "authority")
        if authority:
            grpc["authority"] = authority
        mode = first_query(query, "mode").lower()
        if mode in {"multi", "gun"}:
            grpc["multiMode"] = True
        stream["grpcSettings"] = grpc
    elif method == "xhttp":
        xhttp = {
            "path": path,
            "mode": first_query(query, "mode", default="auto") or "auto",
        }
        if host:
            xhttp["host"] = host
        extra = parse_extra_json(first_query(query, "extra"))
        if extra:
            xhttp["extra"] = extra
        stream["xhttpSettings"] = xhttp
    elif method == "httpupgrade":
        hup = {"path": path}
        if host:
            hup["host"] = host
        stream["httpupgradeSettings"] = hup

    if security == "tls":
        effective_sni = sni
        if not effective_sni and host:
            effective_sni = split_csv(host)[0] if split_csv(host) else host
        if not effective_sni and parsed.hostname and not is_ip_address(parsed.hostname):
            effective_sni = parsed.hostname

        allow_insecure = (
            parse_bool(first_query(query, "allowInsecure"))
            or parse_bool(first_query(query, "insecure"))
        )
        stream["tlsSettings"] = tls_settings(
            effective_sni,
            fingerprint=fingerprint,
            allow_insecure=allow_insecure,
            alpn=alpn,
        )

    elif security == "reality":
        public_key = first_query(query, "pbk", "publicKey", "password")
        short_id = first_query(query, "sid", "shortId")
        spider_x = first_query(query, "spx", "spiderX", default="/") or "/"
        if not sni or not fingerprint or not public_key:
            raise ValueError("incomplete REALITY settings")
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fingerprint,
            "password": public_key,
            "shortId": short_id,
            "spiderX": spider_x,
        }
    else:
        raise ValueError(f"unsupported VLESS security: {security}")

    return stream


def build_vless_outbound(link):
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise ValueError("incomplete VLESS link")

    user = {
        "id": parsed.username,
        "encryption": first_query(query, "encryption", default="none") or "none",
    }
    flow = first_query(query, "flow")
    if flow:
        user["flow"] = flow

    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": build_stream_settings_from_vless(parsed, query),
    }


def build_stream_settings_from_vmess(data):
    transport = str(data.get("net", "tcp")).strip().lower() or "tcp"
    method_map = {
        "tcp": "raw",
        "raw": "raw",
        "ws": "websocket",
        "websocket": "websocket",
        "grpc": "grpc",
        "xhttp": "xhttp",
        "splithttp": "xhttp",
        "http": "xhttp",
        "h2": "xhttp",
        "httpupgrade": "httpupgrade",
    }
    method = method_map.get(transport)
    if not method:
        raise NotImplementedError(f"unsupported VMess transport: {transport}")

    security = "tls" if str(data.get("tls", "")).strip().lower() == "tls" else "none"
    stream = {"method": method, "security": security}
    host = str(data.get("host", "")).strip()
    path = str(data.get("path", "/")).strip() or "/"
    header_type = str(data.get("type", "none")).strip() or "none"

    if method == "raw":
        stream["rawSettings"] = raw_settings(header_type, host, path)
    elif method == "websocket":
        ws = {"path": path}
        if host:
            ws["host"] = host
        stream["wsSettings"] = ws
    elif method == "grpc":
        grpc = {"serviceName": path.lstrip("/")}
        authority = str(data.get("authority", "")).strip()
        if authority:
            grpc["authority"] = authority
        stream["grpcSettings"] = grpc
    elif method == "xhttp":
        xhttp = {
            "path": path,
            "mode": str(data.get("mode", "auto")).strip() or "auto",
        }
        if host:
            xhttp["host"] = host
        extra = data.get("extra")
        if isinstance(extra, dict):
            xhttp["extra"] = extra
        elif isinstance(extra, str):
            parsed_extra = parse_extra_json(extra)
            if parsed_extra:
                xhttp["extra"] = parsed_extra
        stream["xhttpSettings"] = xhttp
    elif method == "httpupgrade":
        hup = {"path": path}
        if host:
            hup["host"] = host
        stream["httpupgradeSettings"] = hup

    if security == "tls":
        sni = str(data.get("sni", "")).strip()
        if not sni and host:
            sni = split_csv(host)[0] if split_csv(host) else host
        address = str(data.get("add", "")).strip()
        if not sni and address and not is_ip_address(address):
            sni = address

        stream["tlsSettings"] = tls_settings(
            sni,
            fingerprint=str(data.get("fp", "")).strip(),
            allow_insecure=parse_bool(data.get("allowInsecure", False)),
            alpn=str(data.get("alpn", "")).strip(),
        )

    return stream


def build_vmess_outbound(link):
    data = decode_vmess(link)
    address = str(data.get("add", "")).strip()
    port = int(str(data.get("port", "0")).strip())
    identifier = str(data.get("id", "")).strip()
    if not address or not port or not identifier:
        raise ValueError("incomplete VMess link")

    user = {
        "id": identifier,
        "alterId": int(str(data.get("aid", "0")).strip() or "0"),
        "security": str(data.get("scy", "auto")).strip() or "auto",
    }

    return {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": build_stream_settings_from_vmess(data),
    }


def build_outbound(link):
    lower = link.lower()
    if lower.startswith("vless://"):
        return build_vless_outbound(link)
    if lower.startswith("vmess://"):
        return build_vmess_outbound(link)
    raise NotImplementedError("only filtered VLESS and VMess are actively verified")


def endpoint_from_outbound(outbound):
    node = outbound["settings"]["vnext"][0]
    return str(node["address"]), int(node["port"])


def allocate_port():
    with PORT_LOCK:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port


def build_client_config(outbound, socks_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "tag": "socks-in",
            }
        ],
        "outbounds": [outbound],
    }


def tcp_reachable(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(port, process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return True
        except OSError:
            time.sleep(0.08)
    return False


def parse_trace(text):
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values.get("ip", ""), values.get("loc", "").upper()


def cache_ttl_hours(status, settings):
    if status == "verified":
        return float(settings.get("verified_ttl_hours", 12))
    if status == "wrong_country":
        return float(settings.get("wrong_country_ttl_hours", 24))
    if status == "unsupported":
        return float(settings.get("unsupported_ttl_hours", 24))
    return float(settings.get("failed_ttl_hours", 3))


def cache_is_fresh(item, settings):
    checked = parse_iso(item.get("checked_at"))
    if not checked:
        return False
    ttl = cache_ttl_hours(item.get("status", "failed"), settings)
    return utc_now() < checked + timedelta(hours=ttl)


def run_one_check(task, settings, xray_path):
    link = task["link"]
    expected = task["expected_country"]
    name = task["name"]
    fingerprint = task["fingerprint"]
    checked_at = iso_now()

    try:
        outbound = build_outbound(link)
    except NotImplementedError as exc:
        return fingerprint, {
            "status": "unsupported",
            "name": name,
            "expected_country": expected,
            "detected_country": "",
            "exit_ip": "",
            "latency_ms": None,
            "reason": str(exc),
            "checked_at": checked_at,
        }
    except Exception as exc:
        return fingerprint, {
            "status": "failed",
            "name": name,
            "expected_country": expected,
            "detected_country": "",
            "exit_ip": "",
            "latency_ms": None,
            "reason": f"build_error: {exc}",
            "checked_at": checked_at,
        }

    host, port = endpoint_from_outbound(outbound)
    if not tcp_reachable(
        host,
        port,
        float(settings.get("tcp_connect_timeout_seconds", 2.5)),
    ):
        return fingerprint, {
            "status": "failed",
            "name": name,
            "expected_country": expected,
            "detected_country": "",
            "exit_ip": "",
            "latency_ms": None,
            "reason": "tcp_unreachable",
            "checked_at": checked_at,
        }

    socks_port = allocate_port()
    config = build_client_config(outbound, socks_port)

    with tempfile.TemporaryDirectory(prefix="xray-geo-") as tmpdir:
        config_path = Path(tmpdir) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")

        process = subprocess.Popen(
            [xray_path, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            if not wait_for_port(
                socks_port,
                process,
                float(settings.get("xray_start_timeout_seconds", 3.0)),
            ):
                error_text = ""
                if process.poll() is not None and process.stderr:
                    error_text = process.stderr.read()[-600:].strip()
                return fingerprint, {
                    "status": "failed",
                    "name": name,
                    "expected_country": expected,
                    "detected_country": "",
                    "exit_ip": "",
                    "latency_ms": None,
                    "reason": "xray_start_failed" + (
                        f": {error_text}" if error_text else ""
                    ),
                    "checked_at": checked_at,
                }

            started = time.monotonic()
            timeout = float(settings.get("probe_timeout_seconds", 7.0))
            result = subprocess.run(
                [
                    "curl",
                    "-fsSL",
                    "--connect-timeout",
                    str(min(timeout, 5.0)),
                    "--max-time",
                    str(timeout),
                    "--proxy",
                    f"socks5h://127.0.0.1:{socks_port}",
                    settings["probe_url"],
                ],
                capture_output=True,
                text=True,
                timeout=timeout + 2.0,
            )
            latency_ms = round((time.monotonic() - started) * 1000)

            if result.returncode != 0:
                return fingerprint, {
                    "status": "failed",
                    "name": name,
                    "expected_country": expected,
                    "detected_country": "",
                    "exit_ip": "",
                    "latency_ms": latency_ms,
                    "reason": f"probe_failed: {result.stderr.strip()[-300:]}",
                    "checked_at": checked_at,
                }

            exit_ip, country = parse_trace(result.stdout)
            if not country or len(country) != 2:
                return fingerprint, {
                    "status": "failed",
                    "name": name,
                    "expected_country": expected,
                    "detected_country": country,
                    "exit_ip": exit_ip,
                    "latency_ms": latency_ms,
                    "reason": "geo_response_missing_country",
                    "checked_at": checked_at,
                }

            status = "verified" if country == expected else "wrong_country"
            return fingerprint, {
                "status": status,
                "name": name,
                "expected_country": expected,
                "detected_country": country,
                "exit_ip": exit_ip,
                "latency_ms": latency_ms,
                "reason": "country_match" if status == "verified" else "country_mismatch",
                "checked_at": checked_at,
            }

        except subprocess.TimeoutExpired:
            return fingerprint, {
                "status": "failed",
                "name": name,
                "expected_country": expected,
                "detected_country": "",
                "exit_ip": "",
                "latency_ms": None,
                "reason": "probe_timeout",
                "checked_at": checked_at,
            }
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)


def main():
    config = load_config()
    settings = config.get("settings", {}).get("geo_verification", {})
    if not settings.get("enabled", True):
        print("Geo verification is disabled.")
        return 0

    xray_path = shutil.which("xray")
    if not xray_path:
        print("xray executable was not found in PATH.", file=sys.stderr)
        return 2

    VERIFIED_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    cache_doc = load_json(CACHE_PATH, {"version": 1, "entries": {}})
    cache = cache_doc.get("entries", {})
    current_fingerprints = set()
    tasks = []
    country_records = []

    for source in config.get("sources", []):
        slug = source["slug"]
        expected = source["iso2"].upper()
        filtered_path = FILTERED_DIR / f"{slug}.txt"
        links = nonempty_lines(filtered_path)

        records = []
        for link in links:
            try:
                fp = config_fingerprint(link)
            except Exception as exc:
                fp = hashlib.sha256(link.encode("utf-8")).hexdigest()
                cache[fp] = {
                    "status": "failed",
                    "name": display_name(link),
                    "expected_country": expected,
                    "detected_country": "",
                    "exit_ip": "",
                    "latency_ms": None,
                    "reason": f"fingerprint_error: {exc}",
                    "checked_at": iso_now(),
                }

            current_fingerprints.add(fp)
            record = {
                "fingerprint": fp,
                "link": link,
                "name": display_name(link),
                "expected_country": expected,
            }
            records.append(record)

            cached = cache.get(fp)
            if not cached or not cache_is_fresh(cached, settings):
                tasks.append(record)

        country_records.append((source, records))

    parallel = max(1, int(settings.get("parallel_checks", 16)))
    print(f"Filtered configs: {len(current_fingerprints)}")
    print(f"Active checks required now: {len(tasks)}")
    print(f"Parallel checks: {parallel}")

    if tasks:
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = [
                executor.submit(run_one_check, task, settings, xray_path)
                for task in tasks
            ]
            for future in concurrent.futures.as_completed(futures):
                fp, result = future.result()
                cache[fp] = result
                completed += 1
                if completed % 25 == 0 or completed == len(tasks):
                    print(f"Checked {completed}/{len(tasks)}")

    # Prune cache entries for configs no longer present in filtered subscriptions.
    cache = {
        fp: value
        for fp, value in cache.items()
        if fp in current_fingerprints
    }

    report_sources = []
    total_counts = Counter()
    mismatch_samples = []

    for source, records in country_records:
        slug = source["slug"]
        expected = source["iso2"].upper()
        verified_path = VERIFIED_DIR / f"{slug}.txt"

        verified_links = []
        status_counts = Counter()
        detected_countries = Counter()

        for record in records:
            item = cache.get(record["fingerprint"], {})
            status = item.get("status", "failed")
            status_counts[status] += 1

            detected = item.get("detected_country", "")
            if detected:
                detected_countries[detected] += 1

            if status == "verified" and detected == expected:
                verified_links.append(record["link"])
            elif status == "wrong_country" and len(mismatch_samples) < 100:
                mismatch_samples.append({
                    "country_file": slug,
                    "name": record["name"],
                    "expected": expected,
                    "detected": detected,
                    "exit_ip": item.get("exit_ip", ""),
                    "latency_ms": item.get("latency_ms"),
                })

        definitive = status_counts["verified"] + status_counts["wrong_country"]
        used_previous = False

        if verified_links or definitive > 0:
            verified_path.write_text(
                ("\n".join(verified_links) + "\n") if verified_links else "",
                encoding="utf-8",
            )
        elif verified_path.exists() and verified_path.stat().st_size > 0:
            # Fail-safe: if GitHub could not complete any geo probe for this
            # country, keep the last verified output instead of wiping it.
            used_previous = True
            verified_links = nonempty_lines(verified_path)

        source_report = {
            "name": source["name"],
            "slug": slug,
            "expected_country": expected,
            "filtered_entries": len(records),
            "verified_entries": len(verified_links),
            "status_counts": dict(sorted(status_counts.items())),
            "detected_countries": dict(sorted(detected_countries.items())),
            "used_previous_verified_output": used_previous,
        }
        report_sources.append(source_report)
        total_counts.update(status_counts)

    cache_doc = {
        "version": 1,
        "updated_at": iso_now(),
        "entries": cache,
    }
    CACHE_PATH.write_text(
        json.dumps(cache_doc, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = {
        "generated_at": iso_now(),
        "probe_url": settings["probe_url"],
        "active_checks_this_run": len(tasks),
        "totals": {
            "filtered_entries": len(current_fingerprints),
            "status_counts": dict(sorted(total_counts.items())),
        },
        "sources": report_sources,
        "wrong_country_samples": mismatch_samples,
    }
    REPORT_PATH.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("Geo verification complete.")
    print(json.dumps(report["totals"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
