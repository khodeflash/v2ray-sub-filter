#!/usr/bin/env python3
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
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

import update_subscriptions as updater


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "sources.json"
FILTERED_DIR = ROOT / "subscriptions"
VERIFIED_DIR = ROOT / "subscriptions_verified"
REPORT_DIR = ROOT / "reports"
CACHE_PATH = REPORT_DIR / "geo_cache.json"
REPORT_PATH = REPORT_DIR / "geo_latest.json"

CACHE_VERSION = 2
PORT_LOCK = threading.Lock()

COUNTRY_FILE_SLUGS = {
    "AD": "Andorra",
    "AE": "United_Arab_Emirates",
    "AF": "Afghanistan",
    "AG": "Antigua_and_Barbuda",
    "AI": "Anguilla",
    "AL": "Albania",
    "AM": "Armenia",
    "AO": "Angola",
    "AQ": "Antarctica",
    "AR": "Argentina",
    "AS": "American_Samoa",
    "AT": "Austria",
    "AU": "Australia",
    "AW": "Aruba",
    "AX": "land_Islands",
    "AZ": "Azerbaijan",
    "BA": "Bosnia_and_Herzegovina",
    "BB": "Barbados",
    "BD": "Bangladesh",
    "BE": "Belgium",
    "BF": "Burkina_Faso",
    "BG": "Bulgaria",
    "BH": "Bahrain",
    "BI": "Burundi",
    "BJ": "Benin",
    "BL": "Saint_Barth_lemy",
    "BM": "Bermuda",
    "BN": "Brunei_Darussalam",
    "BO": "Bolivia_Plurinational_State_of",
    "BQ": "Bonaire_Sint_Eustatius_and_Saba",
    "BR": "Brazil",
    "BS": "Bahamas",
    "BT": "Bhutan",
    "BV": "Bouvet_Island",
    "BW": "Botswana",
    "BY": "Belarus",
    "BZ": "Belize",
    "CA": "Canada",
    "CC": "Cocos_Keeling_Islands",
    "CD": "Congo_The_Democratic_Republic_of_the",
    "CF": "Central_African_Republic",
    "CG": "Congo",
    "CH": "Switzerland",
    "CI": "C_te_d_Ivoire",
    "CK": "Cook_Islands",
    "CL": "Chile",
    "CM": "Cameroon",
    "CN": "China",
    "CO": "Colombia",
    "CR": "Costa_Rica",
    "CU": "Cuba",
    "CV": "Cabo_Verde",
    "CW": "Cura_ao",
    "CX": "Christmas_Island",
    "CY": "Cyprus",
    "CZ": "Czechia",
    "DE": "Germany",
    "DJ": "Djibouti",
    "DK": "Denmark",
    "DM": "Dominica",
    "DO": "Dominican_Republic",
    "DZ": "Algeria",
    "EC": "Ecuador",
    "EE": "Estonia",
    "EG": "Egypt",
    "EH": "Western_Sahara",
    "ER": "Eritrea",
    "ES": "Spain",
    "ET": "Ethiopia",
    "FI": "Finland",
    "FJ": "Fiji",
    "FK": "Falkland_Islands_Malvinas",
    "FM": "Micronesia_Federated_States_of",
    "FO": "Faroe_Islands",
    "FR": "France",
    "GA": "Gabon",
    "GB": "United_Kingdom",
    "GD": "Grenada",
    "GE": "Georgia",
    "GF": "French_Guiana",
    "GG": "Guernsey",
    "GH": "Ghana",
    "GI": "Gibraltar",
    "GL": "Greenland",
    "GM": "Gambia",
    "GN": "Guinea",
    "GP": "Guadeloupe",
    "GQ": "Equatorial_Guinea",
    "GR": "Greece",
    "GS": "South_Georgia_and_the_South_Sandwich_Islands",
    "GT": "Guatemala",
    "GU": "Guam",
    "GW": "Guinea_Bissau",
    "GY": "Guyana",
    "HK": "Hong_Kong",
    "HM": "Heard_Island_and_McDonald_Islands",
    "HN": "Honduras",
    "HR": "Croatia",
    "HT": "Haiti",
    "HU": "Hungary",
    "ID": "Indonesia",
    "IE": "Ireland",
    "IL": "Israel",
    "IM": "Isle_of_Man",
    "IN": "India",
    "IO": "British_Indian_Ocean_Territory",
    "IQ": "Iraq",
    "IR": "Iran_Islamic_Republic_of",
    "IS": "Iceland",
    "IT": "Italy",
    "JE": "Jersey",
    "JM": "Jamaica",
    "JO": "Jordan",
    "JP": "Japan",
    "KE": "Kenya",
    "KG": "Kyrgyzstan",
    "KH": "Cambodia",
    "KI": "Kiribati",
    "KM": "Comoros",
    "KN": "Saint_Kitts_and_Nevis",
    "KP": "Korea_Democratic_People_s_Republic_of",
    "KR": "Korea_Republic_of",
    "KW": "Kuwait",
    "KY": "Cayman_Islands",
    "KZ": "Kazakhstan",
    "LA": "Lao_People_s_Democratic_Republic",
    "LB": "Lebanon",
    "LC": "Saint_Lucia",
    "LI": "Liechtenstein",
    "LK": "Sri_Lanka",
    "LR": "Liberia",
    "LS": "Lesotho",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "LV": "Latvia",
    "LY": "Libya",
    "MA": "Morocco",
    "MC": "Monaco",
    "MD": "Moldova_Republic_of",
    "ME": "Montenegro",
    "MF": "Saint_Martin_French_part",
    "MG": "Madagascar",
    "MH": "Marshall_Islands",
    "MK": "North_Macedonia",
    "ML": "Mali",
    "MM": "Myanmar",
    "MN": "Mongolia",
    "MO": "Macao",
    "MP": "Northern_Mariana_Islands",
    "MQ": "Martinique",
    "MR": "Mauritania",
    "MS": "Montserrat",
    "MT": "Malta",
    "MU": "Mauritius",
    "MV": "Maldives",
    "MW": "Malawi",
    "MX": "Mexico",
    "MY": "Malaysia",
    "MZ": "Mozambique",
    "NA": "Namibia",
    "NC": "New_Caledonia",
    "NE": "Niger",
    "NF": "Norfolk_Island",
    "NG": "Nigeria",
    "NI": "Nicaragua",
    "NL": "Netherlands",
    "NO": "Norway",
    "NP": "Nepal",
    "NR": "Nauru",
    "NU": "Niue",
    "NZ": "New_Zealand",
    "OM": "Oman",
    "PA": "Panama",
    "PE": "Peru",
    "PF": "French_Polynesia",
    "PG": "Papua_New_Guinea",
    "PH": "Philippines",
    "PK": "Pakistan",
    "PL": "Poland",
    "PM": "Saint_Pierre_and_Miquelon",
    "PN": "Pitcairn",
    "PR": "Puerto_Rico",
    "PS": "Palestine_State_of",
    "PT": "Portugal",
    "PW": "Palau",
    "PY": "Paraguay",
    "QA": "Qatar",
    "RE": "R_union",
    "RO": "Romania",
    "RS": "Serbia",
    "RU": "Russia",
    "RW": "Rwanda",
    "SA": "Saudi_Arabia",
    "SB": "Solomon_Islands",
    "SC": "Seychelles",
    "SD": "Sudan",
    "SE": "Sweden",
    "SG": "Singapore",
    "SH": "Saint_Helena_Ascension_and_Tristan_da_Cunha",
    "SI": "Slovenia",
    "SJ": "Svalbard_and_Jan_Mayen",
    "SK": "Slovakia",
    "SL": "Sierra_Leone",
    "SM": "San_Marino",
    "SN": "Senegal",
    "SO": "Somalia",
    "SR": "Suriname",
    "SS": "South_Sudan",
    "ST": "Sao_Tome_and_Principe",
    "SV": "El_Salvador",
    "SX": "Sint_Maarten_Dutch_part",
    "SY": "Syrian_Arab_Republic",
    "SZ": "Eswatini",
    "TC": "Turks_and_Caicos_Islands",
    "TD": "Chad",
    "TF": "French_Southern_Territories",
    "TG": "Togo",
    "TH": "Thailand",
    "TJ": "Tajikistan",
    "TK": "Tokelau",
    "TL": "Timor_Leste",
    "TM": "Turkmenistan",
    "TN": "Tunisia",
    "TO": "Tonga",
    "TR": "Turkiye",
    "TT": "Trinidad_and_Tobago",
    "TV": "Tuvalu",
    "TW": "Taiwan_Province_of_China",
    "TZ": "Tanzania_United_Republic_of",
    "UA": "Ukraine",
    "UG": "Uganda",
    "UM": "United_States_Minor_Outlying_Islands",
    "US": "United_States",
    "UY": "Uruguay",
    "UZ": "Uzbekistan",
    "VA": "Holy_See_Vatican_City_State",
    "VC": "Saint_Vincent_and_the_Grenadines",
    "VE": "Venezuela_Bolivarian_Republic_of",
    "VG": "Virgin_Islands_British",
    "VI": "Virgin_Islands_U_S",
    "VN": "Viet_Nam",
    "VU": "Vanuatu",
    "WF": "Wallis_and_Futuna",
    "WS": "Samoa",
    "YE": "Yemen",
    "YT": "Mayotte",
    "ZA": "South_Africa",
    "ZM": "Zambia",
    "ZW": "Zimbabwe"
}
COUNTRY_SLUG_TO_ISO2 = {
    slug: code
    for code, slug in COUNTRY_FILE_SLUGS.items()
}


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
    lowered = {str(key).lower(): value for key, value in query.items()}
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
        data = dict(decode_vmess(link))
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


def tls_settings(
    server_name,
    fingerprint="",
    allow_insecure=False,
    alpn="",
    ech_config="",
):
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

    if ech_config:
        settings["echConfigList"] = ech_config

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


def effective_tls_sni(address, sni, host):
    if sni:
        return sni

    hosts = split_csv(host)
    if hosts:
        return hosts[0]

    if address and not is_ip_address(address):
        return address

    return ""


def build_stream_settings_from_vless(parsed, query):
    transport = first_query(query, "type", default="tcp").lower() or "tcp"
    security = first_query(query, "security").lower()
    host = first_query(query, "host")
    path = first_query(query, "path", default="/") or "/"
    header_type = first_query(query, "headerType", "header", default="none")
    sni = first_query(query, "sni", "serverName")
    fingerprint = first_query(query, "fp", "fingerprint")
    alpn = first_query(query, "alpn")
    ech = first_query(query, "ech", "echConfigList")

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

    stream = {
        "method": method,
        "security": security,
    }

    if method == "raw":
        stream["rawSettings"] = raw_settings(header_type, host, path)

    elif method == "websocket":
        ws = {"path": path}
        if host:
            ws["host"] = host

        heartbeat = first_query(query, "heartbeatPeriod")
        if heartbeat:
            try:
                ws["heartbeatPeriod"] = int(heartbeat)
            except ValueError:
                pass

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

        extra = first_query(query, "extra")
        if extra:
            parsed_extra = parse_extra_json(extra)
            if parsed_extra is None:
                raise ValueError("invalid XHTTP extra JSON")
            xhttp["extra"] = parsed_extra

        stream["xhttpSettings"] = xhttp

    elif method == "httpupgrade":
        hup = {"path": path}
        if host:
            hup["host"] = host
        stream["httpupgradeSettings"] = hup

    if security == "tls":
        effective_sni = effective_tls_sni(parsed.hostname, sni, host)

        allow_insecure = (
            parse_bool(first_query(query, "allowInsecure"))
            or parse_bool(first_query(query, "insecure"))
        )

        stream["tlsSettings"] = tls_settings(
            effective_sni,
            fingerprint=fingerprint,
            allow_insecure=allow_insecure,
            alpn=alpn,
            ech_config=ech,
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
    stream = {
        "method": method,
        "security": security,
    }

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
        elif isinstance(extra, str) and extra.strip():
            parsed_extra = parse_extra_json(extra)
            if parsed_extra is None:
                raise ValueError("invalid VMess XHTTP extra JSON")
            xhttp["extra"] = parsed_extra

        stream["xhttpSettings"] = xhttp

    elif method == "httpupgrade":
        hup = {"path": path}
        if host:
            hup["host"] = host
        stream["httpupgradeSettings"] = hup

    if security == "tls":
        address = str(data.get("add", "")).strip()
        sni = str(data.get("sni", "")).strip()
        effective_sni = effective_tls_sni(address, sni, host)

        ech = str(
            data.get("echConfigList", data.get("ech", ""))
        ).strip()

        stream["tlsSettings"] = tls_settings(
            effective_sni,
            fingerprint=str(data.get("fp", "")).strip(),
            allow_insecure=parse_bool(data.get("allowInsecure", False)),
            alpn=str(data.get("alpn", "")).strip(),
            ech_config=ech,
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

    raise NotImplementedError(
        "only filtered VLESS and VMess are actively verified"
    )


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
        "log": {
            "loglevel": "warning",
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": False,
                },
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
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.15,
            ):
                return True
        except OSError:
            time.sleep(0.08)

    return False


def parse_trace(text):
    values = {}

    for line in text.splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    return values.get("ip", ""), values.get("loc", "").upper()


def cache_ttl_hours(status, settings):
    if status == "geo_resolved":
        return float(settings.get("verified_ttl_hours", 12))

    if status == "config_invalid":
        return float(settings.get("config_invalid_ttl_hours", 24))

    if status == "unsupported":
        return float(settings.get("unsupported_ttl_hours", 24))

    return float(settings.get("failed_ttl_hours", 3))


def cache_is_fresh(item, settings):
    checked = parse_iso(item.get("checked_at"))
    if not checked:
        return False

    ttl = cache_ttl_hours(item.get("status", "failed"), settings)
    return utc_now() < checked + timedelta(hours=ttl)


def read_tail(path, limit=800):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""

    return text[-limit:]


def make_result(
    *,
    status,
    stage,
    name,
    expected,
    reason,
    checked_at,
    detected="",
    exit_ip="",
    latency_ms=None,
    detail="",
    probe_url="",
):
    return {
        "status": status,
        "stage": stage,
        "name": name,
        "expected_country": expected,
        "detected_country": detected,
        "exit_ip": exit_ip,
        "latency_ms": latency_ms,
        "reason": reason,
        "detail": detail,
        "probe_url": probe_url,
        "checked_at": checked_at,
    }


def curl_trace(socks_port, url, timeout):
    started = time.monotonic()

    result = subprocess.run(
        [
            "curl",
            "-fsS",
            "--max-redirs",
            "0",
            "--connect-timeout",
            str(min(timeout, 4.0)),
            "--max-time",
            str(timeout),
            "--proxy",
            f"socks5h://127.0.0.1:{socks_port}",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 2.0,
    )

    latency_ms = round((time.monotonic() - started) * 1000)
    return result, latency_ms


def tunnel_http_test(socks_port, url, timeout):
    result = subprocess.run(
        [
            "curl",
            "-sS",
            "--max-redirs",
            "0",
            "--connect-timeout",
            str(min(timeout, 4.0)),
            "--max-time",
            str(timeout),
            "--proxy",
            f"socks5h://127.0.0.1:{socks_port}",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 2.0,
    )

    code = result.stdout.strip()
    return result.returncode == 0 and code.isdigit() and int(code) > 0, code, result


def validate_xray_config(xray_path, config_path, timeout):
    try:
        result = subprocess.run(
            [
                xray_path,
                "run",
                "-test",
                "-c",
                str(config_path),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "xray config validation timed out"

    output = (result.stderr + "\n" + result.stdout).strip()
    return result.returncode == 0, output[-1000:]


def run_one_check(task, settings, xray_path):
    link = task["link"]
    expected = task["expected_country"]
    name = task["name"]
    fingerprint = task["fingerprint"]
    checked_at = iso_now()

    try:
        outbound = build_outbound(link)
    except NotImplementedError as exc:
        return fingerprint, make_result(
            status="unsupported",
            stage="build",
            name=name,
            expected=expected,
            reason="unsupported_transport_or_protocol",
            detail=str(exc),
            checked_at=checked_at,
        )
    except Exception as exc:
        return fingerprint, make_result(
            status="failed",
            stage="build",
            name=name,
            expected=expected,
            reason="build_error",
            detail=str(exc),
            checked_at=checked_at,
        )

    host, port = endpoint_from_outbound(outbound)

    if not tcp_reachable(
        host,
        port,
        float(settings.get("tcp_connect_timeout_seconds", 2.5)),
    ):
        return fingerprint, make_result(
            status="failed",
            stage="tcp",
            name=name,
            expected=expected,
            reason="tcp_unreachable",
            checked_at=checked_at,
        )

    socks_port = allocate_port()
    client_config = build_client_config(outbound, socks_port)

    with tempfile.TemporaryDirectory(prefix="xray-geo-") as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_path = tmpdir_path / "config.json"
        log_path = tmpdir_path / "xray-stderr.log"
        config_path.write_text(
            json.dumps(client_config),
            encoding="utf-8",
        )

        valid, validation_detail = validate_xray_config(
            xray_path,
            config_path,
            timeout=5.0,
        )

        if not valid:
            return fingerprint, make_result(
                status="config_invalid",
                stage="xray_config",
                name=name,
                expected=expected,
                reason="xray_config_rejected",
                detail=validation_detail,
                checked_at=checked_at,
            )

        with log_path.open("w", encoding="utf-8") as log_handle:
            process = subprocess.Popen(
                [
                    xray_path,
                    "run",
                    "-c",
                    str(config_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=log_handle,
                text=True,
            )

            try:
                if not wait_for_port(
                    socks_port,
                    process,
                    float(settings.get("xray_start_timeout_seconds", 3.0)),
                ):
                    return fingerprint, make_result(
                        status="failed",
                        stage="xray_start",
                        name=name,
                        expected=expected,
                        reason="xray_start_failed",
                        detail=read_tail(log_path),
                        checked_at=checked_at,
                    )

                timeout = float(settings.get("probe_timeout_seconds", 6.0))
                probe_urls = settings.get("probe_urls", [])
                probe_errors = []

                for probe_url in probe_urls:
                    try:
                        probe_result, latency_ms = curl_trace(
                            socks_port,
                            probe_url,
                            timeout,
                        )
                    except subprocess.TimeoutExpired:
                        probe_errors.append(
                            f"{probe_url}: timeout"
                        )
                        continue

                    if probe_result.returncode != 0:
                        probe_errors.append(
                            f"{probe_url}: curl={probe_result.returncode} "
                            f"{probe_result.stderr.strip()[-200:]}"
                        )
                        continue

                    exit_ip, country = parse_trace(probe_result.stdout)

                    if country and len(country) == 2:
                        return fingerprint, make_result(
                            status="geo_resolved",
                            stage="geo",
                            name=name,
                            expected=expected,
                            detected=country,
                            exit_ip=exit_ip,
                            latency_ms=latency_ms,
                            reason="geo_resolved",
                            probe_url=probe_url,
                            checked_at=checked_at,
                        )

                    probe_errors.append(
                        f"{probe_url}: trace_missing_country"
                    )

                tunnel_url = settings.get(
                    "tunnel_test_url",
                    "http://example.com/",
                )

                try:
                    tunnel_ok, http_code, tunnel_result = tunnel_http_test(
                        socks_port,
                        tunnel_url,
                        timeout,
                    )
                except subprocess.TimeoutExpired:
                    tunnel_ok = False
                    http_code = ""
                    tunnel_result = None

                xray_detail = read_tail(log_path)

                if tunnel_ok:
                    detail = "; ".join(probe_errors)[-1000:]
                    if xray_detail:
                        detail += f" | xray: {xray_detail}"

                    return fingerprint, make_result(
                        status="failed",
                        stage="geo",
                        name=name,
                        expected=expected,
                        reason="geo_probe_failed_tunnel_ok",
                        detail=detail,
                        checked_at=checked_at,
                    )

                tunnel_error = ""
                if tunnel_result is not None:
                    tunnel_error = tunnel_result.stderr.strip()[-300:]

                detail_parts = [
                    "; ".join(probe_errors)[-700:],
                    f"tunnel_http_code={http_code}",
                    tunnel_error,
                    xray_detail,
                ]
                detail = " | ".join(
                    part for part in detail_parts if part
                )[-1200:]

                return fingerprint, make_result(
                    status="failed",
                    stage="proxy_tunnel",
                    name=name,
                    expected=expected,
                    reason="proxy_tunnel_failed",
                    detail=detail,
                    checked_at=checked_at,
                )

            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1.5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1.0)


def get_xray_version(xray_path):
    try:
        result = subprocess.run(
            [xray_path, "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return ""

    output = (result.stdout or result.stderr).strip()
    return output.splitlines()[0] if output else ""



def country_file_slug(country_code):
    code = str(country_code).strip().upper()
    return COUNTRY_FILE_SLUGS.get(code, code)


def country_code_from_verified_filename(path):
    return COUNTRY_SLUG_TO_ISO2.get(path.stem, path.stem.upper())


def load_previous_verified_assignments():
    assignments = {}

    if not VERIFIED_DIR.exists():
        return assignments

    for path in VERIFIED_DIR.glob("*.txt"):
        country_code = country_code_from_verified_filename(path)

        if len(country_code) != 2 or not country_code.isalpha():
            continue

        for link in nonempty_lines(path):
            try:
                fingerprint = config_fingerprint(link)
            except Exception:
                continue

            assignments[fingerprint] = country_code

    return assignments


def renamed_verified_links(country_code, records):
    counters = {}
    output = []

    ordered = sorted(
        records,
        key=lambda item: (
            updater.detect_protocol(item["link"]),
            item["fingerprint"],
        ),
    )

    for record in ordered:
        protocol = updater.detect_protocol(record["link"])
        counters[protocol] = counters.get(protocol, 0) + 1

        remark = (
            f"{country_code}-"
            f"{updater.protocol_label(protocol)}-"
            f"{counters[protocol]:03d}"
        )

        renamed, success = updater.rename_any_config(
            record["link"],
            remark,
        )

        if success:
            output.append(renamed)
        else:
            output.append(record["link"])

    return output


def write_verified_buckets(
    country_records,
    cache,
    previous_assignments,
):
    current_by_fingerprint = {}

    for _, records in country_records:
        for record in records:
            current_by_fingerprint.setdefault(
                record["fingerprint"],
                record,
            )

    buckets = {}
    preserved_last_known = 0
    resolved_now = 0

    for fingerprint, record in current_by_fingerprint.items():
        item = cache.get(fingerprint, {})
        detected = str(
            item.get("detected_country", "")
        ).strip().upper()

        if (
            item.get("status") == "geo_resolved"
            and len(detected) == 2
            and detected.isalpha()
        ):
            country_code = detected
            resolved_now += 1

        else:
            previous_country = previous_assignments.get(fingerprint, "")
            if (
                len(previous_country) == 2
                and previous_country.isalpha()
            ):
                country_code = previous_country
                preserved_last_known += 1
            else:
                continue

        buckets.setdefault(country_code, {})[fingerprint] = record

    for path in VERIFIED_DIR.glob("*.txt"):
        path.unlink()

    outputs = {}

    for country_code in sorted(buckets):
        records = list(buckets[country_code].values())
        links = renamed_verified_links(country_code, records)

        slug = country_file_slug(country_code)
        path = VERIFIED_DIR / f"{slug}.txt"

        path.write_text(
            ("\n".join(links) + "\n") if links else "",
            encoding="utf-8",
        )

        outputs[country_code] = {
            "file": path.name,
            "entries": len(links),
        }

    return outputs, resolved_now, preserved_last_known

def main():
    config = load_config()
    settings = config.get("settings", {}).get("geo_verification", {})

    if not settings.get("enabled", True):
        print("Geo verification is disabled.")
        return 0

    xray_path = shutil.which("xray")
    if not xray_path:
        print(
            "xray executable was not found in PATH.",
            file=sys.stderr,
        )
        return 2

    VERIFIED_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    previous_assignments = load_previous_verified_assignments()

    cache_doc = load_json(
        CACHE_PATH,
        {
            "version": CACHE_VERSION,
            "entries": {},
        },
    )

    if cache_doc.get("version") != CACHE_VERSION:
        print(
            "Geo cache schema changed; previous cache will not be reused."
        )
        cache = {}
    else:
        cache = cache_doc.get("entries", {})

    current_fingerprints = set()
    tasks_by_fingerprint = {}
    country_records = []

    for source in config.get("sources", []):
        slug = source["slug"]
        expected = source["iso2"].upper()
        filtered_path = FILTERED_DIR / f"{slug}.txt"
        links = nonempty_lines(filtered_path)

        records = []

        for link in links:
            try:
                fingerprint = config_fingerprint(link)
            except Exception as exc:
                fingerprint = hashlib.sha256(
                    link.encode("utf-8")
                ).hexdigest()

                cache[fingerprint] = make_result(
                    status="failed",
                    stage="fingerprint",
                    name=display_name(link),
                    expected=expected,
                    reason="fingerprint_error",
                    detail=str(exc),
                    checked_at=iso_now(),
                )

            current_fingerprints.add(fingerprint)

            record = {
                "fingerprint": fingerprint,
                "link": link,
                "name": display_name(link),
                "expected_country": expected,
                "source_slug": slug,
            }
            records.append(record)

            cached = cache.get(fingerprint)

            if not cached or not cache_is_fresh(cached, settings):
                tasks_by_fingerprint.setdefault(
                    fingerprint,
                    record,
                )

        country_records.append((source, records))

    tasks = list(tasks_by_fingerprint.values())
    parallel = max(
        1,
        int(settings.get("parallel_checks", 20)),
    )

    print(f"Unique filtered configs: {len(current_fingerprints)}")
    print(f"Active checks required now: {len(tasks)}")
    print(f"Parallel checks: {parallel}")

    if tasks:
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=parallel
        ) as executor:
            futures = [
                executor.submit(
                    run_one_check,
                    task,
                    settings,
                    xray_path,
                )
                for task in tasks
            ]

            for future in concurrent.futures.as_completed(futures):
                fingerprint, result = future.result()
                cache[fingerprint] = result
                completed += 1

                if completed % 25 == 0 or completed == len(tasks):
                    print(f"Checked {completed}/{len(tasks)}")

    cache = {
        fingerprint: value
        for fingerprint, value in cache.items()
        if fingerprint in current_fingerprints
    }

    verified_outputs, resolved_now, preserved_last_known = (
        write_verified_buckets(
            country_records,
            cache,
            previous_assignments,
        )
    )

    report_sources = []
    total_status_counts = Counter()
    total_reason_counts = Counter()
    total_stage_counts = Counter()
    mismatch_samples = []
    total_source_matches = 0
    total_source_mismatches = 0

    for source, records in country_records:
        slug = source["slug"]
        expected = source["iso2"].upper()

        status_counts = Counter()
        reason_counts = Counter()
        stage_counts = Counter()
        detected_countries = Counter()
        source_matches = 0
        source_mismatches = 0

        for record in records:
            item = cache.get(record["fingerprint"], {})
            status = item.get("status", "failed")
            reason = item.get("reason", "unknown")
            stage = item.get("stage", "unknown")

            status_counts[status] += 1
            reason_counts[reason] += 1
            stage_counts[stage] += 1

            detected = str(
                item.get("detected_country", "")
            ).strip().upper()

            if detected:
                detected_countries[detected] += 1

            if (
                status == "geo_resolved"
                and len(detected) == 2
            ):
                if detected == expected:
                    source_matches += 1
                else:
                    source_mismatches += 1

                    if len(mismatch_samples) < 100:
                        mismatch_samples.append({
                            "source_file": slug,
                            "name": record["name"],
                            "expected": expected,
                            "detected": detected,
                            "destination_file": (
                                country_file_slug(detected)
                                + ".txt"
                            ),
                            "exit_ip": item.get(
                                "exit_ip",
                                "",
                            ),
                            "latency_ms": item.get(
                                "latency_ms"
                            ),
                        })

        report_sources.append({
            "name": source["name"],
            "slug": slug,
            "expected_country": expected,
            "filtered_entries": len(records),
            "source_country_matches": source_matches,
            "reclassified_out": source_mismatches,
            "status_counts": dict(
                sorted(status_counts.items())
            ),
            "reason_counts": dict(
                sorted(reason_counts.items())
            ),
            "stage_counts": dict(
                sorted(stage_counts.items())
            ),
            "detected_countries": dict(
                sorted(detected_countries.items())
            ),
        })

        total_source_matches += source_matches
        total_source_mismatches += source_mismatches
        total_status_counts.update(status_counts)
        total_reason_counts.update(reason_counts)
        total_stage_counts.update(stage_counts)

    cache_doc = {
        "version": CACHE_VERSION,
        "updated_at": iso_now(),
        "entries": cache,
    }

    CACHE_PATH.write_text(
        json.dumps(
            cache_doc,
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    report = {
        "generated_at": iso_now(),
        "xray_version": get_xray_version(xray_path),
        "probe_urls": settings.get("probe_urls", []),
        "tunnel_test_url": settings.get(
            "tunnel_test_url",
            "",
        ),
        "active_checks_this_run": len(tasks),
        "verified_output_policy": (
            "bucket_by_detected_exit_country"
        ),
        "totals": {
            "unique_filtered_entries": len(
                current_fingerprints
            ),
            "geo_resolved_current": resolved_now,
            "preserved_last_known_country": (
                preserved_last_known
            ),
            "source_country_matches": total_source_matches,
            "source_country_mismatches": (
                total_source_mismatches
            ),
            "status_counts": dict(
                sorted(total_status_counts.items())
            ),
            "reason_counts": dict(
                sorted(total_reason_counts.items())
            ),
            "stage_counts": dict(
                sorted(total_stage_counts.items())
            ),
        },
        "verified_outputs": verified_outputs,
        "sources": report_sources,
        "reclassification_samples": mismatch_samples,
    }

    REPORT_PATH.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    print("Geo verification and reclassification complete.")
    print(
        json.dumps(
            report["totals"],
            indent=2,
            sort_keys=True,
        )
    )

    print("Verified country outputs:")
    print(
        json.dumps(
            verified_outputs,
            indent=2,
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
