#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
leto_fetch.py — LetoVPN fetch + DNS endpoint resolution + GitHub Gist upload.

GitHub Actions env:
  GIST_TOKEN, GIST_ID
Optional:
  GIST_FILENAME (default: leto.txt)
  GIST_DESCRIPTION (default: LetoVPN subscription)
  DNS_IPV4_FIRST (default: 1)
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

GM = "https://api.guerrillamail.com/ajax.php"
LETO = "https://m-app.letovpn.com"
GITHUB_API = "https://api.github.com"
CTX = ssl.create_default_context()
_DNS_CACHE: dict[str, str] = {}


class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def http(
    method: str,
    url: str,
    body: Any = None,
    headers: dict | None = None,
    timeout: float = 30,
) -> tuple[int | None, bytes]:
    h = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/plain, */*",
    }
    if headers:
        h.update(headers)

    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        elif isinstance(body, bytes):
            data = body
        else:
            data = str(body).encode()

    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


def resolve_host(host: str) -> str:
    """Resolve only the remote server address; preserve SNI, WS Host and path."""
    host = str(host or "").strip()
    if not host:
        return host

    try:
        return ipaddress.ip_address(host.strip("[]")).compressed
    except ValueError:
        pass

    if host in _DNS_CACHE:
        return _DNS_CACHE[host]

    infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    addresses = []
    for info in infos:
        ip = info[4][0].split("%", 1)[0]
        if ip not in addresses:
            addresses.append(ip)

    if not addresses:
        raise OSError(f"DNS returned no addresses for {host}")

    ipv4_first = os.getenv("DNS_IPV4_FIRST", "1").lower() not in (
        "0", "false", "no"
    )
    preferred = 4 if ipv4_first else 6
    addresses.sort(
        key=lambda x: ipaddress.ip_address(x).version != preferred
    )
    result = addresses[0]
    _DNS_CACHE[host] = result
    print(f"      DNS: {host} -> {result}")
    return result


def normalize_endpoint_hosts(configs: list) -> None:
    """Change only Xray endpoint address fields."""
    for item in configs:
        for ob in item.get("outbounds") or []:
            proto = ob.get("protocol")
            settings = ob.get("settings") or {}
            targets = []

            if proto == "vless":
                targets = settings.get("vnext") or []
            elif proto == "trojan":
                targets = settings.get("servers") or []

            for server in targets:
                original = server.get("address")
                if not original:
                    continue
                try:
                    server["address"] = resolve_host(original)
                except Exception as exc:
                    print(f"      DNS WARNING: {original}: {exc}")


def gm(function: str, **params) -> dict:
    query = urllib.parse.urlencode({"f": function, **params})
    status, raw = http("GET", f"{GM}?{query}", timeout=20)
    try:
        result = json.loads(raw.decode("utf-8", "replace"))
        if isinstance(result, dict):
            result["_http_status"] = status
            return result
        return {"_http_status": status, "_response": result}
    except Exception:
        return {
            "_http_status": status,
            "_raw": raw.decode("utf-8", "replace")[:1000],
        }


def make_temp_email() -> tuple[str, str]:
    result = gm("get_email_address", lang="en")
    email = result.get("email_addr")
    sid = result.get("sid_token")

    if not email or not sid:
        raise RuntimeError(f"GuerrillaMail failed: {result}")

    return email, sid


def request_otp(email: str) -> None:
    status, raw = http(
        "POST",
        f"{LETO}/api/v1/auth/otp/request",
        {"email": email},
        {
            "Content-Type": "application/json",
            "User-Agent": "okhttp/4.12.0",
        },
    )

    if status not in (200, 201, 202, 204, 429):
        raise RuntimeError(
            f"otp/request HTTP {status}: "
            f"{raw.decode('utf-8', 'replace')[:500]}"
        )

    if status == 429:
        print("    OTP request returned HTTP 429; checking mailbox anyway")


def _collect_strings(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Collect string values recursively from the mail API response."""
    found: list[tuple[str, str]] = []

    if isinstance(value, str):
        if value.strip():
            found.append((prefix or "value", value))
    elif isinstance(value, dict):
        for key, child in value.items():
            if key.startswith("_"):
                continue
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            found.extend(_collect_strings(child, child_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_collect_strings(child, f"{prefix}[{index}]"))

    return found


def _mail_text(full: dict) -> tuple[str, list[str]]:
    """Build searchable text from all returned mail fields."""
    strings = _collect_strings(full)
    chunks: list[str] = []
    field_names: list[str] = []

    for name, value in strings:
        field_names.append(name)
        chunks.append(value)

        # Some providers return HTML as a field. Decode it to readable text.
        if "<" in value and ">" in value:
            parser = HTMLTextExtractor()
            try:
                parser.feed(value)
                if parser.parts:
                    chunks.append(" ".join(parser.parts))
            except Exception:
                pass

    combined = unescape("\n".join(chunks))
    combined = combined.replace("\u200b", "").replace("\ufeff", "")
    return combined, sorted(set(field_names))


def _extract_otp(text: str) -> str | None:
    """Extract common OTP layouts without accepting arbitrary long numbers."""
    normalized = unescape(text)
    normalized = normalized.replace("\u00a0", " ")

    # Explicit labels first, including codes split by spaces or hyphens.
    labelled = re.search(
        r"(?:verification|verify|security|one[\s-]*time|login|otp|"
        r"confirmation|confirm|code|код|подтверждения)"
        r"[^0-9]{0,60}([0-9](?:[\s-]*[0-9]){3,7})",
        normalized,
        re.I,
    )
    if labelled:
        digits = re.sub(r"\D", "", labelled.group(1))
        if 4 <= len(digits) <= 8:
            return digits

    # Standard six-digit code.
    match = re.search(r"(?<!\d)(\d{6})(?!\d)", normalized)
    if match:
        return match.group(1)

    # Codes formatted as 123 456 or 123-456.
    match = re.search(r"(?<!\d)(\d{3}[\s-]\d{3})(?!\d)", normalized)
    if match:
        return re.sub(r"\D", "", match.group(1))

    return None


def wait_otp(sid: str, timeout: int = 180) -> str:
    deadline = time.time() + timeout
    seen: set[str] = set()
    diagnosed: set[str] = set()
    last_error_log = 0.0

    print(f"    Waiting up to {timeout}s for LetoVPN email...")

    while time.time() < deadline:
        inbox = gm("check_email", sid_token=sid, seq=0)
        messages = inbox.get("list") or []

        if not isinstance(messages, list):
            messages = []

        for message in messages:
            if not isinstance(message, dict):
                continue

            mail_id = str(message.get("mail_id") or "").strip()
            if not mail_id or mail_id == "0" or mail_id in seen:
                continue

            full = gm("fetch_email", sid_token=sid, email_id=mail_id)
            if not isinstance(full, dict):
                continue

            sender = str(
                full.get("mail_from")
                or message.get("mail_from")
                or ""
            )
            subject = str(
                full.get("mail_subject")
                or message.get("mail_subject")
                or ""
            )

            content, fields = _mail_text(full)
            searchable = f"{subject}\n{sender}\n{content}"

            # A fetch response containing only metadata is not final:
            # retry it on the next poll instead of marking the message seen.
            if not content.strip() and not subject.strip():
                continue

            if mail_id not in diagnosed:
                diagnosed.add(mail_id)
                print(f"    mail: {sender} | {subject}")
                print(f"      returned fields: {', '.join(fields) or '(none)'}")
                print(f"      content length: {len(content)}")

                # Safe preview: mask every digit so OTP is never printed.
                preview = re.sub(r"\d", "*", content)
                preview = re.sub(r"\s+", " ", preview).strip()
                print(f"      preview: {preview[:240] or '(empty)'}")

            is_leto = bool(
                re.search(r"leto|letovpn", sender + " " + subject + " " + content, re.I)
            )

            if not is_leto:
                seen.add(mail_id)
                continue

            otp = _extract_otp(searchable)
            if otp:
                print(f"      OTP extracted ({len(otp)} digits)")
                seen.add(mail_id)
                return otp

            # Keep checking the same message on later polls in case the
            # provider's first fetch was incomplete. Avoid repeating logs.
            if time.time() - last_error_log > 20:
                print(
                    "      LetoVPN message found, but no OTP pattern "
                    "was detected yet; retrying mailbox fetch..."
                )
                last_error_log = time.time()

        time.sleep(4)

    raise RuntimeError(
        "OTP timeout: LetoVPN email was not readable or contained no "
        "supported numeric OTP. Check the redacted mail preview above."
    )


def verify_otp(email: str, code: str) -> str:
    status, raw = http(
        "POST",
        f"{LETO}/api/v1/auth/otp/verify",
        {"email": email, "code": code},
        {
            "Content-Type": "application/json",
            "User-Agent": "okhttp/4.12.0",
        },
    )

    response_text = raw.decode("utf-8", "replace")
    if status != 200:
        raise RuntimeError(
            f"otp/verify HTTP {status}: {response_text[:500]}"
        )

    result = json.loads(response_text)
    token = result.get("token")
    if not token:
        raise RuntimeError(
            f"No token in verify response: {response_text[:500]}"
        )

    return token


def get_subscription(token: str) -> dict:
    status, raw = http(
        "GET",
        f"{LETO}/api/v1/subscription",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "okhttp/4.12.0",
        },
    )

    if status != 200:
        raise RuntimeError(
            f"subscription HTTP {status}: {raw[:500]!r}"
        )

    return json.loads(raw.decode("utf-8", "replace"))


def hwid_from_token(token: str) -> str:
    try:
        payload_part = token.split(".")[1]
        payload_part += "=" * (-len(payload_part) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(payload_part.encode())
        )
        return payload.get("sub") or str(uuid.uuid4())
    except Exception:
        return str(uuid.uuid4())


def fetch_configs(sub_url: str, hwid: str) -> list:
    status, raw = http(
        "GET",
        sub_url,
        headers={
            "User-Agent": "Happ/1",
            "x-hwid": hwid,
            "x-device-os": "Android",
            "x-ver-os": "13",
            "x-device-model": "Pixel 7",
            "x-appName": "letoAndroid/1.2.4",
        },
        timeout=60,
    )

    if status != 200:
        raise RuntimeError(f"sub fetch HTTP {status}: {raw[:300]!r}")

    text = raw.decode("utf-8", "replace")
    if text.strip().startswith("dmxlc3M") or "App not supported" in text:
        raise RuntimeError(
            "Remnawave blocked client — check subscription headers"
        )

    data = json.loads(text)
    if not isinstance(data, list):
        raise RuntimeError(
            f"Unexpected config type: {type(data).__name__}"
        )

    return data


def outbound_to_uri(ob: dict, remark: str) -> str | None:
    proto = ob.get("protocol")

    if proto == "vless":
        settings = ob.get("settings") or {}
        vnext = (settings.get("vnext") or [{}])[0]
        users = (vnext.get("users") or [{}])[0]
        stream = ob.get("streamSettings") or {}

        security = stream.get("security") or "none"
        network = stream.get("network") or "tcp"

        query: dict[str, str] = {
            "encryption": users.get("encryption", "none"),
            "type": network,
            "security": security,
        }

        if users.get("flow"):
            query["flow"] = users["flow"]

        if security == "reality":
            reality = stream.get("realitySettings") or {}
            query["pbk"] = reality.get("publicKey") or ""

            server_name = reality.get("serverName") or ""
            if (
                not server_name
                and isinstance(reality.get("serverNames"), list)
                and reality["serverNames"]
            ):
                server_name = reality["serverNames"][0]

            if server_name:
                query["sni"] = server_name

            query["fp"] = reality.get("fingerprint") or "chrome"

            short_id = reality.get("shortId") or ""
            if isinstance(short_id, list):
                short_id = short_id[0] if short_id else ""
            if short_id:
                query["sid"] = short_id

        elif security == "tls":
            tls = stream.get("tlsSettings") or {}
            if tls.get("serverName"):
                query["sni"] = tls["serverName"]
            query["fp"] = tls.get("fingerprint") or "chrome"

        if network == "ws":
            ws = stream.get("wsSettings") or {}
            query["path"] = ws.get("path") or "/"
            headers = ws.get("headers") or {}
            host = headers.get("Host") or headers.get("host")
            if host:
                query["host"] = host

        if network in ("xhttp", "httpupgrade"):
            transport = (
                stream.get("xhttpSettings")
                or stream.get("httpupgradeSettings")
                or {}
            )
            if transport.get("path"):
                query["path"] = transport["path"]
            if transport.get("host"):
                query["host"] = transport["host"]
            if transport.get("mode"):
                query["mode"] = transport["mode"]

        address = vnext.get("address")
        port = vnext.get("port")
        user_id = users.get("id")

        if address and port and user_id:
            uri_host = (
                f"[{address}]" if ":" in str(address) else str(address)
            )
            return (
                f"vless://{user_id}@{uri_host}:{port}"
                f"?{urllib.parse.urlencode(query)}"
                f"#{urllib.parse.quote(remark)}"
            )

    elif proto == "trojan":
        settings = ob.get("settings") or {}
        servers = (settings.get("servers") or [{}])[0]
        stream = ob.get("streamSettings") or {}

        security = stream.get("security") or "tls"
        network = stream.get("network") or "tcp"
        query = {"security": security, "type": network}

        tls_settings = (
            stream.get("tlsSettings")
            or stream.get("realitySettings")
            or {}
        )
        if tls_settings.get("serverName"):
            query["sni"] = tls_settings["serverName"]

        if security == "reality":
            reality = stream.get("realitySettings") or {}
            if reality.get("publicKey"):
                query["pbk"] = reality["publicKey"]
            query["fp"] = reality.get("fingerprint") or "chrome"

        address = servers.get("address")
        port = servers.get("port")
        password = servers.get("password")

        if address and port and password:
            uri_host = (
                f"[{address}]" if ":" in str(address) else str(address)
            )
            return (
                f"trojan://{password}@{uri_host}:{port}"
                f"?{urllib.parse.urlencode(query)}"
                f"#{urllib.parse.quote(remark)}"
            )

    return None


def configs_to_uris(configs: list) -> list[str]:
    uris = []

    for item in configs:
        remark = item.get("remarks") or "leto"

        for outbound in item.get("outbounds") or []:
            if outbound.get("protocol") in (
                "freedom", "blackhole", "dns", "block", "direct"
            ):
                continue

            uri = outbound_to_uri(outbound, remark)
            if uri:
                uris.append(uri)
                break

    return uris


def upload_gist(content: str) -> None:
    token = os.getenv("GIST_TOKEN", "").strip()
    gist_id = os.getenv("GIST_ID", "").strip()

    if not token or not gist_id:
        print("[Gist] GIST_TOKEN/GIST_ID not set — upload skipped")
        return

    filename = os.getenv("GIST_FILENAME", "leto.txt").strip() or "leto.txt"
    description = os.getenv(
        "GIST_DESCRIPTION", "LetoVPN subscription"
    )

    payload = {
        "description": description,
        "files": {filename: {"content": content}},
    }

    status, raw = http(
        "PATCH",
        f"{GITHUB_API}/gists/{gist_id}",
        payload,
        {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "leto-fetch-action",
        },
        timeout=30,
    )

    if status != 200:
        raise RuntimeError(
            "Gist upload failed "
            f"({status}): {raw.decode('utf-8', 'replace')[:500]}"
        )

    result = json.loads(raw.decode("utf-8", "replace"))
    print(f"[Gist] Updated: {result.get('html_url', 'success')}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LetoVPN full fetch via temporary email"
    )
    parser.add_argument("-o", "--out", default="leto_out")
    parser.add_argument("--otp-timeout", type=int, default=180)
    args = parser.parse_args()

    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)

    print("[1] temp email (Guerrilla Mail)...")
    email, sid = make_temp_email()
    print(f"    {email}")
    (output / "email.txt").write_text(email, encoding="utf-8")

    print("[2] otp/request...")
    request_otp(email)

    print("[3] wait OTP mail...")
    otp = wait_otp(sid, timeout=args.otp_timeout)

    print("[4] otp/verify...")
    token = verify_otp(email, otp)
    print(f"    token={token[:12]}...")

    print("[5] subscription...")
    subscription = get_subscription(token)

    (output / "subscription.json").write_text(
        json.dumps(subscription, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(
        f"    status={subscription.get('subscriptionStatus')} "
        f"trial={subscription.get('isTrial')}"
    )

    sub_url = subscription.get("subscriptionUrl")
    if not sub_url:
        raise RuntimeError("No subscriptionUrl in subscription response")

    hwid = hwid_from_token(token)
    print(f"[6] fetch configs hwid={hwid}...")
    configs = fetch_configs(sub_url, hwid)

    print("[7] resolve endpoint hostnames to IP...")
    normalize_endpoint_hosts(configs)

    (output / "configs.json").write_text(
        json.dumps(configs, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"    nodes={len(configs)}")
    for config in configs:
        print(f"      - {config.get('remarks')}")

    uris = configs_to_uris(configs)
    if not uris:
        raise RuntimeError("No VLESS/Trojan URI generated")

    uri_text = "\n".join(uris) + "\n"
    (output / "uris.txt").write_text(uri_text, encoding="utf-8")

    print(f"\n[+] {len(uris)} URI -> {output / 'uris.txt'}")
    for uri in uris[:5]:
        print(" ", uri[:120])
    if len(uris) > 5:
        print(f"  ... +{len(uris) - 5} more")

    print("[8] upload to GitHub Gist...")
    upload_gist(uri_text)


if __name__ == "__main__":
    main()
