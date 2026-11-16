#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
leto_fetch.py — LetoVPN fetch + DNS endpoint resolution + GitHub Gist upload.

Temp mail: mail.tm (primary), tempmail.lol (fallback).
Guerrilla Mail is NOT used — domains are blocked by most OTP senders.

GitHub Actions env:
  GIST_TOKEN, GIST_ID
Optional:
  GIST_FILENAME (default: leto.txt)
  GIST_DESCRIPTION (default: LetoVPN subscription)
  DNS_IPV4_FIRST (default: 1)
  TEMP_MAIL_PROVIDER (mailtm | tempmail | auto) default: auto
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import string
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

LETO = "https://m-app.letovpn.com"
GITHUB_API = "https://api.github.com"
MAILTM = "https://api.mail.tm"
TEMPMAIL_LOL = "https://api.tempmail.lol"
CTX = ssl.create_default_context()
_DNS_CACHE: dict[str, str] = {}


class HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
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
        try:
            return e.code, e.read()
        except Exception:
            return e.code, str(e).encode()
    except Exception as e:
        return None, str(e).encode()


def resolve_host(host: str) -> str:
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
    ipv4_first = os.getenv("DNS_IPV4_FIRST", "1").lower() not in ("0", "false", "no")
    preferred = 4 if ipv4_first else 6
    addresses.sort(key=lambda x: ipaddress.ip_address(x).version != preferred)
    result = addresses[0]
    _DNS_CACHE[host] = result
    print(f"      DNS: {host} -> {result}")
    return result


def normalize_endpoint_hosts(configs: list) -> None:
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


# ---------------------------------------------------------------------------
# Temp mail providers
# ---------------------------------------------------------------------------

class TempMail:
    """Minimal interface: .email, .list_messages() -> list[dict], .read(id) -> dict"""

    email: str

    def list_messages(self) -> list[dict]:
        raise NotImplementedError

    def read(self, msg_id: str) -> dict:
        raise NotImplementedError


class MailTm(TempMail):
    def __init__(self) -> None:
        st, raw = http("GET", f"{MAILTM}/domains")
        if st != 200:
            raise RuntimeError(f"mail.tm domains HTTP {st}: {raw[:200]!r}")
        domains = json.loads(raw.decode()).get("hydra:member") or []
        if not domains:
            raise RuntimeError("mail.tm: no domains")
        domain = domains[0]["domain"]
        user = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
        password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(18))
        self.email = f"{user}@{domain}"
        self.password = password
        st, raw = http("POST", f"{MAILTM}/accounts", {"address": self.email, "password": password})
        if st not in (200, 201):
            raise RuntimeError(f"mail.tm create HTTP {st}: {raw[:300]!r}")
        st, raw = http("POST", f"{MAILTM}/token", {"address": self.email, "password": password})
        if st != 200:
            raise RuntimeError(f"mail.tm token HTTP {st}: {raw[:300]!r}")
        self.token = json.loads(raw.decode())["token"]

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def list_messages(self) -> list[dict]:
        st, raw = http("GET", f"{MAILTM}/messages", headers=self._auth())
        if st != 200:
            return []
        data = json.loads(raw.decode())
        out = []
        for m in data.get("hydra:member") or []:
            out.append(
                {
                    "id": str(m.get("id") or ""),
                    "from": _addr_of(m.get("from")),
                    "subject": str(m.get("subject") or ""),
                    "intro": str(m.get("intro") or ""),
                }
            )
        return out

    def read(self, msg_id: str) -> dict:
        st, raw = http("GET", f"{MAILTM}/messages/{msg_id}", headers=self._auth())
        if st != 200:
            return {}
        m = json.loads(raw.decode())
        html = m.get("html") or ""
        if isinstance(html, list):
            html = "\n".join(html)
        text = m.get("text") or ""
        return {
            "id": str(m.get("id") or msg_id),
            "from": _addr_of(m.get("from")),
            "subject": str(m.get("subject") or ""),
            "text": str(text),
            "html": str(html),
        }


class TempMailLol(TempMail):
    def __init__(self) -> None:
        st, raw = http("POST", f"{TEMPMAIL_LOL}/v2/inbox/create")
        if st not in (200, 201):
            raise RuntimeError(f"tempmail.lol create HTTP {st}: {raw[:300]!r}")
        data = json.loads(raw.decode())
        self.email = data["address"]
        self.token = data["token"]

    def list_messages(self) -> list[dict]:
        st, raw = http("GET", f"{TEMPMAIL_LOL}/v2/inbox?token={urllib.parse.quote(self.token)}")
        if st != 200:
            return []
        data = json.loads(raw.decode())
        emails = data.get("emails") or data.get("messages") or []
        if not isinstance(emails, list):
            return []
        out = []
        for i, m in enumerate(emails):
            mid = str(m.get("id") or m.get("_id") or i)
            out.append(
                {
                    "id": mid,
                    "from": str(m.get("from") or m.get("sender") or ""),
                    "subject": str(m.get("subject") or ""),
                    "intro": str(m.get("body") or m.get("html") or m.get("text") or "")[:200],
                    "_raw": m,
                }
            )
        return out

    def read(self, msg_id: str) -> dict:
        # tempmail.lol returns full body in list; re-fetch inbox and pick
        for m in self.list_messages():
            if m["id"] == msg_id:
                raw = m.get("_raw") or {}
                body = str(raw.get("body") or raw.get("html") or raw.get("text") or m.get("intro") or "")
                return {
                    "id": msg_id,
                    "from": m["from"],
                    "subject": m["subject"],
                    "text": body,
                    "html": body,
                }
        return {}


def _addr_of(from_field: Any) -> str:
    if isinstance(from_field, dict):
        return str(from_field.get("address") or from_field.get("name") or "")
    return str(from_field or "")


def make_temp_mail(provider: str = "auto") -> TempMail:
    provider = (provider or "auto").lower().strip()
    errors: list[str] = []
    order = ["mailtm", "tempmail"] if provider == "auto" else [provider]
    for name in order:
        try:
            if name in ("mailtm", "mail.tm", "mail_tm"):
                box = MailTm()
                print(f"    provider=mail.tm  email={box.email}")
                return box
            if name in ("tempmail", "tempmail.lol", "lol"):
                box = TempMailLol()
                print(f"    provider=tempmail.lol  email={box.email}")
                return box
            raise RuntimeError(f"unknown provider: {name}")
        except Exception as e:
            errors.append(f"{name}: {e}")
            print(f"    ! {name} failed: {e}")
    raise RuntimeError("All temp-mail providers failed: " + "; ".join(errors))


# ---------------------------------------------------------------------------
# LetoVPN auth
# ---------------------------------------------------------------------------

def request_otp(email: str) -> None:
    status, raw = http(
        "POST",
        f"{LETO}/api/v1/auth/otp/request",
        {"email": email},
        {"Content-Type": "application/json", "User-Agent": "okhttp/4.12.0"},
        timeout=45,
    )
    if status is None:
        raise RuntimeError(f"otp/request network error: {raw.decode('utf-8', 'replace')[:300]}")
    if status not in (200, 201, 202, 204, 429):
        raise RuntimeError(f"otp/request HTTP {status}: {raw.decode('utf-8', 'replace')[:500]}")
    if status == 429:
        print("    OTP request returned HTTP 429; checking mailbox anyway")
    else:
        print(f"    OTP requested (HTTP {status})")


def _html_to_text(body: str) -> str:
    body = unescape(body or "")
    body = body.replace("\u00a0", " ").replace("\u200b", "").replace("\ufeff", "")
    body = re.sub(r"(?i)<br\s*/?>", "\n", body)
    body = re.sub(r"(?i)</p>", "\n", body)
    parser = HTMLTextExtractor()
    try:
        parser.feed(body)
        extracted = " ".join(parser.parts)
        if extracted.strip():
            body = extracted
    except Exception:
        body = re.sub(r"<[^>]+>", " ", body)
    body = unescape(body)
    body = re.sub(r"\s+", " ", body).strip()
    return body


def _message_body(msg: dict) -> str:
    for key in ("text", "html", "body", "mail_body", "intro"):
        val = msg.get(key)
        if isinstance(val, str) and val.strip():
            return _html_to_text(val)
        if isinstance(val, list):
            joined = "\n".join(str(x) for x in val if x)
            if joined.strip():
                return _html_to_text(joined)
    return ""


def _extract_otp(body: str) -> str | None:
    if not body:
        return None
    text = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", " ", body, flags=re.I)
    text = re.sub(r"https?://\S+", " ", text, flags=re.I)

    labelled = (
        r"(?:verification\s*code|verify\s*code|security\s*code|"
        r"one[\s-]*time\s*code|login\s*code|otp|"
        r"код\s*(?:подтверждения|доступа)?|"
        r"код\s*верификации|подтверждения)"
        r"[^0-9]{0,80}(\d{6})(?!\d)",
        r"(?:code|код)[^0-9]{0,30}(\d{6})(?!\d)",
    )
    for pattern in labelled:
        m = re.search(pattern, text, re.I)
        if m:
            return m.group(1)

    matches = re.findall(r"(?<!\d)(\d{6})(?!\d)", text)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        # Prefer codes that are not all same digit
        filtered = [c for c in matches if len(set(c)) > 1]
        if len(filtered) == 1:
            return filtered[0]
        print(f"      Multiple six-digit values: {matches[:5]} — taking first non-trivial")
        if filtered:
            return filtered[0]
        return matches[0]
    return None


def wait_otp(box: TempMail, timeout: int = 180) -> str:
    deadline = time.time() + timeout
    seen: set[str] = set()
    print(f"    Waiting up to {timeout}s for LetoVPN email at {box.email}...")

    while time.time() < deadline:
        try:
            messages = box.list_messages()
        except Exception as e:
            print(f"      inbox error: {e}")
            time.sleep(4)
            continue

        for meta in messages:
            mid = str(meta.get("id") or "")
            if not mid or mid in seen:
                continue

            try:
                full = box.read(mid)
            except Exception as e:
                print(f"      read error {mid}: {e}")
                continue

            sender = str(full.get("from") or meta.get("from") or "")
            subject = str(full.get("subject") or meta.get("subject") or "")
            body = _message_body(full) or _html_to_text(str(meta.get("intro") or ""))

            is_leto = bool(re.search(r"leto|letovpn|no-?reply", sender + " " + subject, re.I))
            # Also accept any message with a clear 6-digit code if only one mail
            print(f"    mail: {sender} | {subject}")
            print(f"      body length: {len(body)}")
            safe = re.sub(r"\d", "*", body)
            print(f"      body preview: {safe[:300]}")

            otp = _extract_otp(body)
            if otp:
                print(f"      OTP extracted: {otp[0]}****")
                seen.add(mid)
                return otp

            if is_leto:
                print("      Leto-related mail but no OTP yet; will retry body")
                # don't mark seen — body may complete later
            else:
                seen.add(mid)

        time.sleep(4)

    raise RuntimeError(
        f"OTP timeout after {timeout}s for {box.email}. "
        "Leto may block this mail domain — try TEMP_MAIL_PROVIDER=tempmail"
    )


def verify_otp(email: str, code: str) -> str:
    status, raw = http(
        "POST",
        f"{LETO}/api/v1/auth/otp/verify",
        {"email": email, "code": code},
        {"Content-Type": "application/json", "User-Agent": "okhttp/4.12.0"},
        timeout=45,
    )
    text = raw.decode("utf-8", "replace")
    if status != 200:
        raise RuntimeError(f"otp/verify HTTP {status}: {text[:500]}")
    result = json.loads(text)
    token = result.get("token")
    if not token:
        raise RuntimeError(f"No token in verify response: {text[:500]}")
    return token


def get_subscription(token: str) -> dict:
    status, raw = http(
        "GET",
        f"{LETO}/api/v1/subscription",
        headers={"Authorization": f"Bearer {token}", "User-Agent": "okhttp/4.12.0"},
        timeout=45,
    )
    if status != 200:
        raise RuntimeError(f"subscription HTTP {status}: {raw[:500]!r}")
    return json.loads(raw.decode("utf-8", "replace"))


def hwid_from_token(token: str) -> str:
    try:
        payload_part = token.split(".")[1]
        payload_part += "=" * (-len(payload_part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_part.encode()))
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
        raise RuntimeError("Remnawave blocked client — check subscription headers")
    data = json.loads(text)
    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected config type: {type(data).__name__}")
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
            if not server_name and isinstance(reality.get("serverNames"), list) and reality["serverNames"]:
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
            transport = stream.get("xhttpSettings") or stream.get("httpupgradeSettings") or {}
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
            uri_host = f"[{address}]" if ":" in str(address) else str(address)
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
        tls_settings = stream.get("tlsSettings") or stream.get("realitySettings") or {}
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
            uri_host = f"[{address}]" if ":" in str(address) else str(address)
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
            if outbound.get("protocol") in ("freedom", "blackhole", "dns", "block", "direct"):
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
    description = os.getenv("GIST_DESCRIPTION", "LetoVPN subscription")
    payload = {"description": description, "files": {filename: {"content": content}}}
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
        raise RuntimeError(f"Gist upload failed ({status}): {raw.decode('utf-8', 'replace')[:500]}")
    result = json.loads(raw.decode("utf-8", "replace"))
    print(f"[Gist] Updated: {result.get('html_url', 'success')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="LetoVPN full fetch via temporary email")
    parser.add_argument("-o", "--out", default="leto_out")
    parser.add_argument("--otp-timeout", type=int, default=180)
    parser.add_argument(
        "--provider",
        default=os.getenv("TEMP_MAIL_PROVIDER", "auto"),
        help="mailtm | tempmail | auto",
    )
    args = parser.parse_args()

    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)

    print("[1] temp email...")
    box = make_temp_mail(args.provider)
    (output / "email.txt").write_text(box.email + "\n", encoding="utf-8")

    print("[2] otp/request...")
    request_otp(box.email)

    print("[3] wait OTP mail...")
    otp = wait_otp(box, timeout=args.otp_timeout)
    (output / "otp.txt").write_text(otp + "\n", encoding="utf-8")

    print("[4] otp/verify...")
    token = verify_otp(box.email, otp)
    print(f"    token={token[:12]}...")
    (output / "token.txt").write_text(token + "\n", encoding="utf-8")

    print("[5] subscription...")
    subscription = get_subscription(token)
    (output / "subscription.json").write_text(
        json.dumps(subscription, ensure_ascii=False, indent=2), encoding="utf-8"
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
        json.dumps(configs, ensure_ascii=False, indent=2), encoding="utf-8"
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
