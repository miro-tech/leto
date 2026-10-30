#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
leto_fetch.py — LetoVPN full fetch + DNS endpoint resolution + GitHub Gist upload.

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
from pathlib import Path
from typing import Any

GM = "https://api.guerrillamail.com/ajax.php"
LETO = "https://m-app.letovpn.com"
GITHUB_API = "https://api.github.com"
CTX = ssl.create_default_context()
_DNS_CACHE: dict[str, str] = {}


def http(
    method: str,
    url: str,
    body: Any = None,
    headers: dict | None = None,
    timeout: float = 30,
) -> tuple[int | None, bytes]:
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*"}
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
    """Resolve only the remote server address; never touch SNI, WS Host, path, etc."""
    host = str(host or "").strip()
    if not host:
        return host
    # Already an IPv4/IPv6 literal.
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

    # Prefer IPv4 by default for broad client compatibility; allow IPv6 fallback.
    ipv4_first = os.getenv("DNS_IPV4_FIRST", "1").lower() not in ("0", "false", "no")
    addresses.sort(key=lambda x: (ipaddress.ip_address(x).version != (4 if ipv4_first else 6)))
    result = addresses[0]
    _DNS_CACHE[host] = result
    print(f"      DNS: {host} -> {result}")
    return result


def normalize_endpoint_hosts(configs: list) -> None:
    """Change only Xray endpoint address fields. WS Host/SNI and all other fields remain intact."""
    for item in configs:
        for ob in item.get("outbounds") or []:
            proto = ob.get("protocol")
            settings = ob.get("settings") or {}
            targets = []
            if proto == "vless":
                for server in (settings.get("vnext") or []):
                    if server.get("address"):
                        targets.append(server)
            elif proto == "trojan":
                for server in (settings.get("servers") or []):
                    if server.get("address"):
                        targets.append(server)
            for server in targets:
                original = server["address"]
                try:
                    server["address"] = resolve_host(original)
                except Exception as exc:
                    # Keep the node instead of aborting the entire subscription.
                    print(f"      DNS WARNING: {original}: {exc}")


def gm(f: str, **params) -> dict:
    q = urllib.parse.urlencode({"f": f, **params})
    code, raw = http("GET", f"{GM}?{q}", timeout=20)
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"_http": code, "_raw": raw.decode("utf-8", "replace")[:500]}


def make_temp_email() -> tuple[str, str]:
    j = gm("get_email_address", lang="en")
    email = j.get("email_addr")
    sid = j.get("sid_token")
    if not email or not sid:
        raise RuntimeError(f"GuerrillaMail failed: {j}")
    return email, sid


def request_otp(email: str) -> None:
    code, raw = http(
        "POST",
        f"{LETO}/api/v1/auth/otp/request",
        {"email": email},
        {"Content-Type": "application/json", "User-Agent": "okhttp/4.12.0"},
    )
    if code not in (200, 429):
        raise RuntimeError(f"otp/request {code}: {raw[:300]!r}")


def wait_otp(sid: str, timeout: int = 90) -> str:
    deadline = time.time() + timeout
    seen = set()
    while time.time() < deadline:
        j = gm("check_email", sid_token=sid, seq=0)
        for m in j.get("list") or []:
            mid = str(m.get("mail_id") or "")
            if not mid or mid == "0" or mid in seen:
                continue
            seen.add(mid)
            full = gm("fetch_email", sid_token=sid, email_id=mid)
            body = (full.get("mail_body") or "") + " " + (full.get("mail_subject") or "")
            subj = full.get("mail_subject") or ""
            print(f"  mail: {full.get('mail_from')} | {subj}")
            if not re.search(r"leto|vpn|код|code|confirm", body + subj, re.I):
                if "letovpn" not in (full.get("mail_from") or "").lower():
                    continue
            mcode = re.search(r"\b(\d{6})\b", body)
            if mcode:
                return mcode.group(1)
        time.sleep(4)
    raise RuntimeError("OTP timeout — письмо не пришло")


def verify_otp(email: str, code: str) -> str:
    status, raw = http(
        "POST",
        f"{LETO}/api/v1/auth/otp/verify",
        {"email": email, "code": code},
        {"Content-Type": "application/json", "User-Agent": "okhttp/4.12.0"},
    )
    text = raw.decode("utf-8", "replace")
    if status != 200:
        raise RuntimeError(f"otp/verify {status}: {text[:300]}")
    j = json.loads(text)
    token = j.get("token")
    if not token:
        raise RuntimeError(f"no token in response: {text[:300]}")
    return token


def get_subscription(token: str) -> dict:
    status, raw = http(
        "GET",
        f"{LETO}/api/v1/subscription",
        headers={"Authorization": f"Bearer {token}", "User-Agent": "okhttp/4.12.0"},
    )
    if status != 200:
        raise RuntimeError(f"subscription {status}: {raw[:300]!r}")
    return json.loads(raw.decode())


def hwid_from_token(token: str) -> str:
    try:
        payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
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
        raise RuntimeError(f"sub fetch {status}: {raw[:200]!r}")
    text = raw.decode("utf-8", "replace")
    if text.strip().startswith("dmxlc3M") or "App not supported" in text:
        raise RuntimeError("Remnawave blocked client — check headers")
    data = json.loads(text)
    if not isinstance(data, list):
        raise RuntimeError(f"unexpected config type: {type(data)}")
    return data


def outbound_to_uri(ob: dict, remark: str) -> str | None:
    proto = ob.get("protocol")
    if proto == "vless":
        settings = ob.get("settings") or {}
        vnext = (settings.get("vnext") or [{}])[0]
        users = (vnext.get("users") or [{}])[0]
        ss = ob.get("streamSettings") or {}
        security = ss.get("security") or "none"
        network = ss.get("network") or "tcp"
        q: dict[str, str] = {
            "encryption": users.get("encryption", "none"),
            "type": network,
            "security": security,
        }
        if users.get("flow"):
            q["flow"] = users["flow"]
        if security == "reality":
            rs = ss.get("realitySettings") or {}
            q["pbk"] = rs.get("publicKey") or ""
            sn = rs.get("serverName") or ""
            if not sn and isinstance(rs.get("serverNames"), list) and rs["serverNames"]:
                sn = rs["serverNames"][0]
            q["sni"] = sn
            q["fp"] = rs.get("fingerprint") or "chrome"
            sid = rs.get("shortId") or ""
            if isinstance(sid, list):
                sid = sid[0] if sid else ""
            if sid:
                q["sid"] = sid
        elif security == "tls":
            ts = ss.get("tlsSettings") or {}
            if ts.get("serverName"):
                q["sni"] = ts["serverName"]
            q["fp"] = ts.get("fingerprint") or "chrome"
        if network == "ws":
            ws = ss.get("wsSettings") or {}
            q["path"] = ws.get("path") or "/"
            host = (ws.get("headers") or {}).get("Host") or (ws.get("headers") or {}).get("host")
            if host:
                q["host"] = host
        if network in ("xhttp", "httpupgrade"):
            xs = ss.get("xhttpSettings") or ss.get("httpupgradeSettings") or {}
            if xs.get("path"):
                q["path"] = xs["path"]
            if xs.get("host"):
                q["host"] = xs["host"]
            if xs.get("mode"):
                q["mode"] = xs["mode"]
        addr, port, uid = vnext.get("address"), vnext.get("port"), users.get("id")
        if addr and port and uid:
            # IPv6 literals must be bracketed in URI authority.
            uri_host = f"[{addr}]" if ":" in str(addr) else str(addr)
            return f"vless://{uid}@{uri_host}:{port}?{urllib.parse.urlencode(q)}#{urllib.parse.quote(remark)}"

    if proto == "trojan":
        servers = ((ob.get("settings") or {}).get("servers") or [{}])[0]
        ss = ob.get("streamSettings") or {}
        q = {"security": ss.get("security") or "tls", "type": ss.get("network") or "tcp"}
        ts = ss.get("tlsSettings") or ss.get("realitySettings") or {}
        if ts.get("serverName"):
            q["sni"] = ts["serverName"]
        if ss.get("security") == "reality":
            rs = ss.get("realitySettings") or {}
            q["pbk"] = rs.get("publicKey") or ""
            q["fp"] = rs.get("fingerprint") or "chrome"
        addr = servers.get("address")
        uri_host = f"[{addr}]" if addr and ":" in str(addr) else str(addr or "")
        return (
            f"trojan://{servers.get('password')}@{uri_host}:{servers.get('port')}"
            f"?{urllib.parse.urlencode(q)}#{urllib.parse.quote(remark)}"
        )
    if proto in ("hysteria2", "hysteria"):
        return None
    return None


def configs_to_uris(configs: list) -> list[str]:
    uris = []
    for item in configs:
        remark = item.get("remarks") or "leto"
        for ob in item.get("outbounds") or []:
            if ob.get("protocol") in ("freedom", "blackhole", "dns", "block", "direct"):
                continue
            uri = outbound_to_uri(ob, remark)
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
    if status not in (200,):
        raise RuntimeError(f"Gist upload failed ({status}): {raw.decode('utf-8', 'replace')[:500]}")
    result = json.loads(raw.decode("utf-8", "replace"))
    print(f"[Gist] Updated: {result.get('html_url', 'success')}")


def main() -> None:
    ap = argparse.ArgumentParser(description="LetoVPN full fetch via temp email")
    ap.add_argument("-o", "--out", default="leto_out")
    ap.add_argument("--otp-timeout", type=int, default=120)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print("[1] temp email (Guerrilla Mail)...")
    email, sid = make_temp_email()
    print(f"    {email}")
    (out / "email.txt").write_text(email, encoding="utf-8")

    print("[2] otp/request...")
    request_otp(email)

    print("[3] wait OTP mail...")
    otp = wait_otp(sid, timeout=args.otp_timeout)
    print(f"    code={otp}")

    print("[4] otp/verify...")
    token = verify_otp(email, otp)
    # Не сохраняем JWT в артефакты/репозиторий.
    print(f"    token={token[:16]}...")

    print("[5] subscription...")
    sub = get_subscription(token)
    (out / "subscription.json").write_text(
        json.dumps(sub, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        f"    status={sub.get('subscriptionStatus')} trial={sub.get('isTrial')} "
        f"url={sub.get('subscriptionUrl')}"
    )
    sub_url = sub.get("subscriptionUrl")
    if not sub_url:
        raise RuntimeError("no subscriptionUrl")

    hwid = hwid_from_token(token)
    print(f"[6] fetch configs hwid={hwid}...")
    configs = fetch_configs(sub_url, hwid)

    print("[7] resolve endpoint hostnames to IP...")
    normalize_endpoint_hosts(configs)

    (out / "configs.json").write_text(
        json.dumps(configs, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"    nodes={len(configs)}")
    for c in configs:
        print(f"      - {c.get('remarks')}")

    uris = configs_to_uris(configs)
    if not uris:
        raise RuntimeError("No VLESS/Trojan URI generated")
    uri_text = "\n".join(uris) + "\n"
    (out / "uris.txt").write_text(uri_text, encoding="utf-8")
    print(f"\n[+] {len(uris)} URI → {out / 'uris.txt'}")
    for u in uris[:5]:
        print(" ", u[:120])
    if len(uris) > 5:
        print(f"  ... +{len(uris) - 5} more")

    print("[8] upload to GitHub Gist...")
    upload_gist(uri_text)


if __name__ == "__main__":
    main()
