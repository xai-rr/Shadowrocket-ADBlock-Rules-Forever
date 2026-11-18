#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static checks for the BWG overlay. No device and no network."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apply_bwg_overlay import apply_text  # noqa: E402


FIXTURE = """\
# fixture
[General]
ipv6 = false
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, localhost, *.local
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
[Rule]
#
# 白名单中包含了境外网站中可以访问的那些，对不确定的网站则尽可能地代理。
#

# 跳板机直连
IP-CIDR,13.215.120.134/32,DIRECT,no-resolve
DOMAIN-SUFFIX, openai.com, 稳定线路
DOMAIN-SUFFIX, googleapis.com, 稳定线路

# adblock rules refresh time: 2020-01-01 00:00:00
DOMAIN-KEYWORD,google,PROXY
DOMAIN-SUFFIX,google-analytics.com,Reject
DOMAIN-SUFFIX,googleadservices.com,Reject
DOMAIN-SUFFIX,googlesyndication.com,Reject
DOMAIN-SUFFIX,googletagmanager.com,Reject
DOMAIN-SUFFIX,doubleclick.net,Reject
DOMAIN-SUFFIX,app-measurement.com,Reject
DOMAIN-SUFFIX,ads.google.com,Reject
DOMAIN-SUFFIX,pagead.google.com,Reject
DOMAIN-SUFFIX,imasdk.googleapis.com,Reject
DOMAIN-SUFFIX,googleadservices-cn.com,Reject

# 手工定义的 Direct 列表
DOMAIN-SUFFIX,tools.google.com,Direct
DOMAIN-SUFFIX,baidu.com,Direct
DOMAIN-SUFFIX,qq.com,Direct
DOMAIN-SUFFIX,github.com,Direct
DOMAIN-SUFFIX,bilibili.com,Direct
DOMAIN-SUFFIX,icloud-content.com,Direct

# 手工定义的 Proxy 列表
# 85（可能冗余）
DOMAIN-SUFFIX,www-google-analytics.l.google.com,Proxy
DOMAIN-SUFFIX,pagead.google.com,Proxy
DOMAIN-SUFFIX,ads.google.com,Proxy
DOMAIN-SUFFIX,google-analytics.com,Proxy
DOMAIN-SUFFIX,doubleclick.net,Proxy

DOMAIN-SUFFIX,usnews.com,Direct

DOMAIN-SUFFIX,cn,DIRECT
GEOIP,CN,DIRECT
IP-CIDR,192.168.0.0/16,DIRECT
FINAL,PROXY

[URL Rewrite]
^https?://(www.)?(g|google)\\.cn https://www.google.com 302

[MITM]
hostname = *.google.cn,*.googlevideo.com
"""


def split_rule(line: str) -> list[str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("["):
        return None
    parts = [part.strip() for part in stripped.split(",")]
    if parts and parts[0].upper() == "FINAL" and len(parts) == 2:
        return [parts[0], "", parts[1]]
    if len(parts) < 3:
        return None
    if parts[0].upper() not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "GEOIP", "FINAL"}:
        return None
    return parts


def first_policy(text: str, host: str | None = None, ip: str | None = None) -> str:
    for line in text.splitlines():
        parts = split_rule(line)
        if parts is None:
            continue
        kind = parts[0].upper()
        value = parts[1]
        policy = parts[2]
        if host is not None and kind == "DOMAIN" and host.lower() == value.lower():
            return policy
        if host is not None and kind == "DOMAIN-SUFFIX":
            domain = host.lower()
            suffix = value.lower()
            if domain == suffix or domain.endswith("." + suffix):
                return policy
        if host is not None and kind == "DOMAIN-KEYWORD" and value.lower() in host.lower():
            return policy
        if ip is not None and kind == "IP-CIDR":
            if ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False):
                return policy
        if kind == "FINAL":
            return policy
    raise AssertionError("no match")


def section_body(text: str, name: str) -> str:
    lines = text.splitlines()
    start = lines.index(name)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("[") and lines[index].endswith("]"):
            end = index
            break
    return "\n".join(lines[start:end])


def check_expectations(text: str, label: str) -> None:
    samples = {
        "www.google-analytics.com": "REJECT",
        "google-analytics.com": "REJECT",
        "googleadservices.com": "REJECT",
        "ads.googleadservices.com": "REJECT",
        "doubleclick.net": "REJECT",
        "ad.doubleclick.net": "REJECT",
        "googlesyndication.com": "REJECT",
        "googletagmanager.com": "REJECT",
        "app-measurement.com": "REJECT",
        "pagead.google.com": "REJECT",
        "ads.google.com": "REJECT",
        "imasdk.googleapis.com": "REJECT",
        "googleadservices-cn.com": "REJECT",
        "mask.icloud.com": "REJECT",
        "mask-h2.icloud.com": "REJECT",
        "www.google.com": "PROXY",
        "tools.google.com": "PROXY",
        "youtube.com": "PROXY",
        "youtu.be": "PROXY",
        "openai.com": "PROXY",
        "turnstile.hcaptcha.com": "PROXY",
        "chatgpt.com": "PROXY",
        "claude.ai": "PROXY",
        "anthropic.com": "PROXY",
        "x.ai": "PROXY",
        "grok.com": "PROXY",
        "github.com": "PROXY",
        "raw.githubusercontent.com": "PROXY",
        "qq.com": "DIRECT",
        "weixin.qq.com": "DIRECT",
        "baidu.com": "DIRECT",
        "bilibili.com": "DIRECT",
        "douyin.com": "DIRECT",
        "lovart.ai": "DIRECT",
        "unknown.example": "PROXY",
        "usnews.com": "DIRECT",
    }
    for host, expected in samples.items():
        actual = first_policy(text, host=host).upper()
        if actual != expected:
            raise SystemExit(f"{label}: {host} -> {actual}, expected {expected}")
    ip_samples = {
        "13.215.120.134": "DIRECT",
        "192.168.1.9": "DIRECT",
        "10.1.2.3": "DIRECT",
        "100.64.1.1": "DIRECT",
        "8.8.8.8": "PROXY",
    }
    for ip, expected in ip_samples.items():
        actual = first_policy(text, ip=ip).upper()
        if actual != expected:
            raise SystemExit(f"{label}: {ip} -> {actual}, expected {expected}")

    headers = [line for line in text.splitlines() if line.startswith("[") and line.endswith("]")]
    for name in ("[General]", "[Proxy Group]", "[Rule]", "[Host]", "[URL Rewrite]", "[MITM]"):
        if headers.count(name) != 1:
            raise SystemExit(f"{label}: {name} count {headers.count(name)}")
    if "[Proxy]" in headers:
        raise SystemExit(label + ": node section added")
    if "稳定线路" in text:
        raise SystemExit(label + ": 稳定线路 remains")
    if "block-quic = all-proxy" not in text:
        raise SystemExit(label + ": missing block-quic")
    if text.count("udp-policy-not-supported-behaviour = REJECT") != 1:
        raise SystemExit(label + ": udp policy not unique")
    if text.count("\nFINAL,PROXY\n") != 1:
        raise SystemExit(label + ": FINAL count")
    if "FINAL,DIRECT" in text:
        raise SystemExit(label + ": FINAL,DIRECT")
    if "ipv6 = true" in text:
        raise SystemExit(label + ": ipv6 enabled")
    if "fallback-dns-server" in text:
        raise SystemExit(label + ": system fallback dns added")
    if "tun-excluded-routes" in text:
        raise SystemExit(label + ": duplicate tun exclusion key")
    for line in text.splitlines():
        parts = split_rule(line)
        if parts and parts[2].strip().upper() == "AUTO":
            raise SystemExit(label + ": rule uses AUTO")
    if "policy-regex-filter=CF-BWG" not in text:
        raise SystemExit(label + ": AUTO group missing")
    # Reject block must appear before the forced Google proxy suffix.
    reject_at = text.index("DOMAIN-SUFFIX,google-analytics.com,REJECT")
    proxy_at = text.index("DOMAIN-SUFFIX,google.com,PROXY")
    if reject_at > proxy_at:
        raise SystemExit(label + ": ad reject is below google.com PROXY")
    if "DOMAIN-KEYWORD,google,PROXY" in text:
        raise SystemExit(label + ": google keyword proxy remains")
    mitm = section_body(text, "[MITM]")
    if "hostname = *.google.cn,*.googlevideo.com" not in mitm:
        raise SystemExit(label + ": MITM hostname missing")
    if mitm.count("hostname") != 1:
        raise SystemExit(label + ": MITM hostname duplicated")


def check_real_file(path: Path) -> None:
    original = path.read_text(encoding="utf-8")
    if "hostname = *.google.cn,*.googlevideo.com" not in original:
        raise SystemExit("real file MITM baseline missing")
    once, _stats = apply_text(original)
    twice, _stats2 = apply_text(once)
    if once != twice:
        raise SystemExit("real file overlay is not idempotent")
    check_expectations(once, path.name)
    # Previous fork edit deleted this exact reject. It must not be silently restored,
    # and the broad google.com proxy is allowed to take it.
    if first_policy(once, host="analytics.google.com").upper() != "PROXY":
        raise SystemExit("analytics.google.com policy changed unexpectedly")
    if "vless://" in once or "hy2://" in once or "password =" in once:
        raise SystemExit("credential material appeared")
    print(f"real file ok: {path} bytes {len(once)}")


def main() -> int:
    once, stats = apply_text(FIXTURE)
    twice, _stats2 = apply_text(once)
    if once != twice:
        raise SystemExit("fixture overlay is not idempotent")
    if stats["ad_proxy_or_direct"] < 5:
        raise SystemExit("fixture did not remove ad proxy overrides: " + str(stats))
    if stats["google_keyword"] != 1:
        raise SystemExit("fixture did not remove google keyword: " + str(stats))
    check_expectations(once, "fixture")
    if section_body(once, "[MITM]") != "[MITM]\nhostname = *.google.cn,*.googlevideo.com":
        raise SystemExit("fixture MITM changed: " + section_body(once, "[MITM]"))
    root = Path(__file__).resolve().parents[1]
    real = root / "sr_top500_whitelist_ad.conf"
    if real.exists():
        check_real_file(real)
    print("fixture ok", stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
