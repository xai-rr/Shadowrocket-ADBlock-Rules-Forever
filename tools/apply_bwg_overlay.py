#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reapply the BWG routing overlay onto sr_top500_whitelist_ad.conf.

The release workflow copies factory output over this file on every successful
generation. This script is idempotent: run it after that copy, and again on an
already merged file, and the routing result stays the same.

It does not add proxy nodes, passwords, certificates, or MITM hostnames.
Rules use the built-in PROXY policy (whatever node is selected in the app).
"""

from __future__ import annotations

import sys
from pathlib import Path


BEGIN = "# BWG-MERGE-BEGIN"
END = "# BWG-MERGE-END"

# Ad suffixes that must stay REJECT. Attachment PROXY rules for these names are
# dropped so they cannot win over the ad list on either first-match or a
# same-length tie.
AD_REJECT_SUFFIXES = (
    "google-analytics.com",
    "googleadservices.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "googletagservices.com",
    "doubleclick.net",
    "doubleclick.com",
    "app-measurement.com",
    "adservice.google.com",
    "ads.google.com",
    "pagead.google.com",
    "pagead.l.google.com",
    "pagead-tpc.l.google.com",
    "mobileads.google.com",
    "partnerad.l.google.com",
    "www-google-analytics.l.google.com",
    "ssl-google-analytics.l.google.com",
    "afd.l.google.com",
    "imasdk.googleapis.com",
)

# Exact names. analytics.google.com is intentionally absent: it was removed
# from the reject list on this fork and is not one of the attachment suffixes.
AD_REJECT_EXACT = (
    "mask.icloud.com",
    "mask-h2.icloud.com",
)

# Services that must follow the node selected on the home screen.
# DOMAIN-KEYWORD,google and DOMAIN-KEYWORD,youtube are omitted: "google" also
# matches the ad suffixes above.
FORCE_PROXY_SUFFIXES = (
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",
    "yt-img.com",
    "youtu.be",
    "youtube-nocookie.com",
    "yt.be",
    "ggpht.com",
    "google.com",
    "google.com.hk",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "gvt1.com",
    "gvt2.com",
    "gmail.com",
    "googlemail.com",
    "withgoogle.com",
    "android.com",
    "1e100.net",
    "blogspot.com",
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "auth0.com",
    "anthropic.com",
    "claude.ai",
    "claudeusercontent.com",
    "x.ai",
    "xai.com",
    "grok.com",
    "perplexity.ai",
    "cursor.com",
    "cursor.sh",
    "cursorapi.com",
    "poe.com",
    "huggingface.co",
    "huggingface.com",
    "midjourney.com",
    "stability.ai",
    "cohere.com",
    "phind.com",
    "replit.com",
    "replicate.com",
    "runpod.io",
    "lmsys.org",
    "kiro.dev",
    "kagi.com",
    "notion.so",
    "notion-static.com",
    "linear.app",
    "figma.com",
    "vercel.com",
    "ollama.com",
    "deeplearning.ai",
    "challenges.cloudflare.com",
    "turnstile.hcaptcha.com",
    "x.com",
    "twitter.com",
    "twimg.com",
    "t.co",
    "telegram.org",
    "t.me",
    "facebook.com",
    "fbcdn.net",
    "instagram.com",
    "cdninstagram.com",
    "whatsapp.net",
    "whatsapp.com",
    "reddit.com",
    "redd.it",
    "redditmedia.com",
    "github.com",
    "githubusercontent.com",
    "github.io",
    "wikipedia.org",
    "medium.com",
    "discord.com",
    "discord.gg",
    "netflix.com",
    "nflxvideo.net",
    "spotify.com",
    "slack.com",
    "tiktok.com",
)

FORCE_PROXY_KEYWORDS = ("kiro", "ollama", "grok")

# Domestic names whose TLD is not necessarily .cn. The generated
# DOMAIN-SUFFIX,cn,DIRECT / GEOIP,CN,DIRECT rules stay where the factory put
# them (after manual proxy) so a more specific proxy for a .cn name can win.
FORCE_DIRECT_SUFFIXES = (
    "lovart.ai",
    "qq.com",
    "weixin.com",
    "wechat.com",
    "gtimg.com",
    "tencent.com",
    "tencent-cloud.net",
    "myqcloud.com",
    "douyin.com",
    "douyinpic.com",
    "douyinvod.com",
    "amemv.com",
    "snssdk.com",
    "pstatp.com",
    "bytedance.com",
    "byteoversea.com",
    "byteimg.com",
    "toutiao.com",
    "taobao.com",
    "tmall.com",
    "alipay.com",
    "alicdn.com",
    "aliyun.com",
    "aliyuncs.com",
    "amap.com",
    "jd.com",
    "360buyimg.com",
    "pinduoduo.com",
    "yangkeduo.com",
    "meituan.com",
    "meituan.net",
    "dianping.com",
    "bilibili.com",
    "hdslb.com",
    "biliapi.net",
    "xiaohongshu.com",
    "xhscdn.com",
    "zhihu.com",
    "zhimg.com",
    "weibo.com",
    "baidu.com",
    "bdstatic.com",
    "163.com",
    "126.net",
    "netease.com",
    "kuaishou.com",
    "iqiyi.com",
    "youku.com",
    "ctrip.com",
    "unionpay.com",
)

FORCE_DIRECT_KEYWORDS = ("feishu", "lark")

GENERAL_KEYS = (
    "block-quic",
    "udp-policy-not-supported-behaviour",
    "prefer-ipv6",
    "dns-direct-system",
    "dns-direct-fallback-proxy",
    "private-ip-answer",
    "icmp-auto-reply",
)

DIRECT_ANCHOR = "# 手工定义的 Direct 列表"
LEGACY_START = "# 跳板机直连"
LEGACY_END = "# adblock rules refresh time:"


def _suffix_hit(domain: str, suffix: str) -> bool:
    domain = domain.lower().strip(".")
    suffix = suffix.lower().strip(".")
    return domain == suffix or domain.endswith("." + suffix)


def _covered(domain: str, suffixes: tuple[str, ...]) -> bool:
    return any(_suffix_hit(domain, suffix) for suffix in suffixes)


def _split_rule(line: str) -> list[str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("["):
        return None
    parts = [part.strip() for part in stripped.split(",")]
    if not parts:
        return None
    kind = parts[0].upper()
    if kind == "FINAL" and len(parts) == 2:
        return [parts[0], "", parts[1]]
    if len(parts) < 3:
        return None
    if kind not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "GEOIP", "FINAL", "RULE-SET"}:
        return None
    return parts


def strip_managed_blocks(lines: list[str]) -> list[str]:
    output: list[str] = []
    skipping = False
    opened = ""
    for line in lines:
        if line.startswith(BEGIN):
            if skipping:
                raise SystemExit("nested " + line)
            skipping = True
            opened = line
            continue
        if line.startswith(END):
            if not skipping:
                raise SystemExit("orphan " + line)
            skipping = False
            continue
        if not skipping:
            output.append(line)
    if skipping:
        raise SystemExit("unclosed " + opened)
    return output


def strip_legacy_prelude(lines: list[str]) -> list[str]:
    """Drop the hand-edited block that sat above the ad list.

    Those rules are rebuilt in managed blocks. Leaving them in front of the
    ad list lets a broad PROXY suffix beat later REJECT lines.
    """
    start = None
    end = None
    for index, line in enumerate(lines):
        if start is None and line.strip() == LEGACY_START:
            start = index
            continue
        if start is not None and line.startswith(LEGACY_END):
            end = index
            break
    if start is None:
        return lines
    if end is None or end - start > 400:
        raise SystemExit("found legacy prelude but not its adblock end marker")
    return lines[:start] + lines[end:]


def _policy(parts: list[str]) -> str:
    return parts[2].strip().lower()


def drop_conflicting_rules(lines: list[str]) -> tuple[list[str], dict[str, int]]:
    """Remove rules that would steal a decision from the managed blocks."""
    stats = {"ad_proxy_or_direct": 0, "forced_proxy_direct": 0, "google_keyword": 0}
    output: list[str] = []
    for line in lines:
        parts = _split_rule(line)
        if parts is None:
            output.append(line)
            continue
        kind = parts[0].upper()
        domain = parts[1].lower()
        policy = _policy(parts)
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"} and _covered(domain, AD_REJECT_SUFFIXES + AD_REJECT_EXACT):
            if policy != "reject":
                stats["ad_proxy_or_direct"] += 1
                continue
        elif kind == "DOMAIN-KEYWORD" and domain == "google" and policy == "proxy":
            stats["google_keyword"] += 1
            continue
        elif (
            kind in {"DOMAIN", "DOMAIN-SUFFIX"}
            and policy == "direct"
            and _covered(domain, FORCE_PROXY_SUFFIXES)
            and not _covered(domain, AD_REJECT_SUFFIXES)
        ):
            stats["forced_proxy_direct"] += 1
            continue
        output.append(line)
    return output, stats


def _section_spans(lines: list[str]) -> list[tuple[str, int, int]]:
    headers = [index for index, line in enumerate(lines) if line.startswith("[") and line.endswith("]")]
    spans = []
    for position, start in enumerate(headers):
        end = headers[position + 1] if position + 1 < len(headers) else len(lines)
        spans.append((lines[start], start, end))
    return spans


def _find_section(lines: list[str], name: str) -> tuple[int, int]:
    for header, start, end in _section_spans(lines):
        if header == name:
            return start, end
    raise SystemExit("missing section " + name)


def _is_managed_general_key(line: str) -> bool:
    stripped = line.strip()
    for key in GENERAL_KEYS:
        if stripped.startswith(key + " ") or stripped.startswith(key + "="):
            return True
    return False


def insert_general(lines: list[str]) -> list[str]:
    start, end = _find_section(lines, "[General]")
    body = [line for line in lines[start + 1 : end] if not _is_managed_general_key(line)]
    # Keep the factory ipv6 = false line. Do not switch on attachment ipv6=true.
    block = [
        "# BWG-MERGE-BEGIN general",
        "# 仅对走代理的连接屏蔽 QUIC，YouTube/Google 回落到 TCP，便于 CF VLESS/WS；直连不改。",
        "block-quic = all-proxy",
        "# 当前节点不支持 UDP 时拒绝该 UDP，避免回落到 DIRECT。选中 HY2 时 UDP 仍可由该节点承载。",
        "udp-policy-not-supported-behaviour = REJECT",
        "prefer-ipv6 = false",
        "dns-direct-system = false",
        "dns-direct-fallback-proxy = true",
        "private-ip-answer = true",
        "icmp-auto-reply = true",
        "# BWG-MERGE-END general",
    ]
    return lines[: start + 1] + body + block + lines[end:]


def insert_proxy_group(lines: list[str]) -> list[str]:
    block = [
        "# BWG-MERGE-BEGIN proxy-group",
        "# 规则使用 PROXY（首页当前选中的节点），不会自动改去 AUTO。",
        "# AUTO 只在节点名匹配 CF-BWG 时测速；名称不含 CF-BWG 的 HY2 不会进组。",
        "# 这不是固定 BWG 出口，也不是出口失败即断开。",
        "AUTO = url-test,policy-regex-filter=CF-BWG,interval=600,timeout=5,tolerance=80,url=http://www.gstatic.com/generate_204",
        "# BWG-MERGE-END proxy-group",
    ]
    try:
        start, end = _find_section(lines, "[Proxy Group]")
    except SystemExit:
        rule_at, _rule_end = _find_section(lines, "[Rule]")
        insertion = ["[Proxy Group]"] + block + [""]
        return lines[:rule_at] + insertion + lines[rule_at:]
    body = lines[start + 1 : end]
    body = [line for line in body if not line.startswith("AUTO = url-test,policy-regex-filter=CF-BWG")]
    return lines[: start + 1] + block + body + lines[end:]


def _suffix_rules(suffixes: tuple[str, ...], policy: str) -> list[str]:
    return [f"DOMAIN-SUFFIX,{suffix},{policy}" for suffix in suffixes]


def _keyword_rules(keywords: tuple[str, ...], policy: str) -> list[str]:
    return [f"DOMAIN-KEYWORD,{keyword},{policy}" for keyword in keywords]


def rule_blocks() -> dict[str, list[str]]:
    reject = (
        ["# BWG-MERGE-BEGIN reject-priority", "# 广告与 iCloud Private Relay。必须位于后续 PROXY 之前。"]
        + [f"DOMAIN,{name},REJECT" for name in AD_REJECT_EXACT]
        + _suffix_rules(AD_REJECT_SUFFIXES, "REJECT")
        + ["# BWG-MERGE-END reject-priority"]
    )
    direct_head = [
        "# BWG-MERGE-BEGIN direct-head",
        "# 跳板机与局域网直连。不含会盖住广告域名的 DOMAIN-SUFFIX。",
        "IP-CIDR,13.215.120.134/32,DIRECT,no-resolve",
        "IP-CIDR,47.129.15.196/32,DIRECT,no-resolve",
        "IP-CIDR,47.244.103.210/32,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT",
        "IP-CIDR,172.16.0.0/12,DIRECT",
        "IP-CIDR,192.168.0.0/16,DIRECT",
        "IP-CIDR,100.64.0.0/10,DIRECT",
        "IP-CIDR,172.17.0.0/16,DIRECT",
        "DOMAIN-SUFFIX,vpc.internal,DIRECT",
        "DOMAIN-SUFFIX,lovart.ai,DIRECT",
        "# BWG-MERGE-END direct-head",
    ]
    proxy = (
        ["# BWG-MERGE-BEGIN proxy-select", "# 走首页当前选中的 PROXY，而不是 AUTO 或命名策略组。"]
        + _suffix_rules(FORCE_PROXY_SUFFIXES, "PROXY")
        + _keyword_rules(FORCE_PROXY_KEYWORDS, "PROXY")
        + [
            "IP-CIDR,91.108.0.0/16,PROXY,no-resolve",
            "IP-CIDR,149.154.160.0/20,PROXY,no-resolve",
            "# BWG-MERGE-END proxy-select",
        ]
    )
    china = (
        [
            "# BWG-MERGE-BEGIN direct-cn",
            "# 国内服务直连。放在广告 REJECT 和强制 PROXY 之后，避免盖住去广告。",
            "# byteoversea.com / bytedance.com 保持直连，是原先飞书/字节规则；TikTok 主域名仍走 PROXY。",
        ]
        + _suffix_rules(tuple(name for name in FORCE_DIRECT_SUFFIXES if name != "lovart.ai"), "DIRECT")
        + _keyword_rules(FORCE_DIRECT_KEYWORDS, "DIRECT")
        + ["# BWG-MERGE-END direct-cn"]
    )
    return {
        "top": reject + direct_head,
        "before_direct": proxy + china,
    }


def insert_rules(lines: list[str]) -> list[str]:
    blocks = rule_blocks()
    _rule_start, rule_end = _find_section(lines, "[Rule]")
    anchor = None
    for index in range(_find_section(lines, "[Rule]")[0] + 1, rule_end):
        if lines[index].strip() == DIRECT_ANCHOR:
            anchor = index
            break
    if anchor is None:
        raise SystemExit("missing anchor: " + DIRECT_ANCHOR)

    top_at = None
    for index in range(_find_section(lines, "[Rule]")[0] + 1, anchor):
        if lines[index].startswith(LEGACY_END) or lines[index].startswith("DOMAIN-") or lines[index].startswith("IP-CIDR"):
            top_at = index
            break
    if top_at is None:
        top_at = anchor

    lines = lines[:top_at] + blocks["top"] + [""] + lines[top_at:]
    anchor += len(blocks["top"]) + 1
    lines = lines[:anchor] + blocks["before_direct"] + [""] + lines[anchor:]
    return lines


def ensure_final_proxy(lines: list[str]) -> list[str]:
    start, end = _find_section(lines, "[Rule]")
    kept: list[str] = []
    finals: list[int] = []
    for index in range(start, end):
        parts = _split_rule(lines[index])
        if parts is not None and parts[0].upper() == "FINAL":
            finals.append(index)
    if not finals:
        raise SystemExit("whitelist rules lost FINAL")
    last = finals[-1]
    for index in range(start, end):
        if index in finals and index != last:
            continue
        if index == last:
            kept.append("FINAL,PROXY")
        else:
            kept.append(lines[index])
    return lines[:start] + kept + lines[end:]


def ensure_host(lines: list[str]) -> list[str]:
    host_line = "localhost = 127.0.0.1"
    try:
        start, end = _find_section(lines, "[Host]")
    except SystemExit:
        try:
            rewrite_at, _rewrite_end = _find_section(lines, "[URL Rewrite]")
        except SystemExit:
            rewrite_at = len(lines)
        block = ["", "[Host]", host_line, ""]
        return lines[:rewrite_at] + block + lines[rewrite_at:]
    body = lines[start + 1 : end]
    if not any(line.strip().lower().startswith("localhost") for line in body):
        body = body + [host_line]
    return lines[: start + 1] + body + lines[end:]


def collapse_blank_lines(lines: list[str]) -> list[str]:
    output: list[str] = []
    previous_blank = False
    for line in lines:
        blank = line.strip() == ""
        if blank and previous_blank:
            continue
        output.append("" if blank else line)
        previous_blank = blank
    return output


def validate(lines: list[str], mitm_before: list[str]) -> None:
    headers = [line for line in lines if line.startswith("[") and line.endswith("]")]
    for name in ("[General]", "[Proxy Group]", "[Rule]", "[Host]", "[URL Rewrite]", "[MITM]"):
        if headers.count(name) != 1:
            raise SystemExit(f"section {name} count is {headers.count(name)}")
    if "[Proxy]" in headers:
        raise SystemExit("refusing to add a [Proxy] node section")
    text = "\n".join(lines)
    if "稳定线路" in text:
        raise SystemExit("稳定线路 policy remains")
    if "block-quic = all-proxy" not in text:
        raise SystemExit("missing block-quic")
    if text.count("\nblock-quic ") + text.count("\nblock-quic=") > 1 and text.count("block-quic = all-proxy") != 1:
        raise SystemExit("duplicated block-quic")
    if text.count("udp-policy-not-supported-behaviour = REJECT") != 1:
        raise SystemExit("udp policy count is wrong")
    if text.count("\nFINAL,PROXY") != 1:
        raise SystemExit("FINAL,PROXY count is wrong")
    if "FINAL,DIRECT" in text.upper() or any(
        (_split_rule(line) or [""])[0].upper() == "FINAL" and _policy(_split_rule(line) or ["", "", "proxy"]) != "proxy"
        for line in lines
        if _split_rule(line) and _split_rule(line)[0].upper() == "FINAL"
    ):
        raise SystemExit("FINAL is not PROXY")
    for line in lines:
        parts = _split_rule(line)
        if parts is None:
            continue
        if parts[2].strip().upper() == "AUTO":
            raise SystemExit("rule points at AUTO: " + line)
        if parts[0].upper() in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"} and _covered(parts[1], AD_REJECT_SUFFIXES):
            if _policy(parts) != "reject":
                raise SystemExit("ad suffix not reject: " + line)
    try:
        _mitm_start, mitm_end = _find_section(lines, "[MITM]")
        mitm_now = lines[_mitm_start:mitm_end]
    except SystemExit:
        mitm_now = []
    if mitm_now != mitm_before:
        raise SystemExit("MITM section changed")
    if "BEGIN certificate" in text or "ssl-certificate" in text:
        raise SystemExit("certificate material appeared")


def apply_text(text: str) -> tuple[str, dict[str, int]]:
    if not text.endswith("\n"):
        text += "\n"
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    try:
        mitm_start, mitm_end = _find_section(lines, "[MITM]")
        mitm_before = lines[mitm_start:mitm_end]
    except SystemExit:
        mitm_before = []
    lines = strip_managed_blocks(lines)
    lines = strip_legacy_prelude(lines)
    lines = [line.replace("稳定线路", "PROXY") for line in lines]
    lines, stats = drop_conflicting_rules(lines)
    lines = insert_general(lines)
    lines = insert_proxy_group(lines)
    lines = insert_rules(lines)
    lines = ensure_final_proxy(lines)
    lines = ensure_host(lines)
    lines = collapse_blank_lines(lines)
    validate(lines, mitm_before)
    return "\n".join(lines) + "\n", stats


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: apply_bwg_overlay.py <sr_top500_whitelist_ad.conf>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    original = path.read_text(encoding="utf-8")
    updated, stats = apply_text(original)
    if updated != original:
        path.write_text(updated, encoding="utf-8")
    print(
        "overlay {0}: ad-overrides-removed={1} direct-overrides-removed={2} google-keyword-removed={3} changed={4}".format(
            path,
            stats["ad_proxy_or_direct"],
            stats["forced_proxy_direct"],
            stats["google_keyword"],
            updated != original,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
