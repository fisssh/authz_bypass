#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
whitelist_probe.py —— 免鉴权白名单前缀独立探测工具 v1.0
================================================================
仅做一件事：探测目标站点哪些路径前缀绕过了鉴权（匿名可达路由层），
不做任何绕过变形测试（变形测试请配合 authz_bypass_v3_4.py 使用）。

判定原理（404 指纹法）
----------------------------------------------------------------
鉴权 Filter/中间件在路由之前执行：
  · 白名单前缀下的随机垃圾路径 → Filter 放行 → 路由层 404/405/400/410
  · 非白名单前缀下的同样路径   → Filter 先拦 → 401/403/跳登录页
先用根级垃圾路径确认站点确有全局鉴权（防全站 404 的 SPA/网关误判）；
无全局鉴权时自动降级为弱信号（前缀根匿名 2xx 且非登录页）。

覆盖设计（完整性）
----------------------------------------------------------------
1. 候选来源四路合并去重：
   a. 内置字典 200+ 条，按生态分组（静态资源/Java生态/Spring Actuator/
      认证端点/.NET/PHP/前端移动/中文业务习惯）
   b. robots.txt Disallow 解析（站点自定义路径主要来源）
   c. sitemap.xml <loc> 解析
   d. 目标页 HTML 的 href/src/action 资源引用提取
   e. --extra-candidate 手工注入
2. 多上下文级探测：站点根 + 目标路径的全部祖先目录（如 /app、/app/admin），
   覆盖 WAR 上下文路径下的白名单
3. 文件级候选（favicon.ico 等）直接匿名 GET 精确路径验证
4. 边界检测：对命中前缀追加 startsWith 误配探测（/staticX）与大小写
   不敏感探测（/STATIC），发现配置缺陷单独标注
5. 双信号分级：强信号（全局有鉴权 + 垃圾路径穿透路由层）→ 高置信；
   弱信号（站点无全局鉴权，仅前缀根 2xx）→ 低置信

用法
----------------------------------------------------------------
python whitelist_probe.py --url http://target/app/admin/user/list
python whitelist_probe.py --url http://target/ --proxy http://127.0.0.1:8080 --delay 0.2
输出：控制台报告 + JSON + CSV，并生成可直接拼给 v3.4 工具的
      --whitelist-prefix 参数行。
"""

import argparse
import asyncio
import csv
import json
import os
import random
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

VERSION = "1.0"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

MAX_BODY = 64 * 1024

# ---------------------------------------------------------------------------
# 候选字典（按生态分组，键用于报告展示来源分组）
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

# 文件级候选（含 "."，走精确 GET 而非垃圾路径追加）
FILE_SUFFIX_MARK = "."

ROUTE_CODES = {400, 404, 405, 410}     # 鉴权放行后由路由层返回
DENY_CODES = {401, 403}                # 鉴权层拦截
REDIRECT_CODES = {301, 302, 303, 307, 308}
LOGIN_HINT_RE = re.compile(r"(?i)login|signin|sign-in|sso|cas|auth|oauth|token|passport|redirect")
HTML_PATH_RE = re.compile(r"""(?:href|src|action|data-url)\s*=\s*["']([^"'#?]+)""")
ROBOTS_DISALLOW_RE = re.compile(r"(?im)^(?:disallow|allow):\s*(\S+)")
SITEMAP_LOC_RE = re.compile(r"(?im)<loc>\s*([^<\s]+)\s*</loc>")


# ---------------------------------------------------------------------------
# 基础设施
# ---------------------------------------------------------------------------
class RateLimiter:
    """最小间隔 + 并发信号量的简易限速"""

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
    """匿名探测客户端（DummyCookieJar：不持久化任何 Cookie，保证匿名语义）。
    瞬时错误（连接重置/超时）自动重试一次，避免高并发下漏报。"""

    def __init__(self, timeout=15.0, proxy=None, cookie=None):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.cookie = cookie
        self._session = None
        self.errors = 0

    async def session(self):
        if self._session is None or self._session.closed:
            jar = aiohttp.DummyCookieJar()
            self._session = aiohttp.ClientSession(
                timeout=self.timeout, cookie_jar=jar,
                headers={"User-Agent": UA, "Accept": "*/*",
                         "Connection": "keep-alive"})
        return self._session

    async def get(self, url, limiter, max_redirect=False):
        last = None
        for attempt in range(2):  # 首发失败重试一次
            await limiter.acquire()
            start = time.monotonic()
            headers = {}
            if self.cookie:
                headers["Cookie"] = self.cookie
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
    """目标路径的全部祖先目录 + 根（去重，保持顺序）。
    /app/admin/user/list → ["", "app", "app/admin", "app/admin/user"]"""
    p = urlparse(url).path or "/"
    segs = [s for s in p.split("/") if s]
    if not segs:
        return [""]
    out = [""]
    acc = ""
    for s in segs[:-1] if len(segs) > 1 else segs[:0]:
        acc = f"{acc}/{s}" if acc else s
        out.append(acc)
    # 单段路径（如 /admin）时，其本身也可能是上下文挂载点
    if len(segs) == 1:
        out.append(segs[0])
    return out


def build_url(base, ctx, path):
    p = f"/{ctx}/{path}" if ctx else f"/{path}"
    return base.rstrip("/") + p


# ---------------------------------------------------------------------------
# 候选收集（四源合并）
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
        out.append("/".join(segs[:2]))   # 两段变体（/api/v2 这类多段白名单）
        out.append(segs[0])              # 首段变体（白名单可能只挂首段）
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
    # 401/403 页面也常引用登录静态资源，一并提取
    body = r["body"] or ""
    out = []
    for m in HTML_PATH_RE.finditer(body):
        u = m.group(1)
        if u.startswith(("javascript:", "data:", "mailto:", "tel:", "//", "http")):
            continue
        segs = [s for s in urlparse(u).path.split("/") if s]
        if segs:
            out.append("/".join(segs[:2]))
            out.append(segs[0])   # 首段单独入列：/customfront/app.js → customfront
    return out


def collect_candidates(target, extra):
    """四源合并去重 → {候选路径: 来源标签}；字典来源记录生态分组"""
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
# 探测与判定
# ---------------------------------------------------------------------------
def classify(root_denied, junk, prefix_root):
    """返回 (是否白名单, 置信度, 信号, 证据描述)。
    junk = 前缀下垃圾路径响应；prefix_root = 前缀根响应（可为 None）"""
    if junk["err"]:
        return False, "-", "请求失败", f"错误: {junk['err']}"
    denied = junk["code"] in DENY_CODES or is_login_redirect(junk["location"])
    if denied:
        return False, "-", "鉴权拦截", f"垃圾路径 HTTP {junk['code']}" + \
            (f" → {junk['location'][:50]}" if junk["location"] else "")

    routed = junk["code"] in ROUTE_CODES
    ok = junk["code"] == 200 and not is_login_redirect(junk["location"])
    loginish_body = bool(junk["body"]) and LOGIN_HINT_RE.search(junk["body"][:512])

    if root_denied:
        # 强信号模式：全局有鉴权，垃圾路径却能穿透
        if routed:
            ev = f"垃圾路径 HTTP {junk['code']}"
            if prefix_root and prefix_root["code"] == 200:
                ev += f"；前缀根 HTTP 200"
            return True, "高", "强信号(路由穿透)", ev
        if ok and not loginish_body:
            ev = f"垃圾路径 HTTP 200 且非登录内容（泛解析/前端路由需人工确认）"
            return True, "中", "疑似穿透", ev
        if ok and loginish_body:
            return False, "-", "登录页", "垃圾路径返回登录页内容"
        return False, "-", "无差异", f"垃圾路径 HTTP {junk['code']}"

    # 弱信号模式：站点根本无全局鉴权拦截 → 只报告"匿名可达且真实存在"的前缀
    if prefix_root and prefix_root["code"] == 200 and not is_login_redirect(prefix_root["location"]) \
            and not LOGIN_HINT_RE.search((prefix_root["body"] or "")[:512]):
        return True, "低", "弱信号(无全局鉴权)", f"前缀根匿名 200 ({prefix_root['ctype'][:30]})"
    if routed:
        return True, "低", "弱信号(路由可达)", f"垃圾路径 HTTP {junk['code']}"
    return False, "-", "无差异", f"垃圾路径 HTTP {junk['code']}"


async def probe_candidate(client, limiter, base, ctx, cand, source, root_denied, junk):
    """探测单个候选前缀。文件级候选（含.）走精确 GET；目录级走垃圾路径追加。"""
    is_file = FILE_SUFFIX_MARK in cand.rsplit("/", 1)[-1]
    if is_file:
        r = await client.get(build_url(base, ctx, cand), limiter)
        if r["err"]:
            return None
        if r["code"] == 200:
            # 文件级：匿名可取即事实上的放行（无鉴权站点下降级低置信）
            conf = "高" if root_denied else "低"
            return {"前缀": cand, "上下文": ctx or "/", "来源": source,
                    "信号": "文件级匿名可达", "置信度": conf,
                    "证据": f"GET {cand} → 200 ({r['ctype'][:30]}, len={r['len']})",
                    "备注": ""}
        return None

    url = build_url(base, ctx, f"{cand}/{junk}")
    jr = await client.get(url, limiter)
    if jr["err"]:
        return None
    root_r = None
    if jr["code"] in (ROUTE_CODES | {200}) or is_login_redirect(jr["location"]) \
            or jr["code"] in DENY_CODES:
        # 仅对有响应差异迹象的候选补一发前缀根验证（控制请求量）
        root_r = await client.get(build_url(base, ctx, cand) + "/", limiter)
    hit, conf, signal, ev = classify(root_denied, jr, root_r)
    if not hit:
        return None
    return {"前缀": cand, "上下文": ctx or "/", "来源": source,
            "信号": signal, "置信度": conf, "证据": ev, "备注": ""}


async def boundary_checks(client, limiter, base, ctx, cand):
    """对已命中前缀做边界检测：startsWith 误配 + 大小写不敏感。
    返回备注列表（描述配置缺陷，属额外收益信息）。"""
    notes = []
    junk = "authz_probe_" + os.urandom(4).hex()
    base_seg = cand.split("/")[0]
    # startsWith 误配：/staticX/垃圾 → 若同样穿透，白名单用 startsWith 匹配（更弱）
    r = await client.get(build_url(base, ctx, f"{base_seg}x9z/{junk}"), limiter)
    if not r["err"] and (r["code"] in ROUTE_CODES or r["code"] in DENY_CODES):
        if r["code"] in ROUTE_CODES:
            notes.append(f"前缀匹配疑似 startsWith（/{base_seg}x9z 同样穿透 → HTTP {r['code']}）")
    # 大小写不敏感：首段大小写互换 → 同样穿透说明匹配不区分大小写
    swapped = base_seg[0].swapcase() + base_seg[1:]
    if swapped != base_seg:
        r2 = await client.get(build_url(base, ctx, f"{swapped}/{junk}"), limiter)
        if not r2["err"] and r2["code"] in ROUTE_CODES:
            notes.append(f"大小写不敏感（/{swapped} 同样穿透 → HTTP {r2['code']}）")
    return notes


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
async def run(args):
    parsed = urlparse(args.url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    limiter = RateLimiter(args.delay, args.concurrency)
    client = Client(timeout=args.timeout, proxy=args.proxy, cookie=args.cookie)

    print(f"[*] 目标: {args.url}")
    print(f"[*] 站点根: {base} | 代理: {args.proxy or '无'} | Cookie: {'已提供' if args.cookie else '匿名'}")

    # ---- 阶段 0：连通性 + 全局鉴权确认 ----
    junk_root = "authz_probe_" + os.urandom(5).hex()
    root_probe = await client.get(f"{base}/{junk_root}", limiter)
    if root_probe["err"]:
        print(f"[-] 站点根探测失败（{root_probe['err']}），退出")
        await client.close()
        return 2
    root_denied = root_probe["code"] in DENY_CODES or is_login_redirect(root_probe["location"])
    print(f"[*] 根级指纹: HTTP {root_probe['code']}"
          + (f" → {root_probe['location'][:60]}" if root_probe["location"] else "")
          + ("  [全局鉴权确认，启用强信号]" if root_denied else "  [未确认全局鉴权，启用弱信号]"))

    # ---- 阶段 1：候选收集（四源 + 注入）----
    extra = [e for chunk in (args.extra_candidate or []) for e in chunk.split(",")]
    cands = collect_candidates(args.url, extra)

    print("[*] 解析 robots.txt / sitemap.xml / 页面资源引用 ...")
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
    html_paths = await collect_html_paths(client, limiter, args.url)
    for p in html_paths:
        n = norm_seg(p)
        if n and n not in cands:
            cands[n] = "页面引用"
    # 页面引用与 robots 来源的候选量可能较大，全部纳入（探测本身可控速）

    ctxs = target_contexts(args.url)
    print(f"[*] 候选 {len(cands)} 个 × 上下文 {ctxs} = {len(cands) * len(ctxs)} 次探测上限")

    # ---- 阶段 2：并行指纹探测 ----
    junk = "authz_probe_" + os.urandom(5).hex()
    sem_tasks = []
    results = []

    async def one(ctx, cand, source):
        r = await probe_candidate(client, limiter, base, ctx, cand, source, root_denied, junk)
        if r:
            results.append(r)

    total = 0
    for ctx in ctxs:
        for cand, source in cands.items():
            sem_tasks.append(one(ctx, cand, source))
    CHUNK = 200
    done = 0
    for i in range(0, len(sem_tasks), CHUNK):
        chunk = sem_tasks[i:i + CHUNK]
        await asyncio.gather(*chunk)
        done += len(chunk)
        print(f"    进度 {done}/{len(sem_tasks)}，命中 {len(results)}", end="\r")

    print()
    if client.errors:
        print(f"[!] 瞬时错误重试 {client.errors} 次（已自动恢复，未影响覆盖）")
    if not results:
        print("[-] 未发现免鉴权白名单前缀")
        await client.close()
        return 0

    # ---- 阶段 3：边界检测 + 去重合并（同前缀多上下文命中时保留证据最全的）----
    by_key = {}
    for r in sorted(results, key=lambda x: x["置信度"], reverse=False):
        key = (r["前缀"], r["上下文"])
        by_key[key] = r
    # 同一前缀不同上下文都命中时合并备注
    merged = defaultdict(list)
    for r in by_key.values():
        merged[r["前缀"]].append(r)
    final = []
    for prefix, rows in merged.items():
        main = max(rows, key=lambda x: ("高中低".index(x["置信度"]) if x["置信度"] in "高中低" else -1))
        if len(rows) > 1:
            main["备注"] += f"；另在上下文 [{'/'.join(r['上下文'] for r in rows if r is not main)}] 命中"
        notes = await boundary_checks(client, limiter, base, main["上下文"].rstrip("/"), prefix)
        if notes:
            main["备注"] += ("；" if main["备注"] else "") + "；".join(notes)
        final.append(main)

    rank = {"高": 0, "中": 1, "低": 2}
    final.sort(key=lambda x: (rank.get(x["置信度"], 9), x["前缀"]))

    def full_path(r):
        ctx = r["上下文"].strip("/")
        return f"/{ctx}/{r['前缀']}" if ctx else f"/{r['前缀']}"

    # ---- 输出 ----
    print(f"\n[+] 发现 {len(final)} 个免鉴权前缀：\n")
    print(f"  {'完整路径':<28}{'置信度':<6}{'信号':<20}来源")
    print("  " + "-" * 78)
    for r in final:
        print(f"  {full_path(r):<28}{r['置信度']:<6}{r['信号']:<20}{r['来源']}")
    print()
    for r in final:
        if r["备注"]:
            print(f"  ⚠ {full_path(r)}: {r['备注'].strip('；')}")

    # 报告落盘
    ts = time.strftime("%Y%m%d_%H%M%S")
    host = parsed.netloc.replace(":", "_")
    base_name = args.out or f"whitelist_{host}_{ts}"
    with open(base_name + ".csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["前缀", "上下文", "来源", "信号", "置信度", "证据", "备注"])
        w.writeheader()
        w.writerows(final)
    with open(base_name + ".json", "w", encoding="utf-8") as f:
        json.dump({"目标": args.url, "站点根": base, "根级指纹": root_probe["code"],
                   "全局鉴权": root_denied, "发现": final}, f, ensure_ascii=False, indent=2)
    print(f"\n[*] 报告: {base_name}.csv / {base_name}.json")

    # v3.4 工具参数行：折叠子路径（父前缀已发现时子路径冗余），保留上下文层级
    all_paths = {full_path(r) for r in final}
    export_items = []
    for r in final:
        if r["置信度"] == "低":
            continue
        p = full_path(r)
        parent_hit = any(p.startswith(q + "/") and p != q for q in all_paths)
        if not parent_hit:
            export_items.append(p)
    if export_items:
        export = " ".join(f"--whitelist-prefix {p}" for p in sorted(export_items))
        print(f"\n[*] 拼接 authz_bypass_v3_4.py 用参数（高/中置信，已折叠子路径）:\n    {export}")
    await client.close()
    return 0


def parse_args():
    p = argparse.ArgumentParser(
        description="免鉴权白名单前缀独立探测工具 v" + VERSION +
                    "（404指纹法 + 四源候选 + 多上下文 + 边界检测）")
    p.add_argument("--url", required=True, help="目标 URL（其路径祖先目录将作为上下文级探测）")
    p.add_argument("--proxy", default=None, help="HTTP(S) 代理，如 http://127.0.0.1:8080")
    p.add_argument("--cookie", default=None, help="可选 Cookie（默认匿名探测；提供后结论含会话语义）")
    p.add_argument("--delay", type=float, default=0.1, help="请求最小间隔秒（默认 0.1）")
    p.add_argument("--concurrency", type=int, default=8, help="并发数（默认 8）")
    p.add_argument("--timeout", type=float, default=15.0, help="单请求超时秒（默认 15）")
    p.add_argument("--extra-candidate", dest="extra_candidate", action="append", default=None,
                   metavar="PATH",
                   help="手工注入候选前缀（可多次指定，逗号分隔多值）")
    p.add_argument("--out", default=None, help="报告文件名前缀（默认 whitelist_<host>_<时间>）")
    return p.parse_args()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
    random.seed()
    args = parse_args()
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(130)


if __name__ == "__main__":
    main()
