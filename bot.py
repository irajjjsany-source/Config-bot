#!/usr/bin/env python3
"""ربات کانفیگ: خواندن کانال مرجع، تست با xray، انتشار در کانال، حذف کانفیگ‌های خراب.
اجرا:  python bot.py post   |   python bot.py clean
"""
import base64
import hashlib
import html
import ipaddress
import itertools
import json
import os
import random
import re
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ============ تنظیمات (این بخش رو ویرایش کن) ============
SOURCE_CHANNELS = ["chillguy_vpn"]  # یوزرنیم کانال(های) مرجع، بدون @
TARGET_CHANNEL = "@k2guard"
REMARK = "@k2guard  جوین شو 👈🏻"  # اسمی که داخل اپ کنار کانفیگ نمایش داده می‌شه
BUY_LINK = "https://t.me/K2guardbot?start=buy"
LAST_POSTS = 20          # تعداد پست‌های اخیر کانال مرجع
TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 8         # ثانیه
WORKERS = 8              # تست‌های همزمان
MAX_POSTED = 400         # تعداد پست‌هایی که برای حذف پیگیری می‌شن
SEEN_TTL = 3 * 86400     # کانفیگ دیده‌شده تا ۳ روز دوباره تست نمی‌شه
QUEUE_TTL = 6 * 3600     # کانفیگ سالمِ منتشرنشده تا ۶ ساعت تو صف می‌مونه
MIN_VIEWS = 100         # حداقل بازدید برای پست‌های کانفیگ
VIEW_GRACE = 6 * 3600   # پست کانفیگ تا ۶ ساعت فرصت جمع‌کردن بازدید دارد
REPOST_MAX = 1          # هر کانفیگ کم‌بازدید حداکثر یک بار بازنشر می‌شود
REPOST_MARK = "♻️"
MAX_PING = 5000
MAX_POSTS_PER_RUN = 1
MAX_CONFIGS_PER_RUN = 80
MAX_CLEAN_PER_RUN = 120
STABILITY_TESTS = 3
STABILITY_GAP = 0.35
MIN_STABILITY = 0.66  # دو تست موفق از سه تست کافی است
GEO_TTL = 7 * 86400      # کشور هر سرور تا ۷ روز دوباره لوکیشن‌یابی نمی‌شه
STATE_FILE = "state.json"
SOURCES_FILE = "sources.json"
SOURCE_TYPES = {"telegram", "github", "subscription", "txt", "api"}
MAX_SOURCE_BYTES = 2 * 1024 * 1024
SOURCE_TIMEOUT = 15
QUARANTINE_SECONDS = 30 * 60
# ========================================================

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")  # توکن فعلی برای ارسال کانفیگ به کانال
ADMIN_BOT_TOKEN = os.environ.get("ADMIN_BOT_TOKEN", "")  # توکن جداگانه برای پنل مدیریت
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID", "").strip()
POST_INTERVAL = 15 * 60
CLEAN_INTERVAL = 6 * 3600
XRAY = os.path.abspath("xray")
PORTS = itertools.count()
CFG_RE = re.compile(r"(?<![A-Za-z0-9])(?:vmess|vless|trojan|ss)://[^\s<>\"']+")


# ---------------- کمکی‌ها ----------------
class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_public_url(url):
    """فقط HTTP(S) عمومی؛ جلوگیری پایه‌ای از SSRF و دسترسی به شبکه داخلی."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("source URL must be HTTP(S)")
    if parsed.username or parsed.password:
        raise ValueError("credentials in source URLs are not allowed")
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"}:
        raise ValueError("local source URL is not allowed")
    try:
        addresses = {x[4][0] for x in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))}
        if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise ValueError("non-public source address is not allowed")
    except socket.gaierror as exc:
        raise ValueError("source host cannot be resolved") from exc


def http_get(url, timeout=SOURCE_TIMEOUT, max_bytes=MAX_SOURCE_BYTES):
    validate_public_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": "K2Guard/2.0 (+public-config-fetcher)"})
    opener = urllib.request.build_opener(SafeRedirectHandler())
    with opener.open(req, timeout=timeout) as r:
        data = r.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("source response exceeds size limit")
        return data.decode("utf-8", "replace")


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True).decode("utf-8", "replace")


def scheme(cfg):
    return cfg.split("://", 1)[0].lower()


def vmess_obj(cfg):
    return json.loads(b64d(cfg[8:]))


def identity(cfg):
    """هش کانفیگ بدون در نظر گرفتن اسم، برای حذف تکراری‌ها"""
    try:
        if scheme(cfg) == "vmess":
            o = vmess_obj(cfg)
            o.pop("ps", None)
            o.pop("name", None)
            base = "vmess:" + json.dumps(o, sort_keys=True)
        else:
            u = urllib.parse.urlsplit(cfg)
            query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(u.query, keep_blank_values=True)))
            # netloc را lowercase نمی‌کنیم؛ رمز Trojan ممکن است به بزرگی/کوچکی حروف حساس باشد.
            base = urllib.parse.urlunsplit((u.scheme.lower(), u.netloc, u.path, query, ""))
    except Exception:
        base = cfg
    return hashlib.sha1(base.encode()).hexdigest()[:16]


def rename(cfg, name):
    if scheme(cfg) == "vmess":
        o = vmess_obj(cfg)
        o["ps"] = name
        raw = json.dumps(o, ensure_ascii=False).encode()
        return "vmess://" + base64.b64encode(raw).decode()
    return cfg.split("#", 1)[0] + "#" + urllib.parse.quote(name)


def outbound_host(out):
    s = out.get("settings", {})
    if "vnext" in s:
        return s["vnext"][0]["address"]
    if "servers" in s:
        return s["servers"][0]["address"]
    return ""


# رنج‌های شناخته‌شده‌ی CDN/anycast (مثل Cloudflare)؛ برای این آی‌پی‌ها کشور نمایش‌داده‌شده
# واقعی نیست (چون IP بین کاربرهای مختلف دنیا مشترکه)، پس پرچم نشون داده نمی‌شه
CDN_NETWORKS = [ipaddress.ip_network(n) for n in (
    "104.16.0.0/13", "172.64.0.0/13", "188.114.96.0/20", "162.158.0.0/15",
    "198.41.128.0/17", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "197.234.240.0/22", "199.27.128.0/21", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "131.0.72.0/22",
)]


def is_cdn_edge(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in CDN_NETWORKS)


def country_flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - 65) for c in cc)


def lookup_geo(host, geo_cache):
    """کشور آی‌پی/دامنه رو برمی‌گردونه؛ نتیجه توی state کش می‌شه تا لوکیشن‌یابی زیاد تکرار نشه"""
    now = time.time()
    c = geo_cache.get(host)
    if c and now - c.get("ts", 0) < GEO_TTL:
        return c.get("cc", ""), c.get("name", "")
    cc, name = "", ""
    try:
        data = json.loads(http_get(
            "http://ip-api.com/json/%s?fields=status,countryCode,country"
            % urllib.parse.quote(host)))
        if data.get("status") == "success":
            cc, name = data.get("countryCode", ""), data.get("country", "")
    except Exception as e:
        print("geo lookup failed:", host, type(e).__name__)
    geo_cache[host] = {"cc": cc, "name": name, "ts": now}
    return cc, name


# ---------------- مدیریت و دریافت منابع ----------------
def default_sources():
    return {"version": 1, "sources": [
        {"name": ch.lstrip("@"), "type": "telegram", "channel": ch.lstrip("@"),
         "enabled": True, "priority": 10}
        for ch in SOURCE_CHANNELS
    ]}


def load_sources():
    if not os.path.exists(SOURCES_FILE):
        return default_sources()
    with open(SOURCES_FILE, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        raise ValueError("sources.json must contain a sources list")
    clean = []
    names = set()
    for item in data["sources"]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        kind = str(item.get("type", "")).lower().strip()
        if not name or kind not in SOURCE_TYPES or name.lower() in names:
            continue
        if kind == "telegram":
            channel = str(item.get("channel") or name).strip().lstrip("@")
            if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", channel):
                continue
            item["channel"] = channel
        else:
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            try:
                validate_public_url(url)
            except Exception as exc:
                print("source skipped (unsafe/invalid URL):", name, type(exc).__name__)
                continue
            item["url"] = url
        item["name"] = name
        item["type"] = kind
        item["enabled"] = bool(item.get("enabled", True))
        try:
            item["priority"] = max(0, min(100, int(item.get("priority", 5))))
        except (TypeError, ValueError):
            item["priority"] = 5
        clean.append(item)
        names.add(name.lower())
    return {"version": 1, "sources": clean}


def save_sources(data):
    atomic_json_write(SOURCES_FILE, data)


def extract_config_strings(value):
    out = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(extract_config_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(extract_config_strings(v))
    return out


def configs_from_text(text):
    found = [m.group(0).rstrip(".,;،") for m in CFG_RE.finditer(text or "")]
    if found:
        return found
    # Subscriptionهای Base64 که پس از decode شامل URIهای متنی هستند.
    compact = (text or "").strip()
    if compact and len(compact) <= MAX_SOURCE_BYTES:
        try:
            decoded = b64d(compact)
            found.extend(m.group(0).rstrip(".,;،") for m in CFG_RE.finditer(decoded))
        except Exception:
            pass
    return found


def fetch_telegram_source(channel):
    page = http_get("https://t.me/s/" + urllib.parse.quote(channel.lstrip("@")))
    blocks = re.findall(r'<div class="tgme_widget_message_text[^\"]*"[^>]*>(.*?)</div>', page, re.S)
    text = "\n".join(html.unescape(re.sub(r"<[^>]+>", " ", re.sub(r"<br\s*/?>", "\n", b))) for b in blocks[-LAST_POSTS:])
    return configs_from_text(text)


def fetch_source(item):
    kind = item["type"]
    if kind == "telegram":
        return fetch_telegram_source(item.get("channel") or item["name"])
    url = item["url"]
    if kind == "github":
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc.lower() == "github.com" and "/blob/" in parsed.path:
            url = "https://raw.githubusercontent.com/" + parsed.path.split("/blob/", 1)[0] + "/" + parsed.path.split("/blob/", 1)[1]
    body = http_get(url)
    if kind == "api":
        try:
            body = "\n".join(extract_config_strings(json.loads(body)))
        except json.JSONDecodeError:
            pass
    return configs_from_text(body)


def fetch_configs(st=None):
    """دریافت از همه منابع فعال؛ خطای یک منبع سایر منابع را متوقف نمی‌کند."""
    cfgs, source_stats, source_map = [], {}, {}
    data = load_sources()
    history = st.setdefault("source_history", {}) if st is not None else {}
    for item in sorted(data["sources"], key=lambda x: (-x.get("priority", 0), x["name"])):
        if not item.get("enabled", True):
            continue
        name = item["name"]
        try:
            found = fetch_source(item)
            ids = set()
            for cfg in found:
                cid = identity(cfg)
                names = source_map.setdefault(cid, [])
                if name not in names:
                    names.append(name)
                cfgs.append(cfg)
            source_stats[name] = {"fetched": len(found), "healthy": 0, "ok": True,
                                  "ts": int(time.time()), "error": ""}
            if st is not None:
                h = history.setdefault(name, {"fetched": 0, "healthy": 0, "failed": 0, "runs": 0})
                h["fetched"] = int(h.get("fetched", 0)) + len(found)
                h["runs"] = int(h.get("runs", 0)) + 1
            print("source %s: fetched %d" % (name, len(found)))
        except Exception as exc:
            source_stats[name] = {"fetched": 0, "healthy": 0, "ok": False,
                                  "ts": int(time.time()), "error": type(exc).__name__}
            if st is not None:
                h = history.setdefault(name, {"fetched": 0, "healthy": 0, "failed": 0, "runs": 0})
                h["runs"] = int(h.get("runs", 0)) + 1
                h["failed"] = int(h.get("failed", 0)) + 1
            print("source %s failed: %s" % (name, type(exc).__name__))
    if st is not None:
        st["source_stats"] = source_stats
        st["_source_map"] = source_map
    unique, seen_ids = [], set()
    for cfg in cfgs:
        key = identity(cfg)
        if key not in seen_ids:
            seen_ids.add(key)
            unique.append(cfg)
    return unique


# ---------------- ساخت کانفیگ xray ----------------
def build_stream(q, host):
    net = q.get("type") or "tcp"
    sec = q.get("security") or "none"
    path = q.get("path") or "/"
    hh = q.get("host", "")
    s = {"network": net}
    if net == "ws":
        s["wsSettings"] = {"path": path, "headers": {"Host": hh} if hh else {}}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": q.get("serviceName", ""),
                             "multiMode": q.get("mode") == "multi"}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": path, "host": hh}
    elif net in ("xhttp", "splithttp"):
        s["network"] = "xhttp"
        s["xhttpSettings"] = {"path": path, "host": hh, "mode": q.get("mode", "auto")}
    elif net == "tcp":
        if q.get("headerType") == "http":
            s["tcpSettings"] = {"header": {"type": "http", "request": {
                "path": path.split(","),
                "headers": {"Host": hh.split(",") if hh else []}}}}
    else:
        raise ValueError("unsupported transport: " + net)

    if sec == "tls":
        t = {"serverName": q.get("sni") or hh or host}
        if q.get("fp"):
            t["fingerprint"] = q["fp"]
        if q.get("alpn"):
            t["alpn"] = q["alpn"].split(",")
        if q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"):
            t["allowInsecure"] = True
        s["security"] = "tls"
        s["tlsSettings"] = t
    elif sec == "reality":
        s["security"] = "reality"
        s["realitySettings"] = {
            "serverName": q.get("sni", ""), "fingerprint": q.get("fp") or "chrome",
            "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", "")}
    return s


def build_outbound(cfg):
    sc = scheme(cfg)
    if sc == "vmess":
        o = vmess_obj(cfg)
        host = o["add"]
        q = {"type": o.get("net", "tcp"),
             "security": "tls" if o.get("tls") == "tls" else "none",
             "path": o.get("path", "/"), "host": o.get("host", ""),
             "sni": o.get("sni", ""), "fp": o.get("fp", ""), "alpn": o.get("alpn", ""),
             "headerType": o.get("type", ""), "serviceName": o.get("path", "")}
        return {"protocol": "vmess", "settings": {"vnext": [{
            "address": host, "port": int(o["port"]),
            "users": [{"id": o["id"], "alterId": int(o.get("aid") or 0),
                       "security": o.get("scy") or "auto"}]}]},
            "streamSettings": build_stream(q, host)}

    u = urllib.parse.urlparse(cfg)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}

    if sc == "vless":
        return {"protocol": "vless", "settings": {"vnext": [{
            "address": u.hostname, "port": u.port,
            "users": [{"id": urllib.parse.unquote(u.username),
                       "encryption": q.get("encryption", "none"),
                       "flow": q.get("flow", "")}]}]},
            "streamSettings": build_stream(q, u.hostname)}

    if sc == "trojan":
        q.setdefault("security", "tls")
        return {"protocol": "trojan", "settings": {"servers": [{
            "address": u.hostname, "port": u.port,
            "password": urllib.parse.unquote(u.username)}]},
            "streamSettings": build_stream(q, u.hostname)}

    if sc == "ss":
        if "plugin" in q:
            raise ValueError("ss plugin unsupported")
        body = cfg[5:].split("#", 1)[0].split("?", 1)[0]
        if "@" in body:
            userinfo, hp = body.rsplit("@", 1)
            try:
                userinfo = b64d(userinfo)
            except Exception:
                pass
            userinfo = urllib.parse.unquote(userinfo)
        else:
            userinfo, hp = b64d(body).rsplit("@", 1)
        method, pw = userinfo.split(":", 1)
        h, p = hp.rsplit(":", 1)
        return {"protocol": "shadowsocks", "settings": {"servers": [{
            "address": h.strip("[]"), "port": int(p), "method": method, "password": pw}]}}

    raise ValueError("unsupported protocol")


# ---------------- تست ----------------
def test_config(cfg):
    """اگه سالم بود پینگ (میلی‌ثانیه) رو برمی‌گردونه، وگرنه None"""
    try:
        out = build_outbound(cfg)
    except Exception as e:
        print("skip (parse):", type(e).__name__, e)
        return None
    port = 21000 + next(PORTS) % 5000
    conf = {"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                          "settings": {"udp": False}}],
            "outbounds": [out]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(conf, f)
        path = f.name
    proc = None
    try:
        proc = subprocess.Popen([XRAY, "run", "-c", path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.time()
        while True:
            if proc.poll() is not None or time.time() - t0 > 4:
                return None
            try:
                socket.create_connection(("127.0.0.1", port), 0.3).close()
                break
            except OSError:
                time.sleep(0.2)
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
             "--socks5-hostname", "127.0.0.1:%d" % port,
             "--max-time", str(TEST_TIMEOUT), TEST_URL],
            capture_output=True, text=True)
        code, _, tm = r.stdout.strip().partition(" ")
        if code in ("200", "204"):
            return max(1, int(float(tm) * 1000))
        return None
    except Exception:
        return None
    finally:
        if proc is not None:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            os.unlink(path)
        except OSError:
            pass


def test_many(cfgs):
    if not cfgs:
        return []
    workers = min(WORKERS, len(cfgs))
    with ThreadPoolExecutor(workers) as ex:
        return list(ex.map(test_config, cfgs))


def stability_test(cfg):
    results = []
    for n in range(STABILITY_TESTS):
        p = test_config(cfg)
        if p:
            results.append(p)
        if n + 1 < STABILITY_TESTS:
            time.sleep(STABILITY_GAP)
    if len(results) / float(STABILITY_TESTS) < MIN_STABILITY:
        return None
    return {
        "avg": int(sum(results) / len(results)),
        "best": min(results),
        "success": len(results),
        "tests": STABILITY_TESTS,
    }


def stability_test_many(cfgs):
    if not cfgs:
        return []
    workers = min(WORKERS, len(cfgs))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(stability_test, cfgs))


def quality_score(avg, success, tests):
    speed = max(0, min(100, 100 - (avg / float(MAX_PING)) * 100))
    stability = (success / float(tests)) * 100
    score = round(speed * 0.65 + stability * 0.35)
    return max(1, min(100, score))


# ---------------- تلگرام ----------------
def tg(method, **params):
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(
        "https://api.telegram.org/bot%s/%s" % (BOT_TOKEN, method), data=data)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {"ok": False, "description": "HTTP %s" % e.code}
    except Exception as e:
        return {"ok": False, "description": type(e).__name__}


FOOTERS = [
    "🔥 سرعت این کانفیگ کم شد؟ اشتراک اختصاصی بگیر، بدون قطعی 👇",
    "⚠️ کانفیگ رایگان ممکنه زود قطع بشه. اشتراک اختصاصی = اتصال پایدار 🔐",
    "🎁 قبل از خرید تست رایگان بگیر، بعد تصمیم بگیر 👇",
    "🔐 اشتراک اختصاصی، تک‌لوکیشن و مولتی‌لوکیشن 👇",
    "🚀 اینترنت پرسرعت و بدون قطعی می‌خوای؟ اینجا کلیک کن",
    "🛡️ فیلترشکن اختصاصی با پشتیبانی ۲۴ ساعته 👇",
]


def footer_line():
    """یک متن تصادفی که خودش لینک خرید است (همان لینک دکمه شیشه‌ای)"""
    return '<a href="%s">%s</a>' % (html.escape(BUY_LINK, quote=True),
                                    html.escape(random.choice(FOOTERS), quote=False))


def build_text(cfg, ping, flag, country, score=0, stability=0, repost=False):
    online_line = "🔵 Online   %s %s\n" % (flag, country) if flag else "🔵 Online\n"
    score_line = "🏆 Quality: %d/100\n" % score if score else ""
    stable_line = "🟢 Stability: %d%%\n" % stability if stability else ""
    repost_line = (REPOST_MARK + "\n") if repost else ""
    return (
        "<blockquote expandable><code>%s</code></blockquote>\n"
        "☝🏻 ضربه بزن تا کپی بشه ☝🏻\n"
        "🛜 کانفیگ ویتوری | V2Ray Configs\n\n"
        "%s"
        "%s"
        "%s"
        "%s"
        "⚡ Response: %dms\n"
        "📱 بهترین اپ: V2BOX\n\n"
        "#V2RAY #رایگان\n\n"
        "%s"
    ) % (html.escape(cfg, quote=False), repost_line, online_line, score_line, stable_line, ping,
         footer_line())


# (متن دکمه, رنگ)  رنگ: primary=آبی، success=سبز، danger=قرمز، None=پیش‌فرض
BUTTONS = [
    ("🎁 تست رایگان ۲۴ ساعته 🇮🇷", "success"),
    ("🛡️ اکانت تست رایگان بگیر", "success"),
    ("🌍 🇨🇦🇹🇷🇺🇸🇩🇪 لوکیشن‌ها رو ببین", "primary"),
    ("⚡ اینترنت بدون قطعی 🚀", "primary"),
    ("🔐 فیلترشکن پرسرعت VIP", "primary"),
    ("🚀 ارتقا به اشتراک VIP", "primary"),
    ("📶 اتصال پایدار، بدون افت", "primary"),
    ("🔓 آزادی اینترنت با یه کلیک", "success"),
    ("🇳🇱🇬🇧 سرور اختصاصی بگیر", None),
    ("⏳ ظرفیت محدوده، الان بگیر", "danger"),
    ("✅ ضمانت بازگشت وجه", None),
    ("💬 پشتیبانی ۲۴ ساعته 🛟", None),
]


def buy_button():
    text, style = random.choice(BUTTONS)
    btn = {"text": text, "url": BUY_LINK}
    if style:
        btn["style"] = style
    return json.dumps({"inline_keyboard": [[btn]]})


# ---------------- وضعیت ----------------
def load_state():
    if not os.path.exists(STATE_FILE):
        st = {}
    else:
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                st = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("state.json is unreadable; refusing to overwrite existing state") from exc
        if not isinstance(st, dict):
            raise RuntimeError("state.json root must be a JSON object")
    st.setdefault("seen", {})
    st.setdefault("queue", [])
    st.setdefault("posted", {})
    st.setdefault("quarantine", {})
    return st


def atomic_json_write(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".k2tmp-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(path):
            try:
                shutil.copy2(path, path + ".bak")
            except OSError as exc:
                print("backup warning:", os.path.basename(path), type(exc).__name__)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass


def save_state(st):
    atomic_json_write(STATE_FILE, st)



def today_str():
    return time.strftime("%Y-%m-%d", time.gmtime())


def roll_stats(st):
    """اگه روز عوض شده باشه، آمار دیروز رو پست می‌کنه و شمارنده‌ها رو صفر می‌کنه"""
    stats = st.setdefault(
        "stats", {"date": today_str(), "fetched": 0, "healthy": 0, "posted": 0, "removed": 0})
    today = today_str()
    if stats["date"] != today:
        if stats["fetched"] or stats["posted"] or stats["removed"]:
            text = (
                "📊 آمار روز %s کانال\n\n"
                "🔎 کانفیگ بررسی‌شده: %d\n"
                "🟢 سالم شناسایی‌شده: %d\n"
                "📮 پست‌شده: %d\n"
                "🗑 حذف‌شده (خراب شده بودن): %d"
            ) % (stats["date"], stats["fetched"], stats["healthy"],
                 stats["posted"], stats["removed"])
            tg("sendMessage", chat_id=TARGET_CHANNEL, text=text)
        stats = {"date": today, "fetched": 0, "healthy": 0, "posted": 0, "removed": 0}
        st["stats"] = stats
    return stats


# ---------------- حالت‌ها ----------------
def mode_post():
    st = load_state()
    apply_settings(st)
    now = time.time()
    seen, queue, posted = st["seen"], st["queue"], st["posted"]
    geo = st.setdefault("geo", {})
    stats = roll_stats(st)

    for k in [k for k, v in seen.items() if now - v > SEEN_TTL]:
        del seen[k]
    queue[:] = [x for x in queue if now - x["ts"] < QUEUE_TTL and x["id"] not in posted]

    new = {}
    cfgs = fetch_configs(st)
    for c in cfgs:
        i = identity(c)
        if i not in seen and i not in posted and i not in new:
            new[i] = c
    print("fetched %d configs, %d new" % (len(cfgs), len(new)))
    stats["fetched"] += min(len(new), MAX_CONFIGS_PER_RUN)

    if new:
        items = list(new.items())[:MAX_CONFIGS_PER_RUN]
        pings = test_many([c for _, c in items])
        eligible = [(i, c) for (i, c), ping in zip(items, pings) if ping and ping <= MAX_PING]
        stable_results = stability_test_many([c for _, c in eligible])
        stable_by_id = {i: result for (i, _), result in zip(eligible, stable_results)}
        for (i, c), ping in zip(items, pings):
            seen[i] = now
            source_names = st.get("_source_map", {}).get(i, [])
            stest = stable_by_id.get(i)
            if stest:
                for source_name in source_names:
                    if source_name in st.get("source_stats", {}):
                        st["source_stats"][source_name]["healthy"] += 1
                    hist = st.setdefault("source_history", {}).setdefault(
                        source_name, {"fetched": 0, "healthy": 0, "failed": 0, "runs": 0})
                    hist["healthy"] = int(hist.get("healthy", 0)) + 1
                score = quality_score(stest["avg"], stest["success"], stest["tests"])
                queue.append({"id": i, "cfg": c, "ping": stest["avg"],
                              "best": stest["best"], "score": score,
                              "stability": round(100 * stest["success"] / stest["tests"]),
                              "ts": now})
                stats["healthy"] += 1
            elif ping and ping <= MAX_PING:
                for source_name in source_names:
                    hist = st.setdefault("source_history", {}).setdefault(
                        source_name, {"fetched": 0, "healthy": 0, "failed": 0, "runs": 0})
                    hist["failed"] = int(hist.get("failed", 0)) + 1
        print("stable configs in queue:", len(queue), "| batch:", len(items))

    queue.sort(key=lambda x: (-x.get("score", 0), x.get("ping", 999999), -x["ts"]))
    posted_this_run = 0
    while queue and posted_this_run < MAX_POSTS_PER_RUN:
        item = queue.pop(0)
        if time.time() - item["ts"] < 120:
            ping = item["ping"]
            score = item.get("score", 0)
            stability = item.get("stability", 0)
        else:
            stest = stability_test(item["cfg"])
            if not stest:
                print("queued config lost stability, dropped")
                continue
            ping = stest["avg"]
            score = quality_score(ping, stest["success"], stest["tests"])
            stability = round(100 * stest["success"] / stest["tests"])
        if not ping or ping > MAX_PING:
            print("queued config too slow, dropped")
            continue
        try:
            host = outbound_host(build_outbound(item["cfg"]))
            if host and not is_cdn_edge(host):
                cc, country = lookup_geo(host, geo)
            else:
                cc, country = "", ""
        except Exception:
            cc, country = "", ""
        named = rename(item["cfg"], REMARK)
        r = tg("sendMessage", chat_id=TARGET_CHANNEL,
               text=build_text(named, ping, country_flag(cc), country, score, stability),
               parse_mode="HTML", disable_web_page_preview="true",
               reply_markup=buy_button())
        if r.get("ok"):
            posted[item["id"]] = {"cfg": named, "msg": r["result"]["message_id"],
                                    "ts": time.time(), "ping": ping, "score": score,
                                    "stability": stability, "country": country, "repost_count": 0}
            stats["posted"] += 1
            posted_this_run += 1
            stats.setdefault("published_scores", []).append(score)
            print("posted, score", score, "response", ping)
        else:
            print("send failed:", r.get("description"))
            queue.insert(0, item)
            break
    if posted_this_run == 0:
        print("no healthy config this round, nothing posted")
    else:
        print("posted this run:", posted_this_run)

    # رکوردهای پست‌شده را بی‌صدا حذف نمی‌کنیم؛ باید تا حذف/آرشیو واقعی قابل پیگیری بمانند.
    st.pop("_source_map", None)
    save_state(st)


def fetch_channel_page():
    """صفحه‌ی پیش‌نمایش عمومی کانال خودمون رو یک بار می‌گیره تا توی یک اجرا بارها دانلود نشه"""
    try:
        return http_get("https://t.me/s/" + TARGET_CHANNEL.lstrip("@"))
    except Exception as e:
        print("channel page fetch failed:", type(e).__name__)
        return None


def channel_post_views(page_html, message_id):
    """بازدید یک پست رو از متنِ از قبل گرفته‌شده‌ی صفحه‌ی کانال می‌خونه.
    فقط وقتی پست واقعاً شامل کانفیگ باشه view برمی‌گردونه؛ پست‌های تبلیغاتی/متنی نادیده گرفته می‌شن.
    """
    if page_html is None:
        return None, False
    try:
        marker = 'data-post="%s/%s"' % (TARGET_CHANNEL.lstrip("@"), message_id)
        pos = page_html.lower().find(marker.lower())
        if pos < 0:
            return None, False
        start = page_html.rfind('<div class="tgme_widget_message_wrap', 0, pos)
        end = page_html.find('<div class="tgme_widget_message_wrap', pos + len(marker))
        block = page_html[start:end if end >= 0 else len(page_html)]
        if not CFG_RE.search(html.unescape(block)):
            return None, False
        m = re.search(r'class="tgme_widget_message_views"[^>]*>([^<]+)<', block)
        if not m:
            m = re.search(r'tgme_widget_message_views[^>]*>([^<]+)<', block)
        if not m:
            return None, True
        raw = m.group(1).strip().replace(' ', '').replace(',', '')
        mult = 1
        if raw.endswith('K'):
            mult = 1000; raw = raw[:-1]
        elif raw.endswith('M'):
            mult = 1000000; raw = raw[:-1]
        views = int(float(raw) * mult)
        return views, True
    except Exception as e:
        print("views parse failed:", type(e).__name__)
        return None, False


def mode_clean():
    st = load_state()
    apply_settings(st)
    stats = roll_stats(st)
    posted = st["posted"]
    items = sorted(posted.items(), key=lambda kv: kv[1].get("last_checked", kv[1].get("ts", 0)))[:MAX_CLEAN_PER_RUN]
    if not items:
        print("nothing to check")
        save_state(st)
        return

    now = time.time()
    low_view = set()
    config_items = []
    page_html = fetch_channel_page()

    # فقط پست‌هایی که واقعاً کانفیگ هستند وارد این چرخه می‌شوند.
    for i, v in items:
        age = now - v.get("ts", now)
        if age < VIEW_GRACE:
            continue
        v["last_checked"] = now
        views, is_config = channel_post_views(page_html, v["msg"])
        if not is_config:
            print("non-config post ignored:", i)
            continue
        config_items.append((i, v, views))
        if views is not None and views < MIN_VIEWS:
            low_view.add(i)
            print("low views candidate:", i, views)

    # تست اول سلامت همه کانفیگ‌های تحت مدیریت ربات
    test_items = [(i, v) for i, v, _ in config_items]
    res = test_many([v["cfg"] for _, v in test_items]) if test_items else []
    first_bad = {i for (i, _), p in zip(test_items, res) if not p}
    print("failed first test %d of %d" % (len(first_bad), len(test_items)))

    if test_items and len(test_items) >= 5 and len(first_bad) > 0.8 * len(test_items):
        print("too many failures, test environment suspected; skipping deletion/repost")
        save_state(st)
        return

    # کانفیگ خراب با هر تعداد بازدید باید تست دوم شود؛
    # کانفیگ کم‌بازدید سالم هم حتماً یک تست تازه می‌گیرد تا بعد از تأیید دوباره بازنشر شود.
    need_second = first_bad | low_view
    second_bad = set()
    if need_second:
        second_items = [(i, posted[i]) for i in need_second if i in posted]
        time.sleep(2)
        res2 = test_many([v["cfg"] for _, v in second_items])
        second_bad = {i for (i, _), p in zip(second_items, res2) if not p}

    # وضعیت نهایی سلامت: اگر تست دوم انجام شده، نتیجه تست دوم ملاک است؛
    # در غیر این صورت نتیجه تست اول.
    final_bad = set()
    for i, _ in test_items:
        final_bad.add(i) if ((i in second_bad) if i in need_second else (i in first_bad)) else None

    # قرنطینه: خرابی باید در دو نوبت پاک‌سازی جداگانه تأیید شود.
    quarantine = st.setdefault("quarantine", {})
    for i, _ in test_items:
        if i in final_bad:
            entry = quarantine.get(i)
            if not entry:
                quarantine[i] = {"first_seen": now, "last_failed": now}
                final_bad.discard(i)
                low_view.discard(i)
                print("quarantined after failed tests:", i)
            elif now - float(entry.get("first_seen", now)) < QUARANTINE_SECONDS:
                entry["last_failed"] = now
                final_bad.discard(i)
                low_view.discard(i)
                print("still quarantined; waiting for confirmation:", i)
            else:
                entry["last_failed"] = now
        else:
            quarantine.pop(i, None)

    removed = 0
    reposted = 0

    for i, v, views in config_items:
        if i not in posted:
            continue

        # خراب باشد، بدون توجه به تعداد بازدید حذف می‌شود.
        if i in final_bad:
            msg = posted[i]["msg"]
            r = tg("deleteMessage", chat_id=TARGET_CHANNEL, message_id=msg)
            if not r.get("ok"):
                print("delete failed:", r.get("description"))
                r = tg("editMessageText", chat_id=TARGET_CHANNEL, message_id=msg,
                       text="⛔️ این کانفیگ منقضی شد")
            if r.get("ok"):
                del posted[i]
                quarantine.pop(i, None)
                stats["removed"] += 1
                removed += 1
            time.sleep(0.5)
            continue

        # کم‌بازدید + سالم در تست مجدد => یک بار بازنشر شود.
        if i in low_view:
            repost_count = int(v.get("repost_count", 0))
            if repost_count >= REPOST_MAX:
                msg = posted[i]["msg"]
                r = tg("deleteMessage", chat_id=TARGET_CHANNEL, message_id=msg)
                if not r.get("ok"):
                    r = tg("editMessageText", chat_id=TARGET_CHANNEL, message_id=msg,
                           text="⛔️ این کانفیگ بازدید کافی نگرفت")
                if r.get("ok"):
                    del posted[i]
                    stats["removed"] += 1
                    removed += 1
                time.sleep(0.5)
                continue

            # Ping تست دوم را برای بازنشر دوباره به دست می‌آوریم.
            ping = test_config(v["cfg"])
            if not ping:
                # احتیاط مضاعف؛ اگر اینجا هم خراب شد، حذفش کن.
                msg = posted[i]["msg"]
                r = tg("deleteMessage", chat_id=TARGET_CHANNEL, message_id=msg)
                if r.get("ok"):
                    del posted[i]
                    stats["removed"] += 1
                    removed += 1
                continue

            # اول پست قبلی را حذف می‌کنیم تا بازنشر باعث دو نسخه همزمان نشود.
            old_msg = v["msg"]
            rdel = tg("deleteMessage", chat_id=TARGET_CHANNEL, message_id=old_msg)
            if not rdel.get("ok"):
                print("repost skipped; old message could not be deleted:", rdel.get("description"))
                continue

            try:
                host = outbound_host(build_outbound(v["cfg"]))
                if host and not is_cdn_edge(host):
                    cc, country = lookup_geo(host, st.setdefault("geo", {}))
                else:
                    cc, country = "", ""
            except Exception:
                cc, country = "", ""

            rpost = tg(
                "sendMessage", chat_id=TARGET_CHANNEL,
                text=build_text(v["cfg"], ping, country_flag(cc), country,
                                 v.get("score") or quality_score(ping, 100, 100),
                                 v.get("stability") or 100, repost=True),
                parse_mode="HTML", disable_web_page_preview="true",
                reply_markup=buy_button()
            )
            if rpost.get("ok"):
                posted[i] = {
                    "cfg": v["cfg"],
                    "msg": rpost["result"]["message_id"],
                    "ts": time.time(),
                    "repost_count": repost_count + 1,
                }
                reposted += 1
                stats["posted"] += 1
                print("reposted low-view healthy config:", i, "ping", ping)
            else:
                # اگر ارسال جدید شکست خورد، رکورد قبلی را نگه نمی‌داریم چون پیام قبلی حذف شده.
                posted.pop(i, None)
                print("repost send failed:", rpost.get("description"))
            time.sleep(0.5)

    print("removed", removed, "reposted", reposted)
    save_state(st)


# ---------------- پنل مدیریت تلگرام (بدون سرور جدا) ----------------
def admin_tg(method, **params):
    """API تلگرام با توکن جداگانه پنل مدیریت تا با webhook ربات اصلی تداخل نکند."""
    if not ADMIN_BOT_TOKEN:
        return {"ok": False, "description": "ADMIN_BOT_TOKEN missing"}
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(
        "https://api.telegram.org/bot%s/%s" % (ADMIN_BOT_TOKEN, method), data=data)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {"ok": False, "description": "HTTP %s" % e.code}
    except Exception as e:
        return {"ok": False, "description": type(e).__name__}


def apply_settings(st):
    """اعمال تنظیمات ذخیره‌شده از state.json روی مقادیر اجرایی."""
    global MIN_VIEWS, MAX_PING, MAX_POSTS_PER_RUN
    cfg = st.setdefault("admin_settings", {})
    MIN_VIEWS = max(0, min(100000, int(cfg.get("min_views", MIN_VIEWS))))
    MAX_PING = max(100, min(30000, int(cfg.get("max_ping", MAX_PING))))
    MAX_POSTS_PER_RUN = max(1, min(10, int(cfg.get("max_posts_per_run", MAX_POSTS_PER_RUN))))


def source_admin_text(st):
    data = load_sources()
    stats = st.get("source_stats", {})
    lines = ["📡 منابع دریافت کانفیگ", ""]
    for item in data["sources"]:
        state = "فعال" if item.get("enabled", True) else "خاموش"
        stat = stats.get(item["name"], {})
        hist = st.get("source_history", {}).get(item["name"], {})
        lines.append("• %s | %s | %s | دریافت اخیر: %s | سالم کل: %s" % (
            item["name"], item["type"], state, stat.get("fetched", "—"), hist.get("healthy", 0)))
    lines.extend(["", "افزودن: /source_add telegram CHANNEL", "/source_add github NAME HTTPS_URL",
                  "/source_add subscription NAME HTTPS_URL", "/source_add txt NAME HTTPS_URL",
                  "/source_add api NAME HTTPS_URL", "فعال/خاموش: /source_toggle NAME",
                  "حذف: /source_del NAME"])
    return "\n".join(lines)


def handle_source_command(text):
    parts = text.strip().split(maxsplit=3)
    if len(parts) < 2:
        return "فرمت دستور ناقص است. /sources را ببین."
    action = parts[0].lower()
    data = load_sources()
    items = data["sources"]
    if action == "/source_add":
        if len(parts) == 3 and parts[1].lower() == "telegram":
            kind, name, url = "telegram", parts[2].lstrip("@"), ""
        elif len(parts) == 4:
            kind, name, url = parts[1].lower(), parts[2], parts[3]
        else:
            return "فرمت: /source_add TYPE NAME URL (برای تلگرام: /source_add telegram CHANNEL)"
        if kind not in SOURCE_TYPES:
            return "نوع منبع نامعتبر است."
        if any(x["name"].lower() == name.lower() for x in items):
            return "این نام منبع قبلاً ثبت شده است."
        item = {"name": name, "type": kind, "enabled": True, "priority": 5}
        if kind == "telegram":
            channel = name
            if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", channel):
                return "نام کانال تلگرام معتبر نیست."
            item["channel"] = channel
        else:
            try:
                validate_public_url(url)
            except Exception as exc:
                return "URL رد شد: %s" % str(exc)
            item["url"] = url
        items.append(item)
        save_sources(data)
        return "✅ منبع %s اضافه شد و فعال است." % name
    if action in ("/source_toggle", "/source_del"):
        name = parts[1]
        found = next((x for x in items if x["name"].lower() == name.lower()), None)
        if not found:
            return "منبع پیدا نشد."
        if action == "/source_del":
            data["sources"] = [x for x in items if x is not found]
            save_sources(data)
            return "🗑 منبع حذف شد: %s" % name
        found["enabled"] = not found.get("enabled", True)
        save_sources(data)
        return "وضعیت %s: %s" % (name, "فعال" if found["enabled"] else "خاموش")
    return "دستور منبع ناشناخته است."


def admin_menu(st, message="پنل مدیریت K2 Guard"):
    auto = st.get("auto_enabled", True)
    mark = "🟢 روشن" if auto else "🔴 خاموش"
    keyboard = {"inline_keyboard": [
        [{"text": "🚀 اجرای انتشار همین الان", "callback_data": "act:post"}],
        [{"text": "🧹 اجرای پاک‌سازی همین الان", "callback_data": "act:clean"}],
        [{"text": "⏯ اجرای خودکار: " + mark, "callback_data": "toggle:auto"}],
        [{"text": "📊 آمار", "callback_data": "view:stats"},
         {"text": "ℹ️ وضعیت", "callback_data": "view:status"}],
        [{"text": "⚙️ تنظیمات", "callback_data": "view:settings"}],
        [{"text": "📡 منابع دریافت", "callback_data": "view:sources"}],
    ]}
    return admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text=message,
              reply_markup=json.dumps(keyboard, ensure_ascii=False))


def settings_menu(st):
    cfg = st.setdefault("admin_settings", {})
    apply_settings(st)
    keyboard = {"inline_keyboard": [
        [{"text": "بازدید حداقل: %s  −50" % MIN_VIEWS, "callback_data": "set:min_views:-50"},
         {"text": "+50", "callback_data": "set:min_views:50"}],
        [{"text": "حداکثر پینگ: %sms  −500" % MAX_PING, "callback_data": "set:max_ping:-500"},
         {"text": "+500", "callback_data": "set:max_ping:500"}],
        [{"text": "تعداد انتشار: %s  −1" % MAX_POSTS_PER_RUN, "callback_data": "set:max_posts_per_run:-1"},
         {"text": "+1", "callback_data": "set:max_posts_per_run:1"}],
        [{"text": "⬅️ منوی اصلی", "callback_data": "view:menu"}],
    ]}
    return admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID,
              text="⚙️ تنظیمات فعلی\n\nبازدید حداقل: %d\nحداکثر پینگ: %d ms\nحداکثر انتشار در هر اجرا: %d" %
                   (MIN_VIEWS, MAX_PING, MAX_POSTS_PER_RUN),
              reply_markup=json.dumps(keyboard, ensure_ascii=False))


def admin_stats(st):
    stats = st.get("stats", {})
    posted = st.get("posted", {})
    queue = st.get("queue", [])
    return ("📊 آمار K2 Guard\n\n"
            "📅 روز آمار: %s\n"
            "🔎 کانفیگ‌های بررسی‌شده: %s\n"
            "🟢 سالم شناسایی‌شده: %s\n"
            "📮 منتشرشده: %s\n"
            "🗑 حذف‌شده: %s\n"
            "📌 کانفیگ‌های تحت مدیریت: %d\n"
            "⏳ در صف انتشار: %d") % (
                stats.get("date", "هنوز ثبت نشده"), stats.get("fetched", 0),
                stats.get("healthy", 0), stats.get("posted", 0),
                stats.get("removed", 0), len(posted), len(queue))


def admin_status(st):
    auto = "روشن 🟢" if st.get("auto_enabled", True) else "خاموش 🔴"
    last_post = st.get("last_auto_post")
    last_clean = st.get("last_auto_clean")
    def fmt(ts):
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "هنوز اجرا نشده"
    return ("ℹ️ وضعیت ربات\n\n"
            "اجرای خودکار: %s\n"
            "آخرین اجرای خودکار انتشار: %s\n"
            "آخرین اجرای خودکار پاک‌سازی: %s\n\n"
            "نکته: در حالت GitHub Actions، پردازش فرمان‌های تلگرام معمولاً با تأخیر تا حدود ۱۵ دقیقه انجام می‌شود.") % (auto, fmt(last_post), fmt(last_clean))


def process_admin_updates(st):
    """به‌صورت کوتاه Updates را می‌خواند؛ فراخوانی بعدی با workflow زمان‌بندی‌شده است."""
    if not ADMIN_CHAT_ID or not ADMIN_BOT_TOKEN:
        print("ADMIN_CHAT_ID or ADMIN_BOT_TOKEN missing; Telegram admin panel disabled")
        return []
    try:
        offset = int(st.get("telegram_update_offset", 0))
        result = admin_tg("getUpdates", offset=offset, timeout=0,
                    allowed_updates=json.dumps(["message", "callback_query"]))
        if not result.get("ok"):
            print("getUpdates failed:", result.get("description"))
            return []
        updates = result.get("result", [])
    except Exception as exc:
        print("update polling failed:", type(exc).__name__)
        return []

    actions = []
    for update in updates:
        st["telegram_update_offset"] = int(update.get("update_id", 0)) + 1
        msg = update.get("message") or {}
        cb = update.get("callback_query") or {}
        user = msg.get("from") or cb.get("from") or {}
        chat = msg.get("chat") or (cb.get("message") or {}).get("chat") or {}
        # فقط مدیر تعیین‌شده و چت خصوصی مجاز است.
        if str(user.get("id", "")) != ADMIN_CHAT_ID or str(chat.get("id", "")) != ADMIN_CHAT_ID:
            if cb.get("id"):
                admin_tg("answerCallbackQuery", callback_query_id=cb["id"], text="دسترسی غیرمجاز")
            continue

        if msg:
            command = (msg.get("text") or "").strip().split()[0].lower() if (msg.get("text") or "").strip() else ""
            if command in ("/start", "/panel", "/menu"):
                admin_menu(st, "🛡️ پنل مدیریت K2 Guard\nیکی از عملیات زیر را انتخاب کن:")
            elif command == "/stats":
                admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text=admin_stats(st))
            elif command == "/status":
                admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text=admin_status(st))
            elif command == "/sources":
                admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text=source_admin_text(st))
            elif command in ("/source_add", "/source_toggle", "/source_del"):
                answer = handle_source_command((msg.get("text") or "").strip())
                admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text=answer)
            continue

        if not cb:
            continue
        data = cb.get("data", "")
        admin_tg("answerCallbackQuery", callback_query_id=cb.get("id", ""), text="درخواست دریافت شد")
        if data == "toggle:auto":
            st["auto_enabled"] = not st.get("auto_enabled", True)
            admin_menu(st, "وضعیت اجرای خودکار: " + ("روشن 🟢" if st["auto_enabled"] else "خاموش 🔴") + "\nاجرای دستی همچنان فعال است.")
        elif data == "act:post":
            actions.append("post")
            admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text="🚀 درخواست انتشار ثبت شد؛ نتیجه پس از پایان اجرا در گزارش Workflow قابل بررسی است.")
        elif data == "act:clean":
            actions.append("clean")
            admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text="🧹 درخواست پاک‌سازی ثبت شد؛ نتیجه پس از پایان اجرا در گزارش Workflow قابل بررسی است.")
        elif data == "view:stats":
            admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text=admin_stats(st))
        elif data == "view:status":
            admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text=admin_status(st))
        elif data == "view:settings":
            settings_menu(st)
        elif data == "view:sources":
            admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text=source_admin_text(st))
        elif data == "view:menu":
            admin_menu(st)
        elif data.startswith("set:"):
            try:
                _, key, delta = data.split(":", 2)
                cfg = st.setdefault("admin_settings", {})
                defaults = {"min_views": MIN_VIEWS, "max_ping": MAX_PING,
                            "max_posts_per_run": MAX_POSTS_PER_RUN}
                limits = {"min_views": (0, 100000), "max_ping": (100, 30000),
                          "max_posts_per_run": (1, 10)}
                if key in defaults:
                    lo, hi = limits[key]
                    current = int(cfg.get(key, defaults[key]))
                    cfg[key] = max(lo, min(hi, current + int(delta)))
                    apply_settings(st)
                    settings_menu(st)
            except (ValueError, TypeError):
                admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID, text="خطا در تغییر تنظیمات")
    save_state(st)
    return actions


def mode_worker():
    """Worker زمان‌بندی‌شده: فرمان‌های تلگرام + اجرای خودکار در صورت روشن بودن."""
    st = load_state()
    st.setdefault("auto_enabled", True)
    now = time.time()
    # اولین worker انتشار را انجام می‌دهد؛ پاک‌سازی از چرخه‌ی بعدی ۶ ساعته آغاز می‌شود.
    st.setdefault("last_auto_post", now - POST_INTERVAL)
    st.setdefault("last_auto_clean", now)
    actions = process_admin_updates(st)
    st = load_state()  # process_admin_updates ممکن است تنظیمات/offset را ذخیره کرده باشد
    apply_settings(st)

    # اجرای دستی حتی وقتی auto_enabled خاموش است، مجاز می‌ماند.
    for action in actions:
        before = load_state()
        before_stats = before.get("stats", {})
        before_posted = int(before_stats.get("posted", 0))
        before_removed = int(before_stats.get("removed", 0))
        if action == "post":
            mode_post()
            after = load_state()
            if after.get("auto_enabled", True):
                after["last_auto_post"] = time.time()
                save_state(after)
                after = load_state()
            delta = int(after.get("stats", {}).get("posted", 0)) - before_posted
            admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID,
               text="✅ اجرای انتشار تمام شد.\nتعداد انتشار ثبت‌شده در این اجرا: %d" % max(0, delta))
        elif action == "clean":
            mode_clean()
            after = load_state()
            if after.get("auto_enabled", True):
                after["last_auto_clean"] = time.time()
                save_state(after)
                after = load_state()
            delta = int(after.get("stats", {}).get("removed", 0)) - before_removed
            admin_tg("sendMessage", chat_id=ADMIN_CHAT_ID,
               text="✅ پاک‌سازی تمام شد.\nتعداد حذف ثبت‌شده در این اجرا: %d" % max(0, delta))

    st = load_state()
    now = time.time()
    if st.get("auto_enabled", True):
        if "post" not in actions and now - float(st.get("last_auto_post", 0)) >= POST_INTERVAL:
            st["last_auto_post"] = now
            save_state(st)
            print("automatic post run")
            mode_post()
        st = load_state()
        now = time.time()
        if "clean" not in actions and now - float(st.get("last_auto_clean", now)) >= CLEAN_INTERVAL:
            st["last_auto_clean"] = now
            save_state(st)
            print("automatic clean run")
            mode_clean()
    save_state(load_state())


if __name__ == "__main__":
    if not BOT_TOKEN:
        sys.exit("BOT_TOKEN is missing (add it in repo Settings > Secrets)")
    # فایل منابع در اولین اجرا با منبع فعلی ساخته می‌شود؛ فایل خراب بی‌صدا بازنویسی نمی‌شود.
    if not os.path.exists(SOURCES_FILE):
        save_sources(default_sources())
    load_sources()
    mode = sys.argv[1] if len(sys.argv) > 1 else "post"
    if mode == "clean":
        mode_clean()
    elif mode == "worker":
        mode_worker()
    else:
        mode_post()
