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
MAX_POSTS_PER_RUN = 3
STABILITY_TESTS = 3
STABILITY_GAP = 0.35
MIN_STABILITY = 0.67
GEO_TTL = 7 * 86400      # کشور هر سرور تا ۷ روز دوباره لوکیشن‌یابی نمی‌شه
STATE_FILE = "state.json"
# ========================================================

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
XRAY = os.path.abspath("xray")
PORTS = itertools.count()
CFG_RE = re.compile(r"(?<![A-Za-z0-9])(?:vmess|vless|trojan|ss)://[^\s<>\"']+")


# ---------------- کمکی‌ها ----------------
def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


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
            base = "vmess:" + json.dumps(o, sort_keys=True)
        else:
            base = cfg.split("#", 1)[0]
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


# ---------------- دریافت کانفیگ‌ها ----------------
def fetch_configs():
    found = []
    for ch in SOURCE_CHANNELS:
        try:
            page = http_get("https://t.me/s/" + ch.lstrip("@"))
        except Exception as e:
            print("fetch failed:", ch, e)
            continue
        blocks = re.findall(
            r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', page, re.S)
        if not blocks:
            print("no visible posts for", ch, "(channel may have web preview disabled)")
        for b in blocks[-LAST_POSTS:]:
            t = re.sub(r"<br\s*/?>", "\n", b)
            t = html.unescape(re.sub(r"<[^>]+>", "", t))
            for m in CFG_RE.finditer(t):
                found.append(m.group(0).rstrip(".,;،"))
    return found


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
    proc = subprocess.Popen([XRAY, "run", "-c", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
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
        proc.kill()
        proc.wait()
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
        "♒ تهیه اشتراک اختصاصی تک‌لوکیشن و مولتی‌لوکیشن با ضمانت تا آخرین مگابایت"
    ) % (html.escape(cfg, quote=False), repost_line, online_line, score_line, stable_line, ping)


BUTTON_TEXTS = [
    "دریافت اکانت تست رایگان 🛡️ 🇨🇦🇮🇷🇱🇷🇵🇸🇹🇷🇺🇸 🛡️",
    "⚡️ همین الان اشتراک بگیر، قبل از تموم شدن ظرفیت",
    "🎁 تست ۲۴ ساعته رایگان، بدون نیاز به کارت",
    "🔥 پرسرعت‌ترین لوکیشن‌ها اینجان، کلیک کن",
    "✅ تضمین بازگشت وجه تا آخرین مگابایت، ثبت‌نام",
    "🚀 ارتقا به اشتراک VIP با تخفیف ویژه اعضا",
    "💬 سوال داری؟ پشتیبانی ۲۴ ساعته همین‌جاست",
]


def buy_button():
    text = random.choice(BUTTON_TEXTS)
    return json.dumps({"inline_keyboard": [[{"text": text, "url": BUY_LINK}]]})


# ---------------- وضعیت ----------------
def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            st = json.load(f)
    except Exception:
        st = {}
    st.setdefault("seen", {})
    st.setdefault("queue", [])
    st.setdefault("posted", {})
    return st


def save_state(st):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)


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
    now = time.time()
    seen, queue, posted = st["seen"], st["queue"], st["posted"]
    geo = st.setdefault("geo", {})
    stats = roll_stats(st)

    for k in [k for k, v in seen.items() if now - v > SEEN_TTL]:
        del seen[k]
    queue[:] = [x for x in queue if now - x["ts"] < QUEUE_TTL and x["id"] not in posted]

    new = {}
    cfgs = fetch_configs()
    for c in cfgs:
        i = identity(c)
        if i not in seen and i not in posted and i not in new:
            new[i] = c
    print("fetched %d configs, %d new" % (len(cfgs), len(new)))
    stats["fetched"] += len(new)

    if new:
        items = list(new.items())
        for (i, c), ping in zip(items, test_many([c for _, c in items])):
            seen[i] = now
            if ping and ping <= MAX_PING:
                stest = stability_test(c)
                if stest:
                    score = quality_score(stest["avg"], stest["success"], stest["tests"])
                    queue.append({"id": i, "cfg": c, "ping": stest["avg"],
                                  "best": stest["best"], "score": score,
                                  "stability": round(100 * stest["success"] / stest["tests"]),
                                  "ts": now})
                    stats["healthy"] += 1
        print("stable configs in queue:", len(queue))

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

    if len(posted) > MAX_POSTED:
        drop = sorted(posted, key=lambda k: posted[k].get("ts", 0))[:len(posted) - MAX_POSTED]
        for k in drop:
            del posted[k]

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
        pos = page_html.find(marker)
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
    stats = roll_stats(st)
    posted = st["posted"]
    items = list(posted.items())
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


if __name__ == "__main__":
    if not BOT_TOKEN:
        sys.exit("BOT_TOKEN is missing (add it in repo Settings > Secrets)")
    mode = sys.argv[1] if len(sys.argv) > 1 else "post"
    (mode_clean if mode == "clean" else mode_post)()
