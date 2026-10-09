#!/usr/bin/env python3
"""پاکسازی یک‌باره‌ی راه‌اندازی: پست‌های کانفیگِ ۱۵ روز اخیر کانال رو می‌خونه،
هر کانفیگ رو تا ۳ بار تست می‌کنه. اگه سالم بود (حداقل ۲ از ۳ تست) و بازدید
پستش >= MIN_VIEWS بود نگهش می‌داره، وگرنه حذفش می‌کنه. در پایان یک پیام
آماری می‌فرسته. این اسکریپت فقط یک‌بار کار می‌کنه: بعد از اجرای موفق یک
پرچم توی state.json ذخیره می‌شه و اجرای بعدی بدون انجام کاری خارج می‌شه.
اجرا: python startup_cleanup.py
این فایل باید کنار bot.py باشه (توابعش رو از اونجا قرض می‌گیره).
"""
import calendar
import html
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import bot

DAYS = 15
WINDOW = DAYS * 86400
MIN_VIEWS = 100
TESTS_PER_CONFIG = 3
MIN_PASS = 2
MAX_PAGES = 120          # سقف صفحات پیش‌نمایش برای جلوگیری از حلقه‌ی بی‌پایان
FLAG_KEY = "once_cleanup_15d_done"


def fetch_page(before=None):
    url = "https://t.me/s/" + bot.TARGET_CHANNEL.lstrip("@")
    if before:
        url += "?before=%d" % before
    try:
        return bot.http_get(url)
    except Exception as e:
        print("page fetch failed:", type(e).__name__)
        return None


def parse_messages(page_html):
    """لیست (msg_id, epoch_utc_or_None, block_html) رو برمی‌گردونه"""
    chan = re.escape(bot.TARGET_CHANNEL.lstrip("@"))
    out = []
    for m in re.finditer(r'data-post="%s/(\d+)"' % chan, page_html):
        mid = int(m.group(1))
        pos = m.start()
        start = page_html.rfind('<div class="tgme_widget_message_wrap', 0, pos)
        end = page_html.find('<div class="tgme_widget_message_wrap', pos + 1)
        if start < 0:
            start = pos
        block = page_html[start:end if end >= 0 else len(page_html)]
        ts = None
        dm = re.search(r'<time[^>]*datetime="([^"]+)"', block)
        if dm:
            try:
                ts = calendar.timegm(time.strptime(dm.group(1)[:19], "%Y-%m-%dT%H:%M:%S"))
            except Exception:
                ts = None
        out.append((mid, ts, block))
    return out


def extract_config(block):
    text = html.unescape(re.sub(r"<[^>]+>", " ", block))
    m = bot.CFG_RE.search(text)
    return m.group(0).rstrip(".,;،") if m else None


def extract_views(block):
    m = re.search(r'class="tgme_widget_message_views"[^>]*>([^<]+)<', block)
    if not m:
        return None
    raw = m.group(1).strip().replace(" ", "").replace(",", "")
    mult = 1
    if raw.endswith("K"):
        mult, raw = 1000, raw[:-1]
    elif raw.endswith("M"):
        mult, raw = 1000000, raw[:-1]
    try:
        return int(float(raw) * mult)
    except ValueError:
        return None


def collect_recent_messages():
    """با ورق‌زدن صفحات قدیمی‌تر، پیام‌های ۱۵ روز اخیر رو جمع می‌کنه"""
    cutoff = time.time() - WINDOW
    seen_ids = set()
    messages = []
    before = None
    for page_num in range(MAX_PAGES):
        page = fetch_page(before)
        if not page:
            break
        batch = parse_messages(page)
        if not batch:
            break
        new_in_batch = [mid for mid, _, _ in batch if mid not in seen_ids]
        if not new_in_batch:
            break
        hit_cutoff = False
        for mid, ts, block in batch:
            if mid in seen_ids:
                continue
            seen_ids.add(mid)
            if ts is not None and ts < cutoff:
                hit_cutoff = True
                continue
            messages.append((mid, ts, block))
        print("page %d: +%d messages (total %d)" % (page_num, len(new_in_batch), len(messages)))
        if hit_cutoff:
            break
        before = min(mid for mid, _, _ in batch)
        time.sleep(1)
    return messages


def check_healthy(cfg):
    """یه بار سریع تست می‌کنه؛ اگه زنده بود، تا ۲ بار دیگه هم تست می‌کنه"""
    if not bot.test_config(cfg):
        return False
    ok = 1
    for _ in range(TESTS_PER_CONFIG - 1):
        if bot.test_config(cfg):
            ok += 1
    return ok >= MIN_PASS


def test_all(cfgs):
    if not cfgs:
        return []
    with ThreadPoolExecutor(min(bot.WORKERS, len(cfgs))) as ex:
        return list(ex.map(check_healthy, cfgs))


def main():
    st = bot.load_state()
    if st.get(FLAG_KEY):
        print("already done once before, skipping")
        return

    messages = collect_recent_messages()
    print("fetched %d messages from the last %d days" % (len(messages), DAYS))

    configs = []
    for mid, ts, block in messages:
        cfg = extract_config(block)
        if not cfg:
            continue
        configs.append({"msg": mid, "cfg": cfg, "views": extract_views(block)})
    print("of which %d are config posts" % len(configs))

    healthy_flags = test_all([c["cfg"] for c in configs])

    kept = removed = 0
    for item, healthy in zip(configs, healthy_flags):
        enough_views = (item["views"] or 0) >= MIN_VIEWS
        if healthy and enough_views:
            kept += 1
            continue
        r = bot.tg("deleteMessage", chat_id=bot.TARGET_CHANNEL, message_id=item["msg"])
        if not r.get("ok"):
            r = bot.tg("editMessageText", chat_id=bot.TARGET_CHANNEL, message_id=item["msg"],
                       text="⛔️ این کانفیگ منقضی شد")
        if r.get("ok"):
            removed += 1
        time.sleep(0.5)

    summary = (
        "🧹 پاکسازی اولیه‌ی کانال انجام شد\n\n"
        "🔎 پست کانفیگ بررسی‌شده (۱۵ روز اخیر): %d\n"
        "🟢 نگه‌داشته‌شده (سالم + بازدید ≥ %d): %d\n"
        "🗑 حذف‌شده: %d\n\n"
        "از این به بعد کانال طبق روال عادی به‌روزرسانی می‌شه."
    ) % (len(configs), MIN_VIEWS, kept, removed)
    bot.tg("sendMessage", chat_id=bot.TARGET_CHANNEL, text=summary)

    st[FLAG_KEY] = True
    bot.save_state(st)
    print("done. kept %d, removed %d" % (kept, removed))


if __name__ == "__main__":
    if not bot.BOT_TOKEN:
        sys.exit("BOT_TOKEN is missing")
    main()
