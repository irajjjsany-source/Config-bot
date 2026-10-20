#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
پاک‌سازی یک‌باره‌ی تمام پست‌های کانفیگ کانال تلگرام.

- همه‌ی پست‌هایی که در متنشان کانفیگ قابل‌شناسایی با bot.CFG_RE وجود دارد حذف می‌شوند،
  بدون توجه به نوع کانفیگ، سالم/خراب بودن یا تعداد بازدید.
- پست‌های غیرکانفیگی دست‌نخورده می‌مانند.
- فقط یک‌بار اجرا می‌شود؛ پس از اجرای کامل و موفق، وضعیت در state.json ثبت می‌شود.

این فایل را کنار bot.py قرار دهید و اجرا کنید:
    python cleanup_all_configs_once.py

پیش‌نیاز: bot.py باید TARGET_CHANNEL، CFG_RE، BOT_TOKEN، load_state،
save_state، http_get و tg را تعریف کرده باشد.
"""
import html
import re
import sys
import time

import bot

FLAG_KEY = "once_delete_all_config_posts_done"
MAX_PAGES = 500
PAGE_DELAY_SECONDS = 1
DELETE_DELAY_SECONDS = 0.4


def fetch_page(before=None):
    """دریافت صفحه‌ی عمومی کانال تلگرام."""
    url = "https://t.me/s/" + bot.TARGET_CHANNEL.lstrip("@")
    if before is not None:
        url += "?before=%d" % before
    try:
        return bot.http_get(url)
    except Exception as exc:
        print("خطا در دریافت صفحه:", type(exc).__name__, str(exc))
        return None


def parse_messages(page_html):
    """پیام‌ها را به شکل (شناسه، بلوک HTML) استخراج می‌کند."""
    channel = re.escape(bot.TARGET_CHANNEL.lstrip("@"))
    results = []
    for match in re.finditer(
        r'data-post="%s/(\d+)"' % channel, page_html, re.IGNORECASE
    ):
        message_id = int(match.group(1))
        pos = match.start()
        start = page_html.rfind(
            '<div class="tgme_widget_message_wrap', 0, pos
        )
        end = page_html.find(
            '<div class="tgme_widget_message_wrap', pos + 1
        )
        if start < 0:
            start = pos
        block = page_html[start:end if end >= 0 else len(page_html)]
        results.append((message_id, block))
    return results


def extract_config(block):
    """
    کانفیگ را با الگوی bot.py یا پیشوندهای رایج پروتکل‌های کانفیگ تشخیص می‌دهد.
    عمداً لینک‌های https عادی به‌تنهایی کانفیگ حساب نمی‌شوند تا پست‌های معمولی
    که فقط لینک سایت دارند حذف نشوند.
    """
    plain_text = html.unescape(re.sub(r"<[^>]+>", " ", block))
    try:
        match = bot.CFG_RE.search(plain_text)
    except Exception as exc:
        raise RuntimeError("اجرای CFG_RE در bot.py ناموفق بود") from exc
    if match:
        return match.group(0).rstrip(".,;،")

    common_schemes = re.compile(
        r"(?i)\b(?:vmess|vless|trojan|ss|ssr|socks|socks5|"
        r"hysteria|hysteria2|hy2|tuic|wireguard|brook|naive)://[^\s<>\"']+"
    )
    match = common_schemes.search(plain_text)
    return match.group(0).rstrip(".,;،)") if match else None


def main():
    if not getattr(bot, "BOT_TOKEN", None):
        sys.exit("خطا: BOT_TOKEN در bot.py تنظیم نشده است.")
    if not getattr(bot, "TARGET_CHANNEL", None):
        sys.exit("خطا: TARGET_CHANNEL در bot.py تنظیم نشده است.")
    if not hasattr(bot, "CFG_RE"):
        sys.exit("خطا: CFG_RE در bot.py پیدا نشد.")

    state = bot.load_state()
    if state.get(FLAG_KEY):
        print("این پاک‌سازی قبلاً اجرا شده؛ برای جلوگیری از حذف دوباره متوقف شد.")
        return

    print("در حال جمع‌آوری پست‌های کانال؛ هنوز چیزی حذف نشده است...")
    seen = set()
    candidates = []
    before = None
    complete_scan = False
    pages_scanned = 0

    for page_num in range(MAX_PAGES):
        page = fetch_page(before)
        if page is None:
            print("خطا: دریافت صفحه ناموفق بود؛ پاک‌سازی لغو شد و چیزی حذف نشد.")
            return

        batch = parse_messages(page)
        if not batch:
            if pages_scanned > 0:
                complete_scan = True
                break
            print("خطا: صفحه‌ی اول پیام قابل‌خواندن ندارد؛ پاک‌سازی لغو شد.")
            return

        new_ids = [mid for mid, _ in batch if mid not in seen]
        if not new_ids:
            print("به شناسه‌ی جدیدی نرسیدیم؛ اسکن کامل تشخیص داده نشد و حذف لغو شد.")
            return

        for message_id, block in batch:
            if message_id in seen:
                continue
            seen.add(message_id)
            try:
                config = extract_config(block)
            except Exception as exc:
                print("خطا در تشخیص کانفیگ؛ حذف لغو شد:", exc)
                return
            if config:
                candidates.append(message_id)

        pages_scanned += 1
        print(
            "صفحه %d: %d پیام جدید، %d پست کانفیگ تا اینجا"
            % (page_num + 1, len(new_ids), len(candidates))
        )

        # صفحه‌ی عمومی معمولاً پیام‌ها را از جدید به قدیم می‌دهد.
        oldest_id = min(mid for mid, _ in batch)
        if len(new_ids) < len(batch):
            print("صفحه‌بندی به پیام‌های تکراری رسید؛ اسکن کامل تأیید نشد و حذف لغو شد.")
            return

        before = oldest_id
        time.sleep(PAGE_DELAY_SECONDS)
    else:
        print("به سقف صفحات رسیدیم؛ اسکن کامل نیست، بنابراین هیچ پیامی حذف نشد.")
        return

    if not complete_scan:
        print(
            "اسکن به پایان قابل‌تأیید نرسید؛ برای جلوگیری از پاک‌سازی ناقص، "
            "هیچ پیامی حذف نشد. اگر کانال بسیار بزرگ است، MAX_PAGES را افزایش دهید."
        )
        return

    print("اسکن کامل شد. تعداد پست‌های کانفیگ برای حذف:", len(candidates))
    deleted = failed = 0
    for index, message_id in enumerate(candidates, 1):
        result = bot.tg(
            "deleteMessage",
            chat_id=bot.TARGET_CHANNEL,
            message_id=message_id,
        )
        if isinstance(result, dict) and result.get("ok"):
            deleted += 1
        else:
            failed += 1
            print("حذف پیام %d ناموفق بود؛ پاسخ: %r" % (message_id, result))
        if index < len(candidates):
            time.sleep(DELETE_DELAY_SECONDS)

    if failed == 0:
        state[FLAG_KEY] = True
        bot.save_state(state)
        print("تمام شد: %d پست کانفیگ حذف شد. پرچم اجرای یک‌باره ذخیره شد." % deleted)
    else:
        print(
            "تمام شد، اما %d حذف ناموفق بود. پرچم اجرای یک‌باره ذخیره نشد؛ "
            "پس از بررسی خطاها می‌توانید دوباره اجرا کنید. موفق: %d، ناموفق: %d"
            % (failed, deleted, failed)
        )


if __name__ == "__main__":
    main()
