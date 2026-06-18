"""
معالجات أوامر المستخدم العادي
/start, /help, فحص الروابط، فحص الملفات، فحص IP، السجل الشخصي
"""

import os
import re
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

from database import db
from utils.url_scanner import scan_url, format_url_result
from utils.file_scanner import scan_file, format_file_result
from utils.ip_lookup import lookup_ip, format_ip_result
from utils.report_generator import generate_url_report, generate_file_report, generate_ip_report
import config

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"^https?://[^\s]+$")
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    db.add_user(user.id, user.username or "", user.first_name or "")

    welcome_text = (
        f"👋 أهلاً {user.first_name}!\n\n"
        "🛡️ *بوت الحماية الذكي*\n"
        "أرسل لي أي من التالي وسأفحصه لك:\n\n"
        "🔗 *رابط* - لمعرفة هل هو آمن أو ضار\n"
        "📎 *ملف* - لفحصه من الفايروسات والبرمجيات الضارة\n"
        "🌍 *عنوان IP* - لمعرفة الدولة والموقع ومزود الخدمة\n\n"
        "📌 الأوامر المتاحة:\n"
        "/scan\\_url - فحص رابط\n"
        "/scan\\_ip - فحص عنوان IP\n"
        "/history - سجل فحوصاتك الأخيرة\n"
        "/recover\\_password - استرجاع كلمة سر لملف تملكه\n"
        "/help - عرض المساعدة"
    )

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔗 فحص رابط", callback_data="menu_url"),
         InlineKeyboardButton("🌍 فحص IP", callback_data="menu_ip")],
        [InlineKeyboardButton("📎 فحص ملف", callback_data="menu_file"),
         InlineKeyboardButton("📜 سجلي", callback_data="menu_history")],
    ])

    await update.message.reply_text(welcome_text, parse_mode="Markdown", reply_markup=keyboard)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "📖 *دليل استخدام البوت*\n\n"
        "1️⃣ *فحص رابط*: أرسل الرابط مباشرة في الرسالة أو استخدم /scan\\_url\n"
        "2️⃣ *فحص ملف*: أرسل الملف مباشرة في المحادثة (حد أقصى 32 ميجا)\n"
        "3️⃣ *فحص IP*: أرسل /scan\\_ip ثم العنوان، مثال: 8.8.8.8\n"
        "4️⃣ *استرجاع كلمة سر*: /recover\\_password لملف ZIP/RAR/PDF تملكه\n"
        "5️⃣ بعد كل فحص يصلك تقرير PDF مفصّل\n\n"
        "⚠️ *تنبيه مهم*: استرجاع كلمة السر يعمل فقط على كلمات السر "
        "الضعيفة/الشائعة، وهذا طبيعي ومتوقع لأن التشفير القوي مصمم "
        "خصيصاً ليمنع هذا - استخدمه فقط لملفاتك الخاصة."
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")


async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """يستقبل أي رسالة نصية ويحدد تلقائياً: رابط؟ IP؟ أو نص عادي"""
    user = update.effective_user
    text = update.message.text.strip()

    if db.is_user_banned(user.id):
        await update.message.reply_text("🚫 تم حظرك من استخدام هذا البوت.")
        return

    db.add_user(user.id, user.username or "", user.first_name or "")

    if URL_PATTERN.match(text):
        await _handle_url_scan(update, context, text)
    elif IP_PATTERN.match(text):
        await _handle_ip_scan(update, context, text)
    else:
        await update.message.reply_text(
            "🤔 لم أتعرف على رابط أو عنوان IP صحيح.\n"
            "أرسل رابطاً يبدأ بـ http:// أو https://\n"
            "أو عنوان IP مثل 8.8.8.8\n"
            "أو أرسل ملفاً مباشرة للفحص."
        )


async def _handle_url_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, url: str):
    user = update.effective_user
    status_msg = await update.message.reply_text("🔍 جاري فحص الرابط، يرجى الانتظار...")

    try:
        result = await scan_url(url, config.VIRUSTOTAL_API_KEY)
        formatted = format_url_result(result)

        scan_id = db.log_scan(
            user_id=user.id, scan_type="url", target=url,
            result_summary=formatted, raw_result=result,
            is_malicious=result["is_malicious"]
        )

        await status_msg.edit_text(formatted, parse_mode="Markdown", disable_web_page_preview=True)

        # إرسال تقرير PDF
        report_path = generate_url_report(result, scan_id)
        with open(report_path, "rb") as f:
            await update.message.reply_document(f, filename=f"تقرير_فحص_رابط_{scan_id}.pdf")

    except Exception as e:
        logger.exception("خطأ في فحص الرابط")
        await status_msg.edit_text(f"❌ حدث خطأ أثناء الفحص:\n`{str(e)}`", parse_mode="Markdown")


async def _handle_ip_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    user = update.effective_user
    status_msg = await update.message.reply_text("🔍 جاري فحص عنوان IP...")

    try:
        result = await lookup_ip(ip)
        formatted = format_ip_result(result)

        scan_id = db.log_scan(
            user_id=user.id, scan_type="ip", target=ip,
            result_summary=formatted, raw_result=result,
            is_malicious=result.get("is_proxy_or_vpn", False)
        )

        await status_msg.edit_text(formatted, parse_mode="Markdown")

        report_path = generate_ip_report(result, scan_id)
        with open(report_path, "rb") as f:
            await update.message.reply_document(f, filename=f"تقرير_فحص_IP_{scan_id}.pdf")

    except Exception as e:
        logger.exception("خطأ في فحص IP")
        await status_msg.edit_text(f"❌ حدث خطأ أثناء الفحص:\n`{str(e)}`", parse_mode="Markdown")


async def handle_file_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """يستقبل الملفات المرسلة للفحص"""
    user = update.effective_user

    if db.is_user_banned(user.id):
        await update.message.reply_text("🚫 تم حظرك من استخدام هذا البوت.")
        return

    db.add_user(user.id, user.username or "", user.first_name or "")

    document = update.message.document
    if document.file_size > config.MAX_FILE_SIZE_MB * 1024 * 1024:
        await update.message.reply_text(
            f"⚠️ الملف أكبر من الحد المسموح ({config.MAX_FILE_SIZE_MB} ميجا)."
        )
        return

    status_msg = await update.message.reply_text("📥 جاري تحميل الملف وفحصه، قد يستغرق هذا دقيقة...")

    os.makedirs(config.TEMP_FILES_DIR, exist_ok=True)
    local_path = os.path.join(config.TEMP_FILES_DIR, f"{user.id}_{document.file_name}")

    try:
        tg_file = await document.get_file()
        await tg_file.download_to_drive(local_path)

        result = await scan_file(local_path, config.VIRUSTOTAL_API_KEY)
        formatted = format_file_result(result)

        scan_id = db.log_scan(
            user_id=user.id, scan_type="file", target=document.file_name,
            result_summary=formatted, raw_result=result,
            is_malicious=result["is_malicious"]
        )

        await status_msg.edit_text(formatted, parse_mode="Markdown", disable_web_page_preview=True)

        report_path = generate_file_report(result, scan_id)
        with open(report_path, "rb") as f:
            await update.message.reply_document(f, filename=f"تقرير_فحص_ملف_{scan_id}.pdf")

    except Exception as e:
        logger.exception("خطأ في فحص الملف")
        await status_msg.edit_text(f"❌ حدث خطأ أثناء الفحص:\n`{str(e)}`", parse_mode="Markdown")
    finally:
        if os.path.exists(local_path):
            os.remove(local_path)


async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    scans = db.get_user_scans(user.id, limit=10)

    if not scans:
        await update.message.reply_text("📭 لا يوجد لديك أي عمليات فحص سابقة.")
        return

    lines = ["📜 *آخر 10 عمليات فحص لك:*", ""]
    for s in scans:
        icon = "🔴" if s["is_malicious"] else "🟢"
        type_label = {"url": "رابط", "file": "ملف", "ip": "IP"}.get(s["scan_type"], s["scan_type"])
        lines.append(f"{icon} #{s['scan_id']} | {type_label} | `{s['target'][:40]}` | {s['created_at'][:16]}")

    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


async def button_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالج أزرار القائمة الرئيسية"""
    query = update.callback_query
    await query.answer()

    messages = {
        "menu_url": "🔗 أرسل الرابط الذي تريد فحصه الآن.",
        "menu_ip": "🌍 أرسل عنوان IP الذي تريد فحصه، مثال: 8.8.8.8",
        "menu_file": "📎 أرسل الملف الذي تريد فحصه مباشرة في المحادثة.",
        "menu_history": None,  # يتم التعامل معه بشكل خاص
    }

    if query.data == "menu_history":
        scans = db.get_user_scans(query.from_user.id, limit=10)
        if not scans:
            await query.message.reply_text("📭 لا يوجد لديك أي عمليات فحص سابقة.")
            return
        lines = ["📜 *آخر 10 عمليات فحص لك:*", ""]
        for s in scans:
            icon = "🔴" if s["is_malicious"] else "🟢"
            type_label = {"url": "رابط", "file": "ملف", "ip": "IP"}.get(s["scan_type"], s["scan_type"])
            lines.append(f"{icon} #{s['scan_id']} | {type_label} | `{s['target'][:40]}`")
        await query.message.reply_text("\n".join(lines), parse_mode="Markdown")
    else:
        await query.message.reply_text(messages[query.data])
