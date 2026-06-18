"""
لوحة تحكم الأدمن - أوامر خاصة تعمل فقط للمعرّفين في config.ADMIN_IDS
الإحصائيات، إدارة المستخدمين، الحظر/فك الحظر، عرض آخر الفحوصات
"""

import logging
from telegram import Update
from telegram.ext import ContextTypes

from database import db
import config

logger = logging.getLogger(__name__)


def is_admin(user_id: int) -> bool:
    return user_id in config.ADMIN_IDS


async def admin_only_guard(update: Update) -> bool:
    """يرجع True إذا كان المستخدم أدمن، وإلا يرسل رسالة رفض ويرجع False"""
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("🚫 هذا الأمر مخصص للمشرفين فقط.")
        return False
    return True


async def admin_panel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض لوحة التحكم الرئيسية بقائمة الأوامر المتاحة للأدمن"""
    if not await admin_only_guard(update):
        return

    text = (
        "🛠️ *لوحة تحكم الأدمن*\n\n"
        "/admin\\_stats - إحصائيات عامة عن البوت\n"
        "/admin\\_users - عرض آخر المستخدمين المسجلين\n"
        "/admin\\_ban `<user_id>` - حظر مستخدم\n"
        "/admin\\_unban `<user_id>` - فك حظر مستخدم\n"
        "/admin\\_scan `<scan_id>` - عرض تفاصيل فحص معيّن\n"
        "/admin\\_broadcast `<رسالة>` - إرسال رسالة لجميع المستخدمين"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def admin_stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only_guard(update):
        return

    stats = db.get_stats()
    text = (
        "📊 *إحصائيات البوت*\n\n"
        f"👥 إجمالي المستخدمين: {stats['total_users']}\n"
        f"🔍 إجمالي عمليات الفحص: {stats['total_scans']}\n"
        f"☣️ عمليات اكتُشف فيها تهديد: {stats['malicious_found']}\n\n"
        f"🔗 فحوصات روابط: {stats['url_scans']}\n"
        f"📎 فحوصات ملفات: {stats['file_scans']}\n"
        f"🌍 فحوصات IP: {stats['ip_scans']}"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def admin_users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only_guard(update):
        return

    users = db.get_all_users(limit=20)
    if not users:
        await update.message.reply_text("لا يوجد مستخدمون مسجلون حتى الآن.")
        return

    lines = ["👥 *آخر 20 مستخدم:*", ""]
    for u in users:
        status = "🚫" if u["is_banned"] else "✅"
        username = f"@{u['username']}" if u["username"] else "—"
        lines.append(f"{status} `{u['user_id']}` | {u['first_name']} ({username}) | فحوصات: {u['scan_count']}")

    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


async def admin_ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only_guard(update):
        return

    if not context.args:
        await update.message.reply_text("الاستخدام: /admin_ban <user_id>")
        return

    try:
        target_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("⚠️ آيدي المستخدم يجب أن يكون رقماً.")
        return

    db.ban_user(target_id, banned=True)
    await update.message.reply_text(f"🚫 تم حظر المستخدم `{target_id}`.", parse_mode="Markdown")


async def admin_unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only_guard(update):
        return

    if not context.args:
        await update.message.reply_text("الاستخدام: /admin_unban <user_id>")
        return

    try:
        target_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("⚠️ آيدي المستخدم يجب أن يكون رقماً.")
        return

    db.ban_user(target_id, banned=False)
    await update.message.reply_text(f"✅ تم فك حظر المستخدم `{target_id}`.", parse_mode="Markdown")


async def admin_scan_detail_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only_guard(update):
        return

    if not context.args:
        await update.message.reply_text("الاستخدام: /admin_scan <scan_id>")
        return

    try:
        scan_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("⚠️ رقم الفحص يجب أن يكون رقماً.")
        return

    scan = db.get_scan_by_id(scan_id)
    if scan is None:
        await update.message.reply_text("⚠️ لم يتم العثور على فحص بهذا الرقم.")
        return

    text = (
        f"🔍 *تفاصيل الفحص #{scan_id}*\n\n"
        f"👤 المستخدم: `{scan['user_id']}`\n"
        f"📌 النوع: {scan['scan_type']}\n"
        f"🎯 الهدف: `{scan['target']}`\n"
        f"☣️ ضار: {'نعم' if scan['is_malicious'] else 'لا'}\n"
        f"🕒 التاريخ: {scan['created_at']}"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def admin_broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إرسال رسالة جماعية لكل المستخدمين المسجلين"""
    if not await admin_only_guard(update):
        return

    if not context.args:
        await update.message.reply_text("الاستخدام: /admin_broadcast <نص الرسالة>")
        return

    message_text = " ".join(context.args)
    users = db.get_all_users(limit=10000)

    sent, failed = 0, 0
    status_msg = await update.message.reply_text(f"📤 جاري الإرسال لـ {len(users)} مستخدم...")

    for u in users:
        try:
            await context.bot.send_message(chat_id=u["user_id"], text=f"📢 {message_text}")
            sent += 1
        except Exception:
            failed += 1

    await status_msg.edit_text(f"✅ تم الإرسال بنجاح: {sent}\n❌ فشل الإرسال: {failed}")
