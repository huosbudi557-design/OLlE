"""
الملف الرئيسي لتشغيل البوت
يجمع كل المعالجات (Handlers) ويبدأ البوت بنظام Polling
"""

import logging
from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ConversationHandler, filters
)

from database import db
from handlers import user_handlers, admin_handlers, password_handlers
import config

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def main():
    # تهيئة قاعدة البيانات
    db.init_db()

    # التحقق من إعداد التوكنات قبل التشغيل
    if config.TELEGRAM_BOT_TOKEN == "ضع_توكن_البوت_هنا":
        raise SystemExit(
            "⚠️ لم يتم ضبط توكن البوت في config.py أو متغير البيئة TELEGRAM_BOT_TOKEN"
        )
    if config.VIRUSTOTAL_API_KEY == "ضع_مفتاح_VirusTotal_هنا":
        logger.warning("⚠️ لم يتم ضبط مفتاح VirusTotal - فحص الروابط والملفات لن يعمل")

    application = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()

    # ===== أوامر المستخدم الأساسية =====
    application.add_handler(CommandHandler("start", user_handlers.start_command))
    application.add_handler(CommandHandler("help", user_handlers.help_command))
    application.add_handler(CommandHandler("history", user_handlers.history_command))
    application.add_handler(CommandHandler("scan_url", user_handlers.help_command))  # توجيه للمساعدة
    application.add_handler(CommandHandler("scan_ip", user_handlers.help_command))

    # استقبال الروابط/IP كنص عادي
    application.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND, user_handlers.handle_text_message
    ))

    # استقبال الملفات للفحص (خارج محادثة استرجاع كلمة السر)
    application.add_handler(MessageHandler(
        filters.Document.ALL, user_handlers.handle_file_upload
    ))

    # أزرار القائمة الرئيسية
    application.add_handler(CallbackQueryHandler(user_handlers.button_callback_handler))

    # ===== محادثة استرجاع كلمة السر =====
    recovery_conversation = ConversationHandler(
        entry_points=[CommandHandler("recover_password", password_handlers.recover_password_start)],
        states={
            password_handlers.WAITING_FILE: [
                MessageHandler(filters.Document.ALL, password_handlers.receive_protected_file)
            ],
            password_handlers.WAITING_HINTS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, password_handlers.receive_hints_and_run)
            ],
        },
        fallbacks=[CommandHandler("cancel", password_handlers.recover_password_cancel)],
    )
    application.add_handler(recovery_conversation)

    # ===== لوحة تحكم الأدمن =====
    application.add_handler(CommandHandler("admin", admin_handlers.admin_panel_command))
    application.add_handler(CommandHandler("admin_stats", admin_handlers.admin_stats_command))
    application.add_handler(CommandHandler("admin_users", admin_handlers.admin_users_command))
    application.add_handler(CommandHandler("admin_ban", admin_handlers.admin_ban_command))
    application.add_handler(CommandHandler("admin_unban", admin_handlers.admin_unban_command))
    application.add_handler(CommandHandler("admin_scan", admin_handlers.admin_scan_detail_command))
    application.add_handler(CommandHandler("admin_broadcast", admin_handlers.admin_broadcast_command))

    logger.info("🚀 البوت بدأ التشغيل...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
