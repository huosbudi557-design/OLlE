"""
معالج محادثة استرجاع كلمة السر (Password Recovery)
يعمل كـ ConversationHandler: يطلب الملف -> يطلب نوعه -> يطلب تلميحات اختيارية -> يبدأ المحاولة
"""

import os
import logging
from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler

from utils.password_recovery import recover_password
import config

logger = logging.getLogger(__name__)

# حالات المحادثة
WAITING_FILE, WAITING_TYPE, WAITING_HINTS = range(3)

SUPPORTED_TYPES = {"zip", "rar", "pdf"}


async def recover_password_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔑 *استرجاع كلمة سر لملف*\n\n"
        "⚠️ هذه الأداة فقط لملفاتك الخاصة التي نسيت كلمة سرها.\n"
        "تعمل فقط مع كلمات السر الضعيفة أو الشائعة — هذا طبيعي، "
        "لأن أي تشفير قوي مصمم خصيصاً ليمنع هذا النوع من المحاولات.\n\n"
        "📎 أرسل الآن الملف المحمي (ZIP أو RAR أو PDF):",
        parse_mode="Markdown"
    )
    return WAITING_FILE


async def receive_protected_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    if document is None:
        await update.message.reply_text("⚠️ أرسل ملفاً صحيحاً من فضلك.")
        return WAITING_FILE

    file_ext = document.file_name.split(".")[-1].lower()
    if file_ext not in SUPPORTED_TYPES:
        await update.message.reply_text(
            f"⚠️ النوع `.{file_ext}` غير مدعوم حالياً.\n"
            f"الأنواع المدعومة: {', '.join(SUPPORTED_TYPES)}",
            parse_mode="Markdown"
        )
        return WAITING_FILE

    os.makedirs(config.TEMP_FILES_DIR, exist_ok=True)
    local_path = os.path.join(config.TEMP_FILES_DIR, f"recover_{update.effective_user.id}_{document.file_name}")

    tg_file = await document.get_file()
    await tg_file.download_to_drive(local_path)

    context.user_data["recovery_file_path"] = local_path
    context.user_data["recovery_file_type"] = file_ext

    await update.message.reply_text(
        "✅ تم استلام الملف.\n\n"
        "💡 (اختياري) أرسل أي كلمات أو أرقام تظن أنها قد تكون كلمة السر "
        "أو تشبهها (تاريخ ميلاد، اسم، إلخ) مفصولة بفاصلة، أو اكتب 'تخطي' للمتابعة بدونها:"
    )
    return WAITING_HINTS


async def receive_hints_and_run(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    hints = [] if text.lower() in ("تخطي", "skip", "لا", "لا يوجد") else [h.strip() for h in text.split(",") if h.strip()]

    file_path = context.user_data.get("recovery_file_path")
    file_type = context.user_data.get("recovery_file_type")

    if not file_path or not os.path.exists(file_path):
        await update.message.reply_text("⚠️ حدث خطأ، يرجى البدء من جديد بـ /recover_password")
        return ConversationHandler.END

    status_msg = await update.message.reply_text(
        "🔄 جاري المحاولة... سيتم تجربة التلميحات والكلمات الشائعة أولاً ثم أرقام قصيرة.\n"
        "قد يستغرق هذا من ثوان إلى دقائق حسب قوة كلمة السر."
    )

    try:
        result = await recover_password(
            file_path=file_path,
            file_type=file_type,
            user_hints=hints,
            max_length_bruteforce=4,
        )

        if result["found"]:
            await status_msg.edit_text(
                f"✅ *تم العثور على كلمة السر!*\n\n"
                f"🔑 كلمة السر: `{result['password']}`\n"
                f"🔢 عدد المحاولات: {result['attempts']}",
                parse_mode="Markdown"
            )
        else:
            await status_msg.edit_text(
                "❌ *لم يتم العثور على كلمة السر*\n\n"
                f"تمت تجربة {result['attempts']} كلمة/رقم بدون نتيجة.\n"
                "هذا يعني أن كلمة السر قوية بما يكفي لمنع هذا النوع من المحاولات السريعة. "
                "لاسترجاعها يلزم تذكّر كلمة السر فعلياً أو استخدام نسخة احتياطية إن وجدت.",
                parse_mode="Markdown"
            )
    except Exception as e:
        logger.exception("خطأ في استرجاع كلمة السر")
        await status_msg.edit_text(f"❌ حدث خطأ:\n`{str(e)}`", parse_mode="Markdown")
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)
        context.user_data.pop("recovery_file_path", None)
        context.user_data.pop("recovery_file_type", None)

    return ConversationHandler.END


async def recover_password_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file_path = context.user_data.pop("recovery_file_path", None)
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
    await update.message.reply_text("تم إلغاء العملية.")
    return ConversationHandler.END
