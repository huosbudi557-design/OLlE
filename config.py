"""
ملف الإعدادات المركزي
ضع هنا التوكنات والمفاتيح، أو فعّل تحميلها من متغيرات البيئة (الأفضل أمنياً)
"""

import os

# توكن بوت تيليجرام - احصل عليه من @BotFather
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "ضع_توكن_البوت_هنا")

# مفتاح VirusTotal API - مجاني من https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "ضع_مفتاح_VirusTotal_هنا")

# معرفات تيليجرام للأدمن (يمكن إضافة أكثر من واحد)
# لمعرفة آيديك: راسل @userinfobot على تيليجرام
ADMIN_IDS = [
    123456789,  # غيّر هذا لآيدي التيليجرام الخاص بك
]

# حدود الاستخدام لكل مستخدم (لمنع الإفراط في استهلاك حصة API المجانية)
MAX_SCANS_PER_DAY_FREE_USER = 20

# الحد الأقصى لحجم الملف المسموح فحصه (ميجابايت)
MAX_FILE_SIZE_MB = 32

# مجلد حفظ الملفات المؤقتة المرفوعة للفحص
TEMP_FILES_DIR = "temp_files"

# مجلد حفظ التقارير المُولّدة
REPORTS_DIR = "reports"
