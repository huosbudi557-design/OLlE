"""
وحدة استرجاع كلمة السر (Password Recovery) لملفات المستخدم الشخصية
=====================================================================
ملاحظة مهمة جداً (اقرأها قبل الاستخدام):
هذه الأداة مخصصة لمساعدة المستخدم على استرجاع كلمة سر *نسيها* لملف
يملكه هو (ZIP / RAR / PDF محمي).

هي تجرب فقط:
  1) قائمة كلمات شائعة + كلمات يزوّدها المستخدم نفسه (مرجّح أكثر تذكراً)
  2) Brute-force محدود جداً (أرقام أو كلمات قصيرة) لأن التشفير الحقيقي
     القوي (AES) لا يمكن كسره بأي "طبقات فك تشفير" - هذا غير موجود تقنياً.

إذا كانت كلمة السر قوية وعشوائية، الأداة لن تنجح، وهذا متوقع ومقصود
لأنه يعني أن التشفير يعمل كما يجب.
"""

import zipfile
import itertools
import string
import asyncio

try:
    import rarfile  # يحتاج: pip install rarfile + تثبيت unrar في النظام
    RAR_AVAILABLE = True
except ImportError:
    RAR_AVAILABLE = False

try:
    import pikepdf  # pip install pikepdf
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "111111", "1234567", "12345", "1234", "000000",
    "admin", "letmein", "welcome", "monkey", "abc123",
    "iloveyou", "1q2w3e4r", "qwertyuiop", "123123", "987654321",
]


def _try_zip_password(file_path: str, password: str) -> bool:
    try:
        with zipfile.ZipFile(file_path) as zf:
            zf.extractall(path="/tmp/recovery_test", pwd=password.encode())
        return True
    except Exception:
        return False


def _try_rar_password(file_path: str, password: str) -> bool:
    if not RAR_AVAILABLE:
        return False
    try:
        with rarfile.RarFile(file_path) as rf:
            rf.extractall(path="/tmp/recovery_test", pwd=password)
        return True
    except Exception:
        return False


def _try_pdf_password(file_path: str, password: str) -> bool:
    if not PDF_AVAILABLE:
        return False
    try:
        with pikepdf.open(file_path, password=password):
            return True
    except Exception:
        return False


def _get_tester(file_type: str):
    return {
        "zip": _try_zip_password,
        "rar": _try_rar_password,
        "pdf": _try_pdf_password,
    }.get(file_type)


async def recover_password(
    file_path: str,
    file_type: str,
    user_hints: list[str] | None = None,
    max_length_bruteforce: int = 4,
    progress_callback=None,
) -> dict:
    """
    محاولة استرجاع كلمة السر لملف.

    file_type: "zip" | "rar" | "pdf"
    user_hints: كلمات يقترحها المستخدم نفسه (تواريخ ميلاد، أسماء، إلخ)
                هذه أكثر فعالية بكثير من القوائم العامة.
    max_length_bruteforce: الحد الأقصى لطول كلمة السر في تجربة الأرقام
                            فقط (يبقى صغيراً لتجنب استغراق وقت غير معقول)

    يرجع: {"found": bool, "password": str|None, "attempts": int}
    """
    tester = _get_tester(file_type)
    if tester is None:
        raise ValueError(f"نوع الملف '{file_type}' غير مدعوم أو المكتبة المطلوبة غير مثبتة")

    attempts = 0
    candidates = []

    # 1) تلميحات المستخدم أولاً (الأعلى احتمالاً للنجاح)
    if user_hints:
        for hint in user_hints:
            candidates.append(hint)
            # تنويعات شائعة على نفس التلميح
            candidates.append(hint.lower())
            candidates.append(hint.upper())
            candidates.append(hint + "123")
            candidates.append(hint + "1")
            candidates.append("123" + hint)

    # 2) قائمة كلمات شائعة
    candidates.extend(COMMON_PASSWORDS)

    # تجربة المرشحين (مع إزالة التكرار مع الحفاظ على الترتيب)
    seen = set()
    for pwd in candidates:
        if pwd in seen:
            continue
        seen.add(pwd)
        attempts += 1
        if progress_callback:
            await progress_callback(attempts, pwd)
        if tester(file_path, pwd):
            return {"found": True, "password": pwd, "attempts": attempts}
        await asyncio.sleep(0)  # السماح للحلقة بالتنفس (non-blocking)

    # 3) brute-force محدود جداً: أرقام فقط، حتى طول معين
    # (تحذير: حتى 4 أرقام = 10,000 محاولة كحد أقصى، أبعد من هذا غير عملي هنا)
    digits = string.digits
    for length in range(1, max_length_bruteforce + 1):
        for combo in itertools.product(digits, repeat=length):
            pwd = "".join(combo)
            if pwd in seen:
                continue
            attempts += 1
            if progress_callback and attempts % 200 == 0:
                await progress_callback(attempts, pwd)
            if tester(file_path, pwd):
                return {"found": True, "password": pwd, "attempts": attempts}
            await asyncio.sleep(0)

    return {"found": False, "password": None, "attempts": attempts}
