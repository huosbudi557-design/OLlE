"""
وحدة فحص الملفات
تستخدم VirusTotal API v3 - رفع الملف وتحليله بعشرات محركات الحماية
"""

import asyncio
import hashlib
import aiohttp

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# الحد الأقصى لحجم الملف عبر API المجاني (32 ميجا للرفع المباشر)
MAX_FILE_SIZE_MB = 32


def calculate_file_hash(file_path: str) -> str:
    """حساب SHA256 للملف - يُستخدم للبحث عنه مباشرة قبل رفعه"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


async def get_file_report_by_hash(file_hash: str, api_key: str):
    """
    البحث عن تقرير ملف موجود مسبقاً عبر الـ hash
    أسرع من رفع الملف كل مرة لو سبق فحصه من قبل مستخدم آخر في العالم
    """
    headers = {"x-apikey": api_key}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{VT_BASE_URL}/files/{file_hash}",
            headers=headers
        ) as resp:
            if resp.status == 404:
                return None  # الملف غير موجود مسبقاً، يحتاج رفع
            if resp.status != 200:
                text = await resp.text()
                raise Exception(f"خطأ في البحث عن الملف: {resp.status} - {text}")
            return await resp.json()


async def upload_file_for_scan(file_path: str, api_key: str) -> str:
    """رفع ملف جديد للفحص، يرجع analysis_id"""
    headers = {"x-apikey": api_key}
    async with aiohttp.ClientSession() as session:
        with open(file_path, "rb") as f:
            form = aiohttp.FormData()
            form.add_field("file", f, filename="scan_file")
            async with session.post(
                f"{VT_BASE_URL}/files",
                headers=headers,
                data=form
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise Exception(f"فشل رفع الملف: {resp.status} - {text}")
                data = await resp.json()
                return data["data"]["id"]


async def get_analysis_report(analysis_id: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=headers
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise Exception(f"فشل جلب التقرير: {resp.status} - {text}")
            return await resp.json()


def _parse_file_attributes(attributes: dict, file_path: str) -> dict:
    """تحويل بيانات VirusTotal الخام إلى ملخص منظم"""
    stats = attributes.get("last_analysis_stats") or attributes.get("stats", {})
    results = attributes.get("last_analysis_results") or attributes.get("results", {})

    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    harmless_count = stats.get("harmless", 0)
    undetected_count = stats.get("undetected", 0)
    total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

    flagged_engines = [
        {
            "engine": name,
            "result": data.get("result"),
            "category": data.get("category")
        }
        for name, data in results.items()
        if data.get("category") in ("malicious", "suspicious")
    ]

    return {
        "file_name": file_path.split("/")[-1],
        "file_type": attributes.get("type_description", "غير معروف"),
        "file_size": attributes.get("size", 0),
        "sha256": attributes.get("sha256", ""),
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count": harmless_count,
        "undetected_count": undetected_count,
        "total_engines": total_engines,
        "flagged_engines": flagged_engines,
        "is_malicious": malicious_count > 0 or suspicious_count > 2,
        "popular_threat_names": attributes.get("popular_threat_classification", {})
                                            .get("suggested_threat_label", None),
        "vt_link": f"https://www.virustotal.com/gui/file/{attributes.get('sha256', '')}",
    }


async def scan_file(file_path: str, api_key: str, max_wait_seconds: int = 60) -> dict:
    """
    فحص ملف كامل:
    1. حساب hash ومحاولة جلب تقرير موجود مسبقاً (أسرع)
    2. لو غير موجود، يرفع الملف ويفحصه من الصفر
    """
    file_hash = calculate_file_hash(file_path)

    # محاولة جلب تقرير موجود مسبقاً
    existing_report = await get_file_report_by_hash(file_hash, api_key)
    if existing_report is not None:
        attributes = existing_report.get("data", {}).get("attributes", {})
        return _parse_file_attributes(attributes, file_path)

    # رفع الملف للفحص من جديد
    analysis_id = await upload_file_for_scan(file_path, api_key)

    waited = 0
    interval = 5
    report = None
    while waited < max_wait_seconds:
        report = await get_analysis_report(analysis_id, api_key)
        status = report.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break
        await asyncio.sleep(interval)
        waited += interval

    if report is None:
        raise Exception("لم يتم استلام أي نتيجة من VirusTotal")

    attributes = report.get("data", {}).get("attributes", {})
    result = _parse_file_attributes(attributes, file_path)
    result["sha256"] = file_hash
    result["vt_link"] = f"https://www.virustotal.com/gui/file/{file_hash}"
    return result


def format_file_result(result: dict) -> str:
    """تنسيق نتيجة فحص الملف كنص جاهز للعرض في تيليجرام"""
    if result["is_malicious"]:
        header = "🔴 *تحذير: الملف يحتوي على فايروس/برمجية ضارة*"
    elif result["suspicious_count"] > 0:
        header = "🟡 *تنبيه: نتائج مشتبه بها في الملف*"
    else:
        header = "🟢 *الملف يبدو آمناً*"

    size_kb = result["file_size"] / 1024 if result["file_size"] else 0

    lines = [
        header,
        "",
        f"📄 الاسم: `{result['file_name']}`",
        f"📦 النوع: {result['file_type']}",
        f"📏 الحجم: {size_kb:.1f} كيلوبايت",
        f"🔑 SHA256: `{result['sha256'][:32]}...`",
        "",
        f"📊 نتيجة الفحص ({result['total_engines']} محرك فحص):",
        f"  • ضار: {result['malicious_count']}",
        f"  • مشتبه به: {result['suspicious_count']}",
        f"  • سليم: {result['harmless_count']}",
        f"  • غير مكتشف: {result['undetected_count']}",
    ]

    if result.get("popular_threat_names"):
        lines.append("")
        lines.append(f"🦠 نوع التهديد المحتمل: {result['popular_threat_names']}")

    if result["flagged_engines"]:
        lines.append("")
        lines.append("⚠️ محركات صنّفته كخطر:")
        for eng in result["flagged_engines"][:6]:
            lines.append(f"  • {eng['engine']}: {eng['result']}")

    lines.append("")
    lines.append(f"🔍 [عرض التقرير الكامل على VirusTotal]({result['vt_link']})")

    return "\n".join(lines)
