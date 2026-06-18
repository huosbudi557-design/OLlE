"""
وحدة فحص الروابط (URLs)
تستخدم VirusTotal API v3
الحصول على مفتاح API مجاني من: https://www.virustotal.com/gui/join-us
"""

import base64
import asyncio
import aiohttp

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def encode_url_id(url: str) -> str:
    """VirusTotal يتطلب الرابط مُرمّز بـ base64 بدون علامات = في النهاية"""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


async def submit_url_for_scan(url: str, api_key: str) -> str:
    """إرسال رابط جديد للفحص، يرجع url_id"""
    headers = {"x-apikey": api_key}
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data={"url": url}
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise Exception(f"فشل إرسال الرابط للفحص: {resp.status} - {text}")
            data = await resp.json()
            return data["data"]["id"]


async def get_url_report(url_id: str, api_key: str) -> dict:
    """جلب نتيجة فحص رابط معين"""
    headers = {"x-apikey": api_key}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{VT_BASE_URL}/analyses/{url_id}",
            headers=headers
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise Exception(f"فشل جلب نتيجة الفحص: {resp.status} - {text}")
            return await resp.json()


async def scan_url(url: str, api_key: str, max_wait_seconds: int = 30) -> dict:
    """
    فحص رابط كامل: إرسال + انتظار النتيجة + تحليلها
    يرجع قاموس بالنتائج المنظمة
    """
    # 1. إرسال الرابط للفحص (يعيد تشغيل فحص جديد)
    analysis_id = await submit_url_for_scan(url, api_key)

    # 2. الانتظار حتى انتهاء التحليل (polling)
    waited = 0
    interval = 3
    report = None
    while waited < max_wait_seconds:
        report = await get_url_report(analysis_id, api_key)
        status = report.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break
        await asyncio.sleep(interval)
        waited += interval

    if report is None:
        raise Exception("لم يتم استلام أي نتيجة من VirusTotal")

    attributes = report.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})
    results = attributes.get("results", {})

    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    harmless_count = stats.get("harmless", 0)
    undetected_count = stats.get("undetected", 0)
    total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

    # استخراج أسماء المحركات التي صنّفت الرابط كخبيث
    flagged_engines = [
        engine_name for engine_name, engine_data in results.items()
        if engine_data.get("category") in ("malicious", "suspicious")
    ]

    is_malicious = malicious_count > 0 or suspicious_count > 2

    return {
        "url": url,
        "status": attributes.get("status", "unknown"),
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count": harmless_count,
        "undetected_count": undetected_count,
        "total_engines": total_engines,
        "flagged_engines": flagged_engines,
        "is_malicious": is_malicious,
        "vt_link": f"https://www.virustotal.com/gui/url/{encode_url_id(url)}",
    }


def format_url_result(result: dict) -> str:
    """تنسيق نتيجة فحص الرابط كنص جاهز للعرض في تيليجرام"""
    if result["is_malicious"]:
        header = "🔴 *تحذير: رابط ضار محتمل*"
    elif result["suspicious_count"] > 0:
        header = "🟡 *تنبيه: نتائج مشتبه بها*"
    else:
        header = "🟢 *الرابط يبدو آمناً*"

    lines = [
        header,
        "",
        f"🔗 الرابط: `{result['url']}`",
        "",
        f"📊 نتيجة الفحص ({result['total_engines']} محرك فحص):",
        f"  • ضار: {result['malicious_count']}",
        f"  • مشتبه به: {result['suspicious_count']}",
        f"  • سليم: {result['harmless_count']}",
        f"  • غير مكتشف: {result['undetected_count']}",
    ]

    if result["flagged_engines"]:
        engines_str = ", ".join(result["flagged_engines"][:8])
        lines.append("")
        lines.append(f"⚠️ محركات صنّفته كخطر: {engines_str}")

    lines.append("")
    lines.append(f"🔍 [عرض التقرير الكامل على VirusTotal]({result['vt_link']})")

    return "\n".join(lines)
