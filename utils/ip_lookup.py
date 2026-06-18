"""
وحدة فحص عناوين IP
تستخدم ip-api.com (مجاني، لا يحتاج API key للاستخدام الأساسي)
ترجع: الدولة، المدينة، مزود الخدمة (ISP)، هل IP مرتبط بـ VPN/Proxy معروف

ملاحظة مهمة: الموقع الناتج هو موقع تقريبي على مستوى المدينة/المزود
وليس موقعاً دقيقاً لجهاز أو شخص بعينه.
"""

import aiohttp

IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"


async def lookup_ip(ip_address: str) -> dict:
    """جلب معلومات الموقع والشبكة لعنوان IP معين"""
    url = IP_API_URL.format(ip=ip_address) + f"?fields={IP_API_FIELDS}&lang=ar"

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                raise Exception(f"فشل الاستعلام عن IP: {resp.status}")
            data = await resp.json()

    if data.get("status") != "success":
        raise Exception(data.get("message", "تعذر العثور على معلومات لهذا IP"))

    return {
        "ip": data.get("query"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "zip_code": data.get("zip"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as_info": data.get("as"),
        "is_proxy_or_vpn": data.get("proxy", False),
        "is_hosting": data.get("hosting", False),
    }


def format_ip_result(result: dict) -> str:
    """تنسيق نتيجة فحص IP كنص جاهز للعرض في تيليجرام"""
    flags = []
    if result.get("is_proxy_or_vpn"):
        flags.append("🔒 يبدو أنه يستخدم VPN/Proxy")
    if result.get("is_hosting"):
        flags.append("☁️ عنوان تابع لخدمة استضافة/سيرفر")

    lines = [
        "🌍 *معلومات عنوان IP*",
        "",
        f"📍 IP: `{result['ip']}`",
        f"🏳️ الدولة: {result['country']} ({result['country_code']})",
        f"🏙️ المدينة: {result['city']}",
        f"🗺️ المنطقة: {result['region']}",
        f"📮 الرمز البريدي: {result.get('zip_code') or '—'}",
        f"🕒 المنطقة الزمنية: {result['timezone']}",
        f"📡 مزود الخدمة (ISP): {result['isp']}",
        f"🏢 المؤسسة: {result.get('org') or '—'}",
    ]

    if flags:
        lines.append("")
        lines.extend(flags)

    lines.append("")
    lines.append("ℹ️ _ملاحظة: هذا موقع تقريبي على مستوى المدينة/مزود الخدمة، وليس موقعاً دقيقاً لجهاز أو شخص._")

    return "\n".join(lines)
