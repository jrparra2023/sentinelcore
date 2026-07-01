"""
SentinelCore — correlation/geo.py
Geo-lookup for external IPs using ip-api.com (free, no key, 45 req/min).
Results are cached in SQLite to avoid repeat lookups.

Private/RFC1918 IPs are marked immediately without an API call.
"""

import requests
from datetime import datetime, timedelta
from correlation.reputation import is_private
from storage.db import Database

# Cache TTL — re-lookup after 7 days
CACHE_TTL_DAYS = 7
_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,query"


def lookup(ip: str, db: Database, timeout: int = 3) -> dict:
    """
    Return geo data for an IP. Uses cache first, then ip-api.com.

    Returns dict with keys:
        ip, country, country_code, city, org, is_private
    """
    if not ip:
        return _empty(ip)

    # Private IPs — no API call needed
    if is_private(ip):
        result = {"ip": ip, "country": "Private", "country_code": "LAN",
                  "city": "LAN", "org": "Private Network", "is_private": True}
        db.set_geo(ip, result)
        return result

    # Check cache
    cached = db.get_geo(ip)
    if cached:
        cached_at = datetime.fromisoformat(cached.get("cached_at", "2000-01-01"))
        if datetime.now() - cached_at < timedelta(days=CACHE_TTL_DAYS):
            return dict(cached)

    # Live lookup
    try:
        r = requests.get(_API_URL.format(ip=ip), timeout=timeout)
        data = r.json()
        if data.get("status") == "success":
            result = {
                "ip":           ip,
                "country":      data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "??"),
                "city":         data.get("city", "Unknown"),
                "org":          data.get("org", "Unknown"),
                "is_private":   False,
            }
            db.set_geo(ip, result)
            return result
    except Exception:
        pass

    return _empty(ip)


def _empty(ip: str) -> dict:
    return {"ip": ip, "country": "Unknown", "country_code": "??",
            "city": "Unknown", "org": "Unknown", "is_private": False}


def enrich_alert(ip: str, db: Database) -> str:
    """Return a short geo string for alert descriptions."""
    if not ip:
        return ""
    geo = lookup(ip, db)
    if geo.get("is_private"):
        return "[LAN]"
    return f"[{geo.get('country_code','??')} / {geo.get('city','?')} / {geo.get('org','?')}]"
