# ip_tracking/middleware.py
import logging
from django.core.cache import cache
from django.http import HttpResponseForbidden

logger = logging.getLogger(__name__)

GEO_CACHE_TTL = 60 * 60 * 24  # 24 hours


class IPLoggingMiddleware:
    """
    Middleware that:
    - Blocks requests whose client IP is present in the BlockedIP table (403).
    - Otherwise logs the request (ip, path, timestamp) in RequestLog.

    The blacklist check is done before saving RequestLog so blocked requests are
    rejected immediately.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self._get_client_ip(request)
        path = getattr(request, "path", "")

        # Check blacklist first; do a local import to avoid import-time cycles
        try:
            from .models import BlockedIP
            if BlockedIP.objects.filter(ip_address=ip).exists():
                # Optionally log the blocked attempt for audit
                logger.warning("Blocked request from blacklisted IP %s to %s", ip, path)
                return HttpResponseForbidden("Your IP has been blocked.")
        except Exception as exc:
            # If blacklist check fails (DB down etc.), log error but continue processing.
            logger.error("Error checking BlockedIP for IP %s: %s", ip, exc)

        # Not blocked -> attempt to log the request (non-fatal)
        try:
            from .models import RequestLog
            RequestLog.objects.create(ip_address=ip, path=path)
        except Exception as exc:
            logger.exception("Failed to log request for IP %s path %s: %s", ip, path, exc)

        response = self.get_response(request)
        return response

    def _get_client_ip(self, request):
        """
        Determine the client's IP address.
        Prefer X-Forwarded-For header if present (first item).
        Fallback to REMOTE_ADDR.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
            if ip:
                return ip
        return request.META.get("REMOTE_ADDR", "")

    def _get_geolocation(self, ip):
        """
        Return (country, city) for an IP address.
        Use Django cache (Redis) with a 24-hour TTL.
        Try to use django-ip-geolocation if installed; otherwise fall back to a public API.
        """
        if not ip:
            return None, None

        cache_key = f"geo:{ip}"
        geo = cache.get(cache_key)
        if geo:
            # expected shape: {"country": "...", "city": "..."}
            return geo.get("country"), geo.get("city")

        # Not cached — attempt to use django-ip-geolocation package first
        country = None
        city = None
        try:
            # The package exposes decorators and utilities; attempt to import its lookup function.
            # This import is guarded — it's okay if package isn't installed.
            from django_ip_geolocation.providers import get_location  # best-effort import
            # get_location should accept an IP and return a dict-like result; wrap in try/except
            try:
                result = get_location(ip)
                # Try to capture common keys
                country = result.get("country") or result.get("country_name") or result.get("country_code")
                city = result.get("city")
            except Exception as e:
                logger.debug("django-ip-geolocation provider get_location failed for %s: %s", ip, e)
        except Exception:
            # Package not installed or import failed — fallback
            pass

        # Fallback: use a free public API (ip-api.com). Note: limited usage and dependent on external availability.
        if not country and not city:
            try:
                import requests
                resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                if resp.status_code == 200:
                    data = resp.json()
                    # ip-api returns {"status":"success","country":"...","city":"..."}
                    if data.get("status") == "success":
                        country = data.get("country")
                        city = data.get("city")
            except Exception as e:
                logger.error("Geolocation fallback lookup failed for %s: %s", ip, e)

        # Normalize None -> empty string maybe, store in cache
        geo = {"country": country or "", "city": city or ""}
        try:
            cache.set(cache_key, geo, GEO_CACHE_TTL)
        except Exception as e:
            logger.error("Failed to cache geolocation for %s: %s", ip, e)

        return geo.get("country"), geo.get("city")

