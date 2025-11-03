# ip_tracking/middleware.py
import logging
from django.http import HttpResponseForbidden

logger = logging.getLogger(__name__)

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

