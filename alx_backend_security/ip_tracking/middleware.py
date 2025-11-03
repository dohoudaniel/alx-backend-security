import logging

logger = logging.getLogger(__name__)

class IPLoggingMiddleware:
    """
    Middleware that logs client IP, request path and timestamp to the RequestLog model.

    Notes:
    - Uses X-Forwarded-For header if present (commonly set by proxies/load-balancers).
    - Wraps DB write in try/except so middleware never breaks requests if logging fails.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Resolve client IP (prefer X-Forwarded-For if present)
        ip = self._get_client_ip(request)
        path = getattr(request, "path", request.path if hasattr(request, "path") else "")

        # Perform a non-blocking/robust save to DB; failure should not break the app
        try:
            # Import locally to avoid potential circular imports at module-import time
            from .models import RequestLog
            RequestLog.objects.create(ip_address=ip, path=path)
        except Exception as exc:
            # Log the error but do not raise — request processing should continue.
            logger.exception("Failed to log request for IP %s path %s: %s", ip, path, exc)

        response = self.get_response(request)
        return response

    def _get_client_ip(self, request):
        """
        Determine the client's IP address.
        - If behind a proxy that sets X-Forwarded-For, take the first (client) IP.
        - Fall back to REMOTE_ADDR.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            # X-Forwarded-For may be a comma-separated list: client, proxy1, proxy2
            # We take the first item which should be the originating client IP.
            ip = x_forwarded_for.split(",")[0].strip()
            if ip:
                return ip
        # Fallback
        return request.META.get("REMOTE_ADDR", "")

