# from django.db import models
# Create your models here.
from django.db import models


class RequestLog(models.Model):
    """
    Stores a simple audit of incoming requests:
    - ip_address: client's IP (supports IPv4 and IPv6)
    - path: request path
    - timestamp: when the request was received
    """
    ip_address = models.CharField(max_length=45)  # enough for IPv6
    path = models.CharField(max_length=2048)
    country = models.CharField(max_length=100, blank=True)  # ISO country name or code
    city = models.CharField(max_length=100, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-timestamp",)
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"

    def __str__(self):
        return f"{self.ip_address} @ {self.timestamp.isoformat()} -> {self.path} ({self.city}, {self.country})"
        # return f"{self.ip_address} @ {self.timestamp.isoformat()} -> {self.path}"


class BlockedIP(models.Model):
    """
    Blacklisted IP addresses. If an incoming request's client IP matches one
    of these entries, the middleware will return HTTP 403 Forbidden.
    """
    ip_address = models.CharField(max_length=45, unique=True)
    reason = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"

    def __str__(self):
        return self.ip_address


class SuspiciousIP(models.Model):
    """
    IPs flagged by anomaly detection, with a concise reason and metadata.
    """
    ip_address = models.CharField(max_length=45, db_index=True)
    reason = models.CharField(max_length=255)  # e.g. "high_request_rate", "sensitive_path_access"
    details = models.TextField(blank=True)      # freeform details like counts or paths
    detected_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(null=True, blank=True)  # optional: last activity time
    resolved = models.BooleanField(default=False)           # mark when investigated/cleared

    class Meta:
        ordering = ("-detected_at",)
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["detected_at"]),
        ]

    def __str__(self):
        return f"{self.ip_address} ({self.reason})"
