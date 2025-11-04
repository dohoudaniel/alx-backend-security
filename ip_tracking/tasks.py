# ip_tracking/tasks.py
import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Max

from .models import RequestLog, SuspiciousIP

logger = logging.getLogger(__name__)

# tuning parameters (easy to change)
REQUEST_THRESHOLD_PER_HOUR = 100
SENSITIVE_PATHS = ["/admin", "/login", "/wp-login.php", "/staff/login"]


@shared_task(bind=True)
def detect_suspicious_ips(self):
    """
    Celery task to run anomaly detection:

    1) Flags IPs with > REQUEST_THRESHOLD_PER_HOUR requests in the last hour.
    2) Flags IPs that accessed sensitive paths in the last hour.
    3) Creates or updates SuspiciousIP entries with reason and details.
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    logger.info("Anomaly detection started at %s (window since %s)", now.isoformat(), one_hour_ago.isoformat())

    # 1) High request rate detection
    try:
        high_rate_qs = (
            RequestLog.objects
            .filter(timestamp__gte=one_hour_ago)
            .values("ip_address")
            .annotate(requests=Count("id"), last_seen=Max("timestamp"))
            .filter(requests__gt=REQUEST_THRESHOLD_PER_HOUR)
        )

        for row in high_rate_qs:
            ip = row["ip_address"]
            req_count = row["requests"]
            last_seen = row.get("last_seen")

            reason = "high_request_rate"
            details = f"requests_last_hour={req_count}"

            # Create or update SuspiciousIP entry
            obj, created = SuspiciousIP.objects.update_or_create(
                ip_address=ip,
                reason=reason,
                defaults={
                    "details": details,
                    "last_seen": last_seen,
                    "resolved": False,
                },
            )
            if created:
                logger.warning("Flagged suspicious IP (high rate): %s - %s", ip, details)
            else:
                logger.info("Updated suspicious IP (high rate): %s - %s", ip, details)
    except Exception as exc:
        logger.exception("Error during high-rate detection: %s", exc)

    # 2) Sensitive path access detection
    try:
        # Build OR query for paths
        sensitive_qs = (
            RequestLog.objects
            .filter(timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS)
            .values("ip_address")
            .annotate(access_count=Count("id"), last_seen=Max("timestamp"))
        )

        for row in sensitive_qs:
            ip = row["ip_address"]
            access_count = row["access_count"]
            last_seen = row.get("last_seen")

            reason = "sensitive_path_access"
            details = f"sensitive_paths_accessed={access_count}"

            obj, created = SuspiciousIP.objects.update_or_create(
                ip_address=ip,
                reason=reason,
                defaults={
                    "details": details,
                    "last_seen": last_seen,
                    "resolved": False,
                },
            )
            if created:
                logger.warning("Flagged suspicious IP (sensitive path): %s - %s", ip, details)
            else:
                logger.info("Updated suspicious IP (sensitive path): %s - %s", ip, details)
    except Exception as exc:
        logger.exception("Error during sensitive-path detection: %s", exc)

    logger.info("Anomaly detection finished at %s", timezone.now().isoformat())
    return {"status": "ok", "time": timezone.now().isoformat()}

