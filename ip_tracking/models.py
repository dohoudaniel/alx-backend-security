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
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-timestamp",)
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"

    def __str__(self):
        return f"{self.ip_address} @ {self.timestamp.isoformat()} -> {self.path}"

