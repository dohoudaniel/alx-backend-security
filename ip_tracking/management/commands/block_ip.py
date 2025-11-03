# ip_tracking/management/commands/block_ip.py
from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = "Add an IP address to the BlockedIP list."

    def add_arguments(self, parser):
        parser.add_argument("ip_address", type=str, help="IP address to block")
        parser.add_argument("--reason", type=str, default="", help="Optional reason for blocking")

    def handle(self, *args, **options):
        ip = options["ip_address"].strip()
        reason = options.get("reason", "").strip()
        if not ip:
            raise CommandError("You must supply a valid ip_address")

        obj, created = BlockedIP.objects.get_or_create(ip_address=ip, defaults={"reason": reason})
        if created:
            self.stdout.write(self.style.SUCCESS(f"Blocked IP {ip} (reason: {reason})"))
        else:
            self.stdout.write(self.style.WARNING(f"IP {ip} is already blocked."))
            # Optionally update reason if provided
            if reason and obj.reason != reason:
                obj.reason = reason
                obj.save(update_fields=["reason"])
                self.stdout.write(self.style.SUCCESS(f"Updated reason for {ip}"))

