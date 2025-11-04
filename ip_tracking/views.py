from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from ratelimit.decorators import ratelimit
from ratelimit.exceptions import Ratelimited
from django.views.decorators.http import require_POST

# --- Login view (anonymous users) ---
@require_POST
@ratelimit(key="ip", rate="5/m", method="POST", block=True)
def login_view(request):
    """
    Example login endpoint protected with 5 requests per minute per IP.
    - block=True causes django-ratelimit to immediately return HTTP 429.
    - In dev, you can change block=False to handle it in-code (see commented example).
    """
    # Your existing login code goes here.
    # For demonstration return a dummy response:
    return JsonResponse({"ok": True, "msg": "login succeeded (demo)."})

# --- Example authenticated sensitive view (10 requests/minute) ---
# This endpoint requires authentication and has a higher limit.
@login_required
@ratelimit(key="ip", rate="10/m", method="ALL", block=True)
def sensitive_authenticated_view(request):
    """
    A sample authenticated view protected by 10 requests/minute per IP.
    """
    return JsonResponse({"ok": True, "msg": "sensitive data (demo)."})

# --- Alternative: handle rate limit manually (block=False) ---
# If you prefer to handle the 429 yourself, use block=False and inspect request.limited:
#
# @ratelimit(key="ip", rate="5/m", method="POST", block=False)
# def login_view(request):
#     if getattr(request, "limited", False):
#         return JsonResponse({"detail": "Too many requests"}, status=429)
#     ...

