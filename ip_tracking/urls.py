# ip_tracking/urls.py
from django.urls import path
from .views import login_view, sensitive_authenticated_view

urlpatterns = [
    path("login/", login_view, name="login"),
    path("sensitive-auth/", sensitive_authenticated_view, name="sensitive-auth"),
]

