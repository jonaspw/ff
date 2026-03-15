# backend/abuseipdb/urls.py

from django.urls import path
from .views import AbuseIPDBCheckView

urlpatterns = [
    path("", AbuseIPDBCheckView.as_view(), name="abuseipdb-check"),
]