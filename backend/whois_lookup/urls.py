# backend/whois_lookup/urls.py

from django.urls import path
from .views import WhoisLookupView

urlpatterns = [
    path("", WhoisLookupView.as_view(), name="whois-lookup"),
]