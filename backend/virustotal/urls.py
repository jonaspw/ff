# backend/virustotal/urls.py

from django.urls import path
from .views import VirusTotalLookupView

urlpatterns = [
    path("", VirusTotalLookupView.as_view(), name="virustotal-lookup"),
]