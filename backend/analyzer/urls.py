# backend/analyzer/urls.py

from django.urls import path
from .views import AnalyzeView, APTProfileView

urlpatterns = [
    path("", AnalyzeView.as_view(), name="analyze"),
    path("apt/", APTProfileView.as_view(),  name="apt-profile"),
]