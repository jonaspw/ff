# backend/analyzer/urls.py

from django.urls import path
from .views import AnalyzeView

urlpatterns = [
    path("", AnalyzeView.as_view(), name="analyze"),
]