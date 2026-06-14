# backend/analyzer/urls.py

from django.urls import path
from .views import AnalyzeView, APTProfileView, AnalyzeWithConfigView, TechniqueDetailView

urlpatterns = [
    path("", AnalyzeView.as_view(), name="analyze"),
    path("apt/", APTProfileView.as_view(),  name="apt-profile"),
    path("apt/technique/", TechniqueDetailView.as_view(),  name="technique-detail"),
    path("config/", AnalyzeWithConfigView.as_view(), name="analyze-config"),
]