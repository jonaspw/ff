# backend/crtsh/urls.py

from django.urls import path
from .views import CrtShLookupView

urlpatterns = [
    path("lookup/", CrtShLookupView.as_view(), name="crtsh-lookup"),
]