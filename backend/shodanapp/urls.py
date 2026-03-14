from django.urls import path
from .views import ShodanHostView

urlpatterns = [
    path("host/", ShodanHostView.as_view(), name="shodan-host"),
]