from django.urls import path
from .views import ShodanHostView, ShodanDomainView

urlpatterns = [
    path("host/", ShodanHostView.as_view(), name="shodan-host"),
    path("domain/", ShodanDomainView.as_view(), name="shodan-domain"),
]