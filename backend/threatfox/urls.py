from django.urls import path
from .views import RecentIOCsView, SearchIOCView

urlpatterns = [
    path("recent/", RecentIOCsView.as_view(),  name="recent-iocs"),
    path("search/", SearchIOCView.as_view(),   name="search-ioc"),
]