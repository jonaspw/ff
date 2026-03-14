from django.urls import path
from .views import (
    SyncManifestView,
    ManifestView,
    EventDetailView,
    ActorSearchView,
    FullSyncView
)

urlpatterns = [
    path("sync/",     SyncManifestView.as_view(), name="circl-sync"),
    path("full-sync/", FullSyncView.as_view(), name="circl-full-sync"),
    path("manifest/", ManifestView.as_view(),     name="circl-manifest"),
    path("event/",    EventDetailView.as_view(),  name="circl-event"),
    path("search/",   ActorSearchView.as_view(),  name="circl-search"),
]