from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .services import CIRCLFeedService
from .serializers import EventQuerySerializer, ActorSearchSerializer


class SyncManifestView(APIView):
    """
    POST /api/circl/sync/
    Synchronizuje manifest z CIRCL — wykrywa nowe eventy.
    """
    def post(self, request):
        service = CIRCLFeedService()
        result  = service.sync_manifest()

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        return Response({"status": "ok", **result})


class ManifestView(APIView):
    """
    GET /api/circl/manifest/
    Zwraca listę eventów z lokalnej bazy — zero HTTP do CIRCL.
    """
    def get(self, request):
        service = CIRCLFeedService()
        result  = service.get_manifest_local()
        return Response({"status": "ok", **result})


class EventDetailView(APIView):
    """
    GET /api/circl/event/?uuid=<UUID>
    Zwraca IOC z konkretnego eventu.
    """
    def get(self, request):
        serializer = EventQuerySerializer(data=request.query_params)

        if not serializer.is_valid():
            return Response(
                {"error": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        uuid    = serializer.validated_data["uuid"]
        service = CIRCLFeedService()
        result  = service.get_event(uuid)

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_404_NOT_FOUND
            )
        return Response({"status": "ok", **result})


class ActorSearchView(APIView):
    """
    GET /api/circl/search/?actor=APT28
    Szuka eventów po nazwie grupy APT w lokalnej bazie.
    """
    def get(self, request):
        serializer = ActorSearchSerializer(data=request.query_params)

        if not serializer.is_valid():
            return Response(
                {"error": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        actor   = serializer.validated_data["actor"]
        service = CIRCLFeedService()
        result  = service.search_by_actor(actor)
        return Response({"status": "ok", **result})
    

class FullSyncView(APIView):
    """
    POST /api/circl/full-sync/

    Pobiera WSZYSTKIE eventy z CIRCL do lokalnej bazy.
    Wywołaj tylko raz — przy pierwszym uruchomieniu.
    Może trwać 15-30 minut.
    Bezpieczne do wielokrotnego wywołania — pomija już pobrane.
    """
    def post(self, request):
        service = CIRCLFeedService()
        result  = service.full_sync()

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        return Response({"status": "ok", **result})