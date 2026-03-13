from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .services import ThreatFoxService
from .serializers import (
    RecentIOCsQuerySerializer,
    SearchIOCQuerySerializer,
    IOCSerializer,
)


class RecentIOCsView(APIView):
    """
    GET /api/threatfox/recent/?days=1

    Zwraca najnowsze IOC z ThreatFox.
    Parametr days: 1-7 (ile ostatnich dni)
    """

    def get(self, request):
        # Waliduj parametry zapytania przez serializer
        query_serializer = RecentIOCsQuerySerializer(
            data=request.query_params
        )

        if not query_serializer.is_valid():
            return Response(
                {"error": query_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        days = query_serializer.validated_data["days"]

        # Wywołaj serwis
        service = ThreatFoxService()
        result  = service.get_recent_iocs(days=days)

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({
            "status": "ok",
            "days":   days,
            "count":  result["count"],
            "iocs":   result["iocs"],
        })


class SearchIOCView(APIView):
    """
    GET /api/threatfox/search/?q=185.220.101.47

    Wyszukuje konkretny IOC w ThreatFox.
    """

    def get(self, request):
        query_serializer = SearchIOCQuerySerializer(
            data=request.query_params
        )

        if not query_serializer.is_valid():
            return Response(
                {"error": query_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        search_term = query_serializer.validated_data["q"]

        service = ThreatFoxService()
        result  = service.search_ioc(search_term)

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response({
            "status":      "ok",
            "search_term": search_term,
            "count":       result["count"],
            "iocs":        result["iocs"],
        })