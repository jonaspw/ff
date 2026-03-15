from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .services import AnalyzerService
from .serializers import AnalyzeQuerySerializer


class AnalyzeView(APIView):
    """
    GET /api/analyze/?q=<ip_lub_domena>

    Główny endpoint aplikacji.
    Odpytuje ThreatFox i CIRCL, zwraca zagregowany raport.

    Przykłady:
        GET /api/analyze/?q=185.220.101.47
        GET /api/analyze/?q=update-service.net
    """

    def get(self, request):
        # Waliduj wejście
        serializer = AnalyzeQuerySerializer(
            data=request.query_params
        )

        if not serializer.is_valid():
            return Response(
                {"error": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        query   = serializer.validated_data["q"]
        service = AnalyzerService()
        result  = service.analyze(query)

        return Response(result)


class APTProfileView(APIView):
    """
    GET /api/analyze/apt/?name=APT28
    GET /api/analyze/apt/?name=Fancy+Bear
    GET /api/analyze/apt/?name=Lazarus

    Zwraca pełny profil grupy APT:
    MITRE ATT&CK + ThreatFox IOC + CIRCL eventy
    """

    def get(self, request):
        name = request.query_params.get("name", "").strip()

        if not name or len(name) < 2:
            return Response(
                {"error": "Podaj nazwę grupy APT (min. 2 znaki)"},
                status=status.HTTP_400_BAD_REQUEST
            )

        service = AnalyzerService()
        result  = service.get_apt_profile(name)

        if not result["success"]:
            return Response(
                {"error": result["error"],
                 "threatfox": result.get("threatfox"),
                 "circl":     result.get("circl")},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response({"status": "ok", **result})