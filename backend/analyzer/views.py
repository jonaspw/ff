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