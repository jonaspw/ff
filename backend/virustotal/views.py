# backend/virustotal/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import VirusTotalService


class VirusTotalLookupView(APIView):
    """
    GET /api/virustotal/?q=<ip_lub_domena>

    Sprawdza reputację IP lub domeny w VirusTotal.
    Zwraca wyniki silników AV i dodatkowe metadane.
    """

    def get(self, request):
        query = request.query_params.get("q", "").strip()

        if not query:
            return Response(
                {"error": "Enter IP address or domain"},
                status=status.HTTP_400_BAD_REQUEST
            )

        service = VirusTotalService()
        result  = service.lookup(query)

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({"status": "ok", **result})