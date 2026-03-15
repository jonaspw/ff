# backend/crtsh/views.py

import ipaddress
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .services import CrtShService
from .serializers import CrtShQuerySerializer


class CrtShLookupView(APIView):
    """
    GET /api/crtsh/lookup/?q=<domena_lub_ip>

    Dla domeny: zwraca certyfikaty i subdomeny
    Dla IP: zwraca certyfikaty i domeny hostowane na tym IP
    """

    def get(self, request):
        serializer = CrtShQuerySerializer(
            data=request.query_params
        )

        if not serializer.is_valid():
            return Response(
                {"error": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        query   = serializer.validated_data["q"]
        service = CrtShService()

        # Wykryj typ zapytania
        try:
            ipaddress.ip_address(query)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            result = service.get_ip_certs(query)
        else:
            result = service.get_domain_certs(query)

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({"status": "ok", **result})