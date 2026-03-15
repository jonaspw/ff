# backend/abuseipdb/views.py

import ipaddress
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import AbuseIPDBService


class AbuseIPDBCheckView(APIView):
    """
    GET /api/abuseipdb/?ip=185.220.101.47

    Sprawdza reputację IP w AbuseIPDB.
    Zwraca abuse score 0-100 i kategorie ataków.
    Działa tylko dla adresów IP.
    """

    def get(self, request):
        ip = request.query_params.get("ip", "").strip()

        if not ip:
            return Response(
                {"error": "Podaj adres IP"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Walidacja IP
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                return Response(
                    {"error": "Prywatne adresy IP nie są dostępne w AbuseIPDB"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except ValueError:
            return Response(
                {"error": "Podaj poprawny adres IP"},
                status=status.HTTP_400_BAD_REQUEST
            )

        service = AbuseIPDBService()
        result  = service.check_ip(ip)

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({"status": "ok", **result})