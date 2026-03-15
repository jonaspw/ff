# backend/whois_lookup/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import WhoisService


class WhoisLookupView(APIView):
    """
    GET /api/whois/?q=<ip_lub_domena>

    Zwraca dane rejestracyjne WHOIS/RDAP.
    Dla domen: registrar, daty, nameservery.
    Dla IP: ASN, właściciel, kraj, prefix.
    """

    def get(self, request):
        query = request.query_params.get("q", "").strip()

        if not query:
            return Response(
                {"error": "Podaj adres IP lub domenę"},
                status=status.HTTP_400_BAD_REQUEST
            )

        service = WhoisService()
        result  = service.lookup(query)

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response({"status": "ok", **result})