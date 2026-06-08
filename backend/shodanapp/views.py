from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .services import ShodanService
from .serializers import ShodanIPQuerySerializer


class ShodanHostView(APIView):
    """
    GET /api/shodan/host/?ip=185.220.101.47

    Zwraca pełne informacje o hoście z Shodan:
    porty, bannery, certyfikaty, ASN, lokalizację.
    """

    def get(self, request):
        serializer = ShodanIPQuerySerializer(
            data=request.query_params
        )

        if not serializer.is_valid():
            return Response(
                {"error": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        ip      = serializer.validated_data["ip"]
        service = ShodanService()
        result  = service.get_host_info(ip)

        if not result["success"]:
            # Zwróć 404 jeśli Shodan nie ma danych dla tego IP
            if result.get("code") == "NOT_FOUND":
                return Response(
                    {"error": result["error"]},
                    status=status.HTTP_404_NOT_FOUND
                )
            return Response(
                {"error": result["error"]},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({
            "status": "ok",
            **result,
        })
    

class ShodanDomainView(APIView):
    """
    GET /api/shodan/domain/?domain=update-service.net

    Zwraca dane DNS dla domeny z Shodan:
    subdomeny, rekordy A/MX/NS/TXT, IP.
    """

    def get(self, request):
        domain = request.query_params.get("domain", "").strip()

        if not domain:
            return Response(
                {"error": "Enter your domain"},
                status=status.HTTP_400_BAD_REQUEST
            )

        service = ShodanService()
        result  = service.get_domain_info(domain)

        if not result["success"]:
            return Response(
                {"error": result["error"]},
                status=status.HTTP_404_NOT_FOUND
                if result.get("code") == "NOT_FOUND"
                else status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({"status": "ok", **result})