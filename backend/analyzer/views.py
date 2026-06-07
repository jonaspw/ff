from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from analyzer.config import get_effective_weights
from .config import load_config, save_config
from .services import AnalyzerService
from .serializers import AnalyzeQuerySerializer


class AnalyzeView(APIView):
    """
    GET /api/analyze/?q=<ip_lub_domena>

    Opcjonalnie przyjmuje nagłówek X-Scoring-Config
    z konfiguracją wag w formacie JSON.
    Jeśli brak nagłówka — używa domyślnych wag.
    """
    permission_classes = []

    def get(self, request):
        import json

        serializer = AnalyzeQuerySerializer(
            data=request.query_params
        )
        if not serializer.is_valid():
            return Response(
                {"error": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        query = serializer.validated_data["q"]

        # Wczytaj konfigurację z nagłówka jeśli jest
        weights = None
        config_header = request.headers.get("X-Scoring-Config")
        if config_header:
            try:
                config  = json.loads(config_header)
                weights = {
                    source: (
                        w if config.get("enabled", {}).get(source, True)
                        else 0
                    )
                    for source, w in config.get("weights", {}).items()
                }
            except Exception:
                pass

        # Fallback do domyślnych wag
        if not weights:
            weights = get_effective_weights()

        
        config_header = request.headers.get("X-Scoring-Config")
        print(f"[DEBUG CONFIG] header={config_header}")
        print(f"[DEBUG WEIGHTS] weights={weights}")

        service = AnalyzerService()
        result  = service.analyze(query, weights=weights)
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
    

class AnalyzeWithConfigView(APIView):
    """
    POST /api/analyze/config/

    Analiza z własną konfiguracją wag źródeł.
    Body JSON:
    {
        "q": "185.220.101.47",
        "weights": {
            "virustotal": 40,
            "abuseipdb":  30,
            "threatfox":  20,
            "circl":      10,
            "shodan":     0
        }
    }
    """

    def post(self, request):
        query   = request.data.get("q", "").strip()
        weights = request.data.get("weights", None)

        if not query:
            return Response(
                {"error": "Podaj adres IP lub domenę w polu 'q'"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Walidacja wag
        if weights:
            total = sum(weights.values())
            if total != 100:
                return Response(
                    {"error": f"Suma wag musi wynosić 100% (aktualnie: {total}%)"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        service = AnalyzerService()
        result  = service.analyze(query, weights=weights)
        return Response(result)
    

class ScoringConfigView(APIView):
    """
    GET  /api/analyze/scoring-config/  — pobierz aktualną konfigurację
    POST /api/analyze/scoring-config/  — zapisz nową konfigurację
    """

    def get(self, request):
        """Zwraca aktualną konfigurację scoringu."""
        config = load_config()
        return Response({"status": "ok", **config})

    def post(self, request):
        """
        Zapisuje konfigurację scoringu.
        Body JSON:
        {
            "weights": {
                "virustotal": 40,
                "abuseipdb":  30,
                "threatfox":  20,
                "circl":      10,
                "shodan":     0
            },
            "enabled": {
                "virustotal": true,
                "abuseipdb":  true,
                "threatfox":  true,
                "circl":      true,
                "shodan":     false
            }
        }
        """
        weights = request.data.get("weights")
        enabled = request.data.get("enabled")

        if not weights or not enabled:
            return Response(
                {"error": "Wymagane pola: weights i enabled"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            config = save_config(weights, enabled)
            return Response({
                "status":  "ok",
                "message": "Konfiguracja zapisana",
                **config
            })
        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        