from rest_framework import serializers
import ipaddress
import re


class AnalyzeQuerySerializer(serializers.Serializer):
    q = serializers.CharField(
        min_length=3,
        max_length=253,
        help_text="Adres IP lub domena do analizy",
    )

    def validate_q(self, value):
        """
        Sprawdza czy podana wartość to poprawny IP lub domena.
        Jeśli nie — zwraca błąd z czytelnym komunikatem.
        """
        value = value.strip()

        # Sprawdź czy to IP
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                raise serializers.ValidationError(
                    "Prywatne adresy IP (192.168.x.x, 10.x.x.x) "
                    "nie są monitorowane."
                )
            return value
        except ValueError:
            pass

        # Sprawdź czy to domena
        domain_regex = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
        if re.match(domain_regex, value):
            return value

        raise serializers.ValidationError(
            "Podaj poprawny adres IP (np. 185.220.101.47) "
            "lub domenę (np. update-service.net)"
        )