from rest_framework import serializers
import ipaddress


class ShodanIPQuerySerializer(serializers.Serializer):
    ip = serializers.CharField(
        help_text="Adres IP do sprawdzenia w Shodan"
    )

    def validate_ip(self, value):
        value = value.strip()
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                raise serializers.ValidationError(
                    "Prywatne adresy IP nie są dostępne w Shodan."
                )
            return value
        except ValueError:
            raise serializers.ValidationError(
                "Podaj poprawny adres IP (np. 185.220.101.47)"
            )