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
                    "Private IP addresses are not available in Shodan."
                )
            return value
        except ValueError:
            raise serializers.ValidationError(
                "Please enter a valid IP address (e.g. 185.220.101.47)"
            )