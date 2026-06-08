from rest_framework import serializers
import ipaddress
import re


class AnalyzeQuerySerializer(serializers.Serializer):
    q = serializers.CharField(
        min_length=3,
        max_length=253,
        help_text="IP address or domain to be analyzed",
    )

    def validate_q(self, value):
        """
        Sprawdza czy podana wartość to poprawny IP lub domena.
        """
        value = value.strip()

        # Sprawdź czy to IP
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                raise serializers.ValidationError(
                    "Private IP addresses (192.168.x.x, 10.x.x.x) "
                    "are not monitored."
                )
            return value
        except ValueError:
            pass

        # Sprawdź czy to domena
        domain_regex = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
        if re.match(domain_regex, value):
            return value

        raise serializers.ValidationError(
            "Please provide a valid IP address (185.220.101.47) "
            "or domain (update-service.net)"
        )
    