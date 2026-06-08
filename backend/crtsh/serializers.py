# backend/crtsh/serializers.py

from rest_framework import serializers
import ipaddress
import re


class CrtShQuerySerializer(serializers.Serializer):
    q = serializers.CharField(
        min_length=3,
        max_length=253,
        help_text="Domena lub adres IP",
    )

    def validate_q(self, value):
        value = value.strip()

        # Sprawdź czy to IP
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass

        # Sprawdź czy to domena
        if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', value):
            return value

        raise serializers.ValidationError(
            "Please provide a valid IP address or domain"
        )