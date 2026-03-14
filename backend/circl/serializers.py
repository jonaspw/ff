from rest_framework import serializers


class EventQuerySerializer(serializers.Serializer):
    uuid = serializers.CharField(
        min_length=36,
        max_length=36,
        help_text="UUID eventu z manifestu CIRCL"
    )


class ActorSearchSerializer(serializers.Serializer):
    actor = serializers.CharField(
        min_length=2,
        max_length=100,
        help_text="Nazwa grupy APT np. APT28, Lazarus",
    )