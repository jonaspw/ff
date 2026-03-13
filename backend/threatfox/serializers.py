from rest_framework import serializers


class IOCSerializer(serializers.Serializer):
    """
    Definiuje strukturę pojedynczego IOC zwracanego przez API.
    """
    id               = serializers.CharField(read_only=True)
    ioc              = serializers.CharField()
    ioc_type         = serializers.CharField()
    ioc_type_desc    = serializers.CharField()
    threat_type      = serializers.CharField()
    malware          = serializers.CharField()
    malware_printable= serializers.CharField()
    confidence_level = serializers.IntegerField()
    first_seen       = serializers.CharField()
    last_seen        = serializers.CharField(required=False, allow_null=True)
    reporter         = serializers.CharField()
    tags             = serializers.ListField(
                            child=serializers.CharField(),
                            required=False,
                            allow_null=True
                       )


class RecentIOCsQuerySerializer(serializers.Serializer):
    """
    Waliduje parametry zapytania od użytkownika.
    """
    days = serializers.IntegerField(
        min_value=1,
        max_value=7,
        default=1,
        help_text="Za ile ostatnich dni pobrać IOC (1–7)"
    )


class SearchIOCQuerySerializer(serializers.Serializer):
    """
    Waliduje zapytanie wyszukiwania.
    """
    q = serializers.CharField(
        min_length=3,
        help_text="IP, domena lub hash do wyszukania"
    )