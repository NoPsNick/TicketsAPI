from rest_framework import serializers

from users.models import Sector

class SectorSerializer(serializers.ModelSerializer):

    class Meta:
        model = Sector
        fields = ['id', 'sector_name', 'sector_description', 'sector_leader']
        read_only_fields = ['id', 'sector_name', 'sector_description', 'sector_leader']
