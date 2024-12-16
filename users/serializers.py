from rest_framework import serializers

from users.models import Sector



class SectorSerializer(serializers.ModelSerializer):
    leader = serializers.SerializerMethodField()

    class Meta:
        model = Sector
        fields = ['id', 'sector_name', 'sector_description', 'leader']
        read_only_fields = ['id', 'sector_name', 'sector_description', 'leader']

    @staticmethod
    def get_leader(obj):
        from apis.serializers import UserSerializer
        if obj.sector_leader:
            return UserSerializer(obj.sector_leader).data
        return None
