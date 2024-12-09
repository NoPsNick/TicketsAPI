from django.contrib.auth import get_user_model
from rest_framework.relations import PrimaryKeyRelatedField
from rest_framework import serializers

from tickets.models import Ticket, TicketResponse
from users.serializers import SectorSerializer

User = get_user_model()


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)

    def validate_username(self, username):
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError("O nome de usuário já está em uso.")
        return username

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("O email já está em uso.")
        return email

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class TicketSerializer(serializers.ModelSerializer):
    receiver = PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Ticket
        fields = ['title', 'description', 'receiver', 'status']
        read_only_fields = ['receiver']
        extra_kwargs = {
            'status': {'default': Ticket.STATUS_PENDING, 'read_only': True}
        }

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['sender'] = request.user
        return super().create(validated_data)


class TicketResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = TicketResponse
        fields = ['id', 'ticket', 'responder', 'content', 'created_at']
        read_only_fields = ['id', 'ticket', 'responder', 'created_at']


class TicketListSerializer(serializers.ModelSerializer):
    responses = TicketResponseSerializer(many=True, read_only=True)

    class Meta:
        model = Ticket
        fields = ['id', 'title', 'description', 'sender', 'receiver', 'status', 'created_at', 'responses']
        read_only_fields = ['id', 'sender', 'receiver', 'status', 'created_at']


class UserSerializer(serializers.ModelSerializer):
    sector = SectorSerializer(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'date_joined', 'is_staff', 'is_active', 'is_superuser', 'sector']
        read_only_fields = ['id', 'username', 'email', 'date_joined', 'is_staff', 'is_active', 'is_superuser']
