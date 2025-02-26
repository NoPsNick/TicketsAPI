from django.contrib.auth import get_user_model
from rest_framework import serializers

from tickets.models import Ticket, TicketResponse, TicketReceiver
from users.serializers import SectorSerializer

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    sector = SectorSerializer(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'date_joined', 'is_staff', 'is_active', 'is_superuser', 'sector']
        read_only_fields = ['id', 'username', 'email', 'date_joined', 'is_staff', 'is_active', 'is_superuser']


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
    sender = UserSerializer(read_only=True)
    receivers = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), many=True, write_only=True
    )
    receivers_display = serializers.SerializerMethodField()
    last_status_changed_by = serializers.SerializerMethodField()

    class Meta:
        model = Ticket
        fields = [
            'id', 'title', 'description', 'sender', 'receivers', 'receivers_display',
            'status', 'created_at', 'last_status_changed_by'
        ]
        read_only_fields = ['id', 'created_at', 'last_status_changed_by', 'sender']

    def get_last_status_changed_by(self, obj):
        return UserSerializer(obj.last_status_changed_by).data if obj.last_status_changed_by else None

    def get_receivers_display(self, obj):
        return UserSerializer(User.objects.filter(ticketreceiver__ticket=obj), many=True).data

    def create(self, validated_data):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError("Usuário não autenticado.")

        receivers = validated_data.pop('receivers')  # Lista de IDs dos usuários
        ticket = Ticket.objects.create(sender=request.user, **validated_data)  # Define o sender

        # Criar as relações na tabela TicketReceiver
        TicketReceiver.objects.bulk_create([
            TicketReceiver(ticket=ticket, user=receiver) for receiver in receivers
        ])

        return ticket

    def validate(self, attrs):
        if not attrs.get('receivers'):
            raise serializers.ValidationError("Você deve incluir pelo menos um receptor.")
        return attrs


class TicketResponseSerializer(serializers.ModelSerializer):
    ticket = serializers.PrimaryKeyRelatedField(read_only=True)
    responder = UserSerializer(read_only=True)

    class Meta:
        model = TicketResponse
        fields = ['id', 'ticket', 'responder', 'content', 'created_at']
        read_only_fields = ['id', 'responder', 'created_at', 'ticket']

    def create(self, validated_data):
        validated_data['responder'] = self.context['request'].user
        return TicketResponse.objects.create(**validated_data)
