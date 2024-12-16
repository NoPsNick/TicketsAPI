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
    sender = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    receivers = serializers.ListField(
        child=serializers.PrimaryKeyRelatedField(queryset=User.objects.all()),
        write_only=True,
        help_text="Lista de IDs dos usuários que receberão o ticket."
    )

    class Meta:
        model = Ticket
        fields = ['title', 'description', 'sender', 'receivers']

    def create(self, validated_data):
        # Extraindo dados e removendo 'receivers' para lidar separadamente
        receivers = validated_data.pop('receivers')
        request = self.context.get('request')

        # Criar o ticket com o remetente definido pelo usuário autenticado
        ticket = Ticket.objects.create(sender=request.user, **validated_data)

        # Criar as relações na tabela intermediária
        TicketReceiver.objects.bulk_create([
            TicketReceiver(ticket=ticket, user=receiver) for receiver in receivers
        ])

        return ticket


class TicketResponseSerializer(serializers.ModelSerializer):
    ticket = serializers.PrimaryKeyRelatedField(queryset=Ticket.objects.all())
    responder = UserSerializer(read_only=True)
    class Meta:
        model = TicketResponse
        fields = ['id', 'ticket', 'responder', 'content', 'created_at']
        read_only_fields = ['id', 'ticket', 'responder', 'created_at']


class TicketReceiverSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = TicketReceiver
        fields = ['id', 'user', 'ticket', 'read', 'created_at', 'read_at']
        read_only_fields = ['id', 'ticket', 'read', 'created_at', 'read_at']


class TicketListSerializer(serializers.ModelSerializer):
    responses = TicketResponseSerializer(many=True, read_only=True)
    receivers = TicketReceiverSerializer(many=True, read_only=True)

    class Meta:
        model = Ticket
        fields = ['id', 'title', 'description', 'sender', 'receivers', 'status', 'created_at', 'responses']
        read_only_fields = ['id', 'sender', 'created_at']
