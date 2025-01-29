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
    sender = serializers.HiddenField(default=serializers.CurrentUserDefault())
    receivers = serializers.ListField(
        child=serializers.PrimaryKeyRelatedField(queryset=User.objects.all()),
        write_only=True,
        help_text="Lista de IDs dos usuários que receberão o ticket."
    )
    last_status_changed_by = serializers.SerializerMethodField()

    class Meta:
        model = Ticket
        fields = [
            'id', 'title', 'description', 'sender', 'receivers', 'status',
            'created_at', 'last_status_changed_by'
        ]
        read_only_fields = ['id', 'created_at', 'last_status_changed_by', 'sender']

    def get_last_status_changed_by(self, obj):
        return UserSerializer(obj.last_status_changed_by).data if obj.last_status_changed_by else None

    def create(self, validated_data):
        receivers = validated_data.pop('receivers')
        ticket = Ticket.objects.create(**validated_data)

        TicketReceiver.objects.bulk_create([
            TicketReceiver(ticket=ticket, user=receiver) for receiver in receivers
        ])
        return ticket

    def validate(self, attrs):
        if not attrs.get('receivers'):
            raise serializers.ValidationError("Você deve incluir pelo menos um receptor.")
        return attrs


class TicketResponseSerializer(serializers.ModelSerializer):
    ticket = serializers.PrimaryKeyRelatedField(queryset=Ticket.objects.all())
    responder = UserSerializer(read_only=True)

    class Meta:
        model = TicketResponse
        fields = ['id', 'ticket', 'responder', 'content', 'created_at']
        read_only_fields = ['id', 'responder', 'created_at']

    def create(self, validated_data):
        validated_data['responder'] = self.context['request'].user
        return super().create(validated_data)
