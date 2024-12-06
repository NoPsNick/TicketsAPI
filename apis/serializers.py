from django.contrib.auth import get_user_model
from rest_framework.relations import PrimaryKeyRelatedField
from rest_framework.serializers import Serializer, CharField, EmailField, ValidationError, ModelSerializer

from tickets.models import Ticket, TicketResponse

User = get_user_model()


class RegisterSerializer(Serializer):
    username = CharField(max_length=150)
    email = EmailField()
    password = CharField(write_only=True, min_length=8)

    def validate_username(self, username):
        if User.objects.filter(username=username).exists():
            raise ValidationError("O nome de usuário já está em uso.")
        return username

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            raise ValidationError("O email já está em uso.")
        return email

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class TicketSerializer(ModelSerializer):
    receiver = PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Ticket
        fields = ['title', 'description', 'receiver', 'status']
        extra_kwargs = {
            'status': {'default': Ticket.pending, 'read_only': True}
        }

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['sender'] = request.user
        return super().create(validated_data)


class ResponseSerializer(ModelSerializer):
    class Meta:
        model = TicketResponse
        fields = ['id', 'ticket', 'responder', 'content', 'created_at']
        read_only_fields = ['id', 'ticket', 'responder', 'created_at']


class TicketListSerializer(ModelSerializer):
    responses = ResponseSerializer(many=True, read_only=True)

    class Meta:
        model = Ticket
        fields = ['id', 'title', 'description', 'sender', 'receiver', 'status', 'created_at', 'responses']
