from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

from apis.serializers import RegisterSerializer, TicketSerializer, TicketListSerializer, ResponseSerializer
from tickets.models import Ticket, TicketResponse

User = get_user_model()


class BaseView(APIView):
    """
    Classe base para reutilizar lógica comum.
    """
    permission_classes = [IsAuthenticated]

    def get_user_tickets(self, user, role):
        """
        Retorna os tickets de um usuário como sender ou receiver.
        """
        if user.is_staff:
            return Ticket.objects.all()
        elif role == "sent":
            return Ticket.objects.filter(sender=user)
        elif role == "received":
            return Ticket.objects.filter(receiver=user)
        return Ticket.objects.none()


class RegisterView(BaseView):
    permission_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Usuário criado com sucesso!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer


class LogoutView(BaseView):
    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({"error": "Token de refresh não fornecido."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Deslogou-se com sucesso!"}, status=status.HTTP_205_RESET_CONTENT)
        except TokenError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CreateTicketView(BaseView):
    def post(self, request):
        serializer = TicketSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetUsersView(BaseView):
    def get(self, request):
        paginator = PageNumberPagination()
        paginator.page_size = 10
        users = User.objects.all().values(
            'id', 'username', 'email', 'date_joined', 'is_staff', 'is_active', 'is_superuser'
        )
        paginated_users = paginator.paginate_queryset(users, request)
        return paginator.get_paginated_response(paginated_users)


class GetSentTicketsView(BaseView):
    def get(self, request):
        tickets = self.get_user_tickets(request.user, "sent")
        serializer = TicketListSerializer(tickets, many=True)
        return Response(serializer.data)


class GetReceivedTicketsView(BaseView):
    def get(self, request):
        tickets = self.get_user_tickets(request.user, "received")
        serializer = TicketListSerializer(tickets, many=True)
        return Response(serializer.data)


class CreateTicketResponseView(BaseView):
    def post(self, request, ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)

        if request.user not in [ticket.sender, ticket.receiver]:
            return Response({"error": "Você não tem permissão para responder este ticket."}, status=status.HTTP_403_FORBIDDEN)

        content = request.data.get('content')
        if not content:
            raise ValidationError({"content": "O conteúdo da resposta não pode estar vazio."})

        ticket_response = TicketResponse.objects.create(
            ticket=ticket,
            responder=request.user,
            content=content
        )
        return Response({
            "id": ticket_response.id,
            "ticket": ticket_response.ticket.id,
            "responder": ticket_response.responder.username,
            "content": ticket_response.content,
            "created_at": ticket_response.created_at
        }, status=status.HTTP_201_CREATED)


class GetTicketResponsesView(BaseView):
    def get(self, request, ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)
        responses = ticket.responses.all()
        serializer = ResponseSerializer(responses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
