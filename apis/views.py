from typing import Optional, Iterable

from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

from apis.serializers import RegisterSerializer, TicketSerializer, TicketListSerializer, ResponseSerializer, \
    UserSerializer
from tickets.models import Ticket, TicketResponse
from users.models import Sector
from users.serializers import SectorSerializer

User = get_user_model()


def change_ticket_status(ticket, new_status):
    """
    Atualiza o status de um ticket, se necessário.
    """
    status_dict = Ticket.get_status_display_dict()

    # Verificar se o novo status é válido
    if new_status not in status_dict:
        valid_statuses = ", ".join(status_dict.keys())
        raise ValidationError({
            "status": f"'{new_status}' não é um status válido. Status válidos: {valid_statuses}."
        })

    # Verificar se o status já está atualizado
    if ticket.status == status_dict[new_status]:
        return ticket

    # Atualizar o status do ticket
    ticket.status = status_dict[new_status]
    ticket.save(update_fields=['status'])
    return ticket


class BaseView(APIView):
    """
    Classe base para reutilizar lógica comum.
    """
    permission_classes = [IsAuthenticated]

    @staticmethod
    def get_user_tickets(user, role):
        """
        Retorna os tickets de um usuário como sender ou receiver.
        """
        if user.is_staff or user.is_superuser:
            return Ticket.objects.all()
        if role == "sent":
            return Ticket.objects.filter(sender=user)
        if role == "received":
            return Ticket.objects.filter(receiver=user)
        return Ticket.objects.none()

    @staticmethod
    def permissions_check(
        user,
        allowed_users: Optional[Iterable[int]] = None,
        requires_superuser: bool = False,
        requires_staff: bool = False
    ) -> None:
        """
        Valida permissões genéricas para ações em recursos.

        Args:
            user: O usuário que está tentando acessar o recurso.
            allowed_users: Lista ou conjunto de IDs de usuários que têm permissão.
            requires_superuser: Se `True`, apenas superusuários podem acessar.
            requires_staff: Se `True`, apenas usuários staff podem acessar.

        Raises:
            ValidationError: Se o usuário não tiver permissão.
        """
        # Checar permissão de superusuário
        if requires_superuser and not user.is_superuser:
            raise ValidationError({"error": "Ação restrita a superusuários."})

        # Checar permissão de staff
        if requires_staff and not user.is_staff:
            raise ValidationError({"error": "Ação restrita a usuários staff."})

        # Checar se o usuário está na lista de permitidos
        if not user.is_superuser and not user.is_staff:
            if allowed_users is not None and user.pk not in allowed_users:
                raise ValidationError({"error": "Você não tem permissão para este recurso."})

    @staticmethod
    def get_sector_infos_from_request(request) -> dict:
        """
        Obtém e valida as informações do setor a partir do request.
        """
        name = request.data.get('name', 'Setor sem nome').strip()
        description = request.data.get('description', '').strip()
        leader_id = request.data.get('leader')

        # Validações
        if not name:
            raise ValidationError({"name": "O nome do setor não pode estar vazio."})

        leader = None
        if leader_id:
            try:
                leader = User.objects.get(id=leader_id)
            except User.DoesNotExist:
                raise ValidationError({"leader": "Usuário líder informado não existe."})

        return {
            "sector_name": name,
            "sector_description": description,
            "sector_leader": leader
        }


# Views de autenticação
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


# Views de Usuários
class GetUsersView(BaseView):
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangeUserSectorView(BaseView):
    def post(self, request, user_id: int):
        # Checa permissões para alterar setor (requires_staff=True)
        is_staff_action = 'new_sector_id' in request.data
        if is_staff_action:
            self.permissions_check(request.user, requires_staff=True)

        # Checa permissões para alterar status de staff (requires_superuser=True)
        is_superuser_action = 'is_staff' in request.data
        if is_superuser_action:
            self.permissions_check(request.user, requires_superuser=True)

        # Busca o usuário alvo
        user = get_object_or_404(User, id=user_id)

        # Altera o setor, se solicitado
        if is_staff_action:
            new_sector_id = request.data.get('new_sector_id')
            new_sector = None

            if new_sector_id:
                try:
                    new_sector_id = int(new_sector_id)
                    new_sector = Sector.objects.get(id=new_sector_id)
                except (ValueError, Sector.DoesNotExist):
                    raise ValidationError({"new_sector_id": "O ID do setor fornecido não é válido ou não existe."})

            if user.sector != new_sector:
                user.sector = new_sector
                user.save(update_fields=['sector'])
                sector_message = (
                    f"O setor do usuário #{user_id} foi atualizado para '{new_sector.sector_name}'."
                    if new_sector else f"O setor do usuário #{user_id} foi removido com sucesso."
                )
            else:
                sector_message = (
                    f"O setor do usuário #{user_id} já é '{new_sector.sector_name}'."
                    if new_sector else f"O setor do usuário #{user_id} já está vazio."
                )
        else:
            sector_message = None

        # Altera o status de staff, se solicitado
        if is_superuser_action:
            is_staff = request.data.get('is_staff', False)
            if user.is_staff != is_staff:
                user.is_staff = is_staff
                user.save(update_fields=['is_staff'])
                staff_message = (
                    f"O status de staff do usuário #{user_id} foi atualizado para {'habilitado' if is_staff
                    else 'desabilitado'}."
                )
            else:
                staff_message = (
                    f"O status de staff do usuário #{user_id} já está {'habilitado' if is_staff else 'desabilitado'}."
                )
        else:
            staff_message = None

        # Monta a resposta final
        response_message = {
            "sector_message": sector_message,
            "staff_message": staff_message,
        }
        # Remove mensagens nulas da resposta
        response_message = {key: msg for key, msg in response_message.items() if msg}

        return Response(response_message, status=status.HTTP_200_OK)


# Views de Tickets
class CreateTicketView(BaseView):
    def post(self, request):
        serializer = TicketSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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

        self.permissions_check(request.user, [ticket.sender.pk, ticket.receiver.pk])

        # Validar conteúdo
        content = request.data.get('content')
        if not content:
            raise ValidationError({"content": "O conteúdo da resposta não pode estar vazio."})

        # Criar resposta
        ticket_response = TicketResponse.objects.create(
            ticket=ticket,
            responder=request.user,
            content=content
        )

        # Retornar resposta criada
        return Response(
            {
                "id": ticket_response.id,
                "ticket": ticket.id,
                "responder": ticket_response.responder.username,
                "content": ticket_response.content,
                "created_at": ticket_response.created_at,
            },
            status=status.HTTP_201_CREATED
        )


class GetTicketResponsesView(BaseView):
    def get(self, request, ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)
        responses = ticket.responses.all()
        serializer = ResponseSerializer(responses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangeTicketStatusView(BaseView):
    def post(self, request, ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)

        # Validar permissões
        self.permissions_check(request.user, [ticket.sender.pk, ticket.receiver.pk])

        # Obter novo status
        new_status = request.data.get('status')
        if not new_status:
            return Response({"error": "Status não fornecido."}, status=status.HTTP_400_BAD_REQUEST)

        # Alterar status
        ticket = change_ticket_status(ticket, new_status)

        return Response(
            {"message": f"Status do chamado #{ticket.pk} alterado para '{new_status}' com sucesso!"},
            status=status.HTTP_200_OK
        )


class DeleteTicketView(BaseView):
    def post(self, request, ticket_id):
        ticket = get_object_or_404(Ticket, id=ticket_id)

        # Validar permissões
        self.permissions_check(request.user, requires_superuser=True)

        # Deletar ticket
        ticket.delete()
        return Response(
            {"message": f"Chamado #{ticket_id} deletado com sucesso!"},
            status=status.HTTP_200_OK
        )


# Views de Setores
class CreateSectorView(BaseView):
    def post(self, request):
        # Verificar permissão
        self.permissions_check(request.user, requires_staff=True)

        # Obter dados do request
        data_from_request = self.get_sector_infos_from_request(request)

        # Criar setor
        sector = Sector.objects.create(
            sector_name=data_from_request['sector_name'],
            sector_description=data_from_request['sector_description'],
            sector_leader=data_from_request['sector_leader']
        )

        # Retornar resposta
        return Response(
            {
                "message": f"Setor #{sector.pk} criado com sucesso!",
                "sector": {
                    "id": sector.pk,
                    "name": sector.sector_name,
                    "description": sector.sector_description,
                    "leader":
                        data_from_request['sector_leader'].username if data_from_request['sector_leader'] else None,
                }
            },
            status=status.HTTP_201_CREATED
        )


class ChangeSectorView(BaseView):
    def post(self, request, sector_id):
        # Verificar permissão
        self.permissions_check(request.user, requires_staff=True)

        # Buscar setor
        sector = get_object_or_404(Sector, id=sector_id)

        # Obter novas informações do request
        new_data = self.get_sector_infos_from_request(request)

        # Atualizar setor se necessário
        changed_fields = self.update_sector_if_needed(sector, new_data)

        # Montar resposta
        if changed_fields:
            return Response({
                "message": f"Setor #{sector_id} atualizado com sucesso.",
                "changed_fields": changed_fields
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "message": f"Nenhuma alteração foi feita no setor #{sector_id}."
            }, status=status.HTTP_200_OK)

    @staticmethod
    def update_sector_if_needed(sector, new_data):
        """
        Atualiza os campos do setor apenas se houverem alterações.
        """
        changed = []

        for field, new_value in new_data.items():
            old_value = getattr(sector, field)
            if old_value != new_value:
                setattr(sector, field, new_value)
                changed.append(field)

        if changed:
            sector.save(update_fields=changed)

        return changed


class DeleteSectorView(BaseView):
    def post(self, request, sector_id):
        self.permissions_check(request.user, requires_superuser=True)

        sector = get_object_or_404(Sector, id=sector_id)
        sector.delete()

        return Response({"message": f"Setor #{sector_id} deletado com sucesso!"},
                        status=status.HTTP_200_OK)


class GetSectorsView(BaseView):
    def get(self, request):
        sectors = Sector.objects.all()
        serializer = SectorSerializer(sectors, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)
