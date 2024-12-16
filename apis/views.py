from typing import Callable, List, Optional

from django.contrib.auth import get_user_model
from django.db.models import Prefetch
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.generics import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

from apis.serializers import RegisterSerializer, TicketSerializer, TicketListSerializer, TicketResponseSerializer, \
    UserSerializer
from tickets.models import Ticket, TicketResponse, TicketReceiver
from users.models import Sector
from users.serializers import SectorSerializer

User = get_user_model()


class BaseView(APIView):
    """
    Classe base para reutilizar lógica comum.
    """

    permission_classes = [IsAuthenticated]

    @staticmethod
    def get_allowed_users(ticket, only_sender = False):
        """
        Retorna os IDs dos usuários que enviaram ou receberam o ticket.

        ### Parâmetros:
        - `ticket`: Instância do ticket.

        ### Retornos:
        - Lista de IDs de usuários permitidos.
        """
        sent = ticket.sender
        if not only_sender:
            receivers = TicketReceiver.objects.filter(ticket=ticket).select_related('user').distinct()
            allowed_users = [sent.pk] + [rec.user.pk for rec in receivers]
        else:
            allowed_users = [sent.pk]
        return allowed_users

    @staticmethod
    def get_user_tickets(user, role):
        """
        Retorna os tickets relacionados a um usuário, seja como remetente ou destinatário.

        ### Parâmetros:
        - `user` (User): Instância do usuário solicitante.
        - `role` (str): "sent" para tickets enviados ou "received" para tickets recebidos.

        ### Retornos:
        - Queryset de tickets filtrados conforme o papel do usuário.
        """
        # Tickets para staff ou superusuários (acesso completo)
        if user.is_staff or user.is_superuser:
            return Ticket.objects.all().select_related('sender', 'last_status_changed_by'
                                                       ).prefetch_related('receivers', 'responses')

        # Tickets enviados pelo usuário
        if role == "sent":
            return Ticket.objects.filter(sender=user).select_related('last_status_changed_by'
                                                                     ).prefetch_related('receivers', 'responses')

        # Tickets recebidos pelo usuário
        if role == "received":
            return Ticket.objects.filter(ticketreceiver__user=user
                                         ).select_related('sender', 'last_status_changed_by'
                                                          ).prefetch_related('receivers', 'responses').distinct()

        # Nenhum ticket retornado para outros casos
        return Ticket.objects.none()

    @staticmethod
    def permissions_check(
            user,
            allowed_users: Optional[List[int]] = None,
            weight: int = 0,
            custom_rules: Optional[List[Callable[[object], bool]]] = None,
            error_message=None
    ) -> None:
        """
        Valida permissões genéricas com base em regras configuráveis.

        ### Parâmetros:
        - `user`: O usuário que está tentando acessar o recurso.
        - `allowed_users` (Optional[List[int]]): Lista de IDs de usuários permitidos.
        - `weight` (int): Peso mínimo necessário para acessar o recurso.
            - Exemplo:
                - Staff = 1
                - Superusuário = 2 (acumula com staff, totalizando 3).
        - `custom_rules` (Optional[List[Callable[[object], bool]]]): Lista de funções que recebem o usuário e retornam `True` se a regra for satisfeita.
            - Exemplo: `[lambda user: user.is_active]`.
        - `error_message` (Union[str, dict]): Mensagem de erro personalizada levantada se o usuário não tiver permissão.

        ### Regras:
        1. Se o usuário estiver na lista `allowed_users`, ele pode acessar.
        2. Se o peso do usuário for maior ou igual ao peso necessário, ele pode acessar.
        3. Se `custom_rules` estiver definido, todas as regras devem ser satisfeitas.
        4. Se nenhuma regra for satisfeita, uma `ValidationError` será levantada.

        ### Retornos:
        - Nenhum.

        ### Erros:
        - `ValidationError`: Levantado se o usuário não tiver permissão.
        """
        if error_message is None:
            error_message = {"error": "Você não tem permissão para este recurso."}
        # Determinar o peso do usuário
        user_weight = 0
        if user.is_staff:
            user_weight += 1
        if user.is_superuser:
            user_weight += 2

        # Regra 1: Usuário está na lista permitida
        if allowed_users and user.pk in allowed_users:
            return  # Permissão concedida

        # Regra 2: Usuário possui peso suficiente
        if user_weight >= weight:
            return  # Permissão concedida

        # Regra 3: Avaliar regras personalizadas
        if custom_rules:
            for rule in custom_rules:
                if not rule(user):
                    raise ValidationError(error_message)  # Falha em uma regra personalizada
            return  # Todas as regras foram satisfeitas

        # Nenhuma regra satisfeita
        raise ValidationError(error_message)

    @staticmethod
    def get_leader_from_request(leader_id, is_update):
        """
        Obtém o usuário líder a partir do request, se necessário.
        """
        if leader_id:
            if is_update and int(leader_id) == 0:
                return 0  # No leader for update with leader_id == 0

            try:
                return User.objects.get(id=leader_id)
            except User.DoesNotExist:
                raise ValidationError({"leader_id": "Usuário líder informado não existe."})
        return None

    def get_sector_infos_from_request(self, request, is_update=False) -> dict:
        """
        Obtém e valida as informações do setor a partir do request.

        Parâmetro is_update:
        - Se True, indica que estamos atualizando o setor, e a lógica de tratamento do 'leader' será diferente.
        """
        name = request.data.get('name')
        description = request.data.get('description')
        leader_id = request.data.get('leader_id')

        leader = self.get_leader_from_request(leader_id, is_update)

        sector = {
            "sector_name": name,
            "sector_description": description,
            "sector_leader": leader
        }

        # Retorna apenas os campos que têm valores, excluindo None
        return sector if not is_update else {key: value for key, value in sector.items() if value is not None}

    @staticmethod
    def change_ticket_status(ticket, user, new_status):
        """
        Atualiza a situação de um ticket para um destinatário específico.
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

        # Atualizar o status do chamado
        ticket.status = status_dict[new_status]
        ticket.last_status_changed_by = user
        ticket.save(update_fields=['status', 'last_status_changed_by'])
        return ticket


# Views de autenticação
class RegisterView(BaseView):
    """
    Endpoint para registrar novos usuários no sistema.

    ### Descrição:
    Permite que usuários se cadastrem fornecendo informações como nome, e-mail e senha.

    ### Parâmetros:
    - `POST /apis/registrar/`: JSON contendo:
        - `username` (str): Nome de usuário.
        - `email` (str): E-mail do usuário.
        - `password` (str): Senha do usuário.

    ### Retornos:
    - `201 CREATED`: Se o usuário foi registrado com sucesso.
    - `400 BAD REQUEST`: Se os dados fornecidos forem inválidos.
    """
    permission_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Usuário criado com sucesso!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    """
    Endpoint para autenticação de usuários.

    ### Parâmetros:
    - `POST /apis/login/`: JSON contendo:
        - `email` (str): Email do usuário.
        - `password` (str): Senha do usuário.

    ### Retornos:
    - `200 OK`: Token de acesso e refresh gerados com sucesso. 'access' 'refresh'
    - `401 UNAUTHORIZED`: Credenciais inválidas.
    """
    serializer_class = TokenObtainPairSerializer


class LogoutView(BaseView):
    """
    Endpoint para realizar o logout e invalidar o token de refresh.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Parâmetros:
    - `POST /apis/logout/`: JSON contendo:
        - `refresh` (str): Token de refresh fornecido pelo usuário.

    ### Retornos:
    - `205 RESET CONTENT`: Logout realizado com sucesso.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Token de refresh não fornecido ou inválido.
    """
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
    """
    Endpoint para obter os usuários no sistema.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Parâmetros:
    - `GET /apis/usuarios/`

    ### Retornos:
    - `200 OK`: Usuários serializados pelo `UserSerializer`.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Erros adicionais relacionados à requisição.
    """
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangeUserChangeView(BaseView):
    """
    Endpoint para alterar o setor ou a situação de staff de um usuário.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Descrição:
    - Usuários staff podem alterar o setor de outros usuários.
    - Apenas superusuários podem alterar o status de staff.

    ### Parâmetros:
    - `POST /apis/usuarios/alterar/`: JSON contendo:
        - `user_id` (int): ID do usuário alvo. (Obrigatório)
        - `new_sector_id` (int): ID do novo setor. (Opcional, requer permissão de staff)
        - `is_staff` (bool): Define se o usuário deve ser staff ou não. (Opcional, requer permissão de superusuário)

    ### Retornos:
    - `200 OK`: Alteração bem-sucedida.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Dados inválidos ou erro de permissão.

    ### Erros:
    - `ValidationError`: Se o usuário não tiver permissão ou se os dados fornecidos forem inválidos.
    """

    def post(self, request):
        user_id = request.data.get('user_id')
        if not user_id:
            raise ValidationError({"user_id": "O ID do usuário é obrigatório."})
        user = get_object_or_404(User, id=user_id)

        # Processa alterações solicitadas
        sector_message = self.handle_sector_change(request, user)
        staff_message = self.handle_staff_status_change(request, user)

        # Monta resposta
        response_message = {
            "sector_message": sector_message,
            "staff_message": staff_message,
        }
        return Response({key: msg for key, msg in response_message.items() if msg}, status=status.HTTP_200_OK)

    def handle_sector_change(self, request, user):
        """
        Processa a alteração de setor para o usuário, se solicitado.
        """
        new_sector_id = request.data.get('new_sector_id')
        if new_sector_id is None:
            return None

        self.permissions_check(request.user, weight=1)

        # Tenta buscar o novo setor
        new_sector = None
        if new_sector_id:
            try:
                new_sector = Sector.objects.get(id=int(new_sector_id))
            except (ValueError, Sector.DoesNotExist):
                raise ValidationError({"new_sector_id": "O ID do setor fornecido não é válido ou não existe."})

        # Atualiza o setor
        if user.sector != new_sector:
            user.sector = new_sector
            user.save(update_fields=["sector"])
            return (
                f"O setor do usuário #{user.id} foi atualizado para '{new_sector.sector_name}'."
                if new_sector else f"O setor do usuário #{user.id} foi removido com sucesso."
            )
        return (
            f"O setor do usuário #{user.id} já é '{new_sector.sector_name}'."
            if new_sector else f"O setor do usuário #{user.id} já está vazio."
        )

    def handle_staff_status_change(self, request, user):
        """
        Processa a alteração da situação de staff para o usuário, se solicitado.
        """
        is_staff = request.data.get('is_staff')
        if is_staff is None:
            return None

        self.permissions_check(request.user, weight=3, error_message="Acesso restrito à super usuários.")

        # Atualiza a situação de staff
        is_staff = bool(is_staff)
        if user.is_staff != is_staff:
            user.is_staff = is_staff
            user.save(update_fields=["is_staff"])
            return f"O status de staff do usuário #{user.id} foi atualizado para {'habilitado' if is_staff else 'desabilitado'}."
        return f"O status de staff do usuário #{user.id} já está {'habilitado' if is_staff else 'desabilitado'}."


# Views de Tickets
class CreateTicketView(BaseView):
    """
    Endpoint para a criação de um novo chamado.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Parâmetros:
    - `POST /apis/chamados/criar/`: JSON contendo:
        - `title` (str): Título do chamado.
        - `description` (str): Descrição do chamado.
        - `receivers` (str): IDs dos usuários que irão receber o chamado separados por vírgula.

    ### Retornos:
    - `201 CREATED`: Chamado criado e serializado pelo ´TicketSerializer´.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Informações do por que não foi possível criar o chamado.
    """

    def post(self, request):
        serializer = TicketSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class GetSentTicketsView(BaseView):
    """
    Endpoint para obter os chamados enviados do usuário que está fazendo a requisição.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Parâmetros:
    - `GET /apis/chamados/enviados/`

    ### Retornos:
    - `200 OK`: Chamados Enviados serializados pelo `TicketListSerializer`.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Erros adicionais relacionados à requisição.
    """
    def get(self, request):
        tickets = self.get_user_tickets(request.user, "sent")
        serializer = TicketListSerializer(tickets, many=True)
        return Response(serializer.data)


class GetReceivedTicketsView(BaseView):
    """
    Endpoint para obter os chamados recebidos do usuário que está fazendo a requisição.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Parâmetros:
    - `GET /apis/chamados/recebidos/`

    ### Retornos:
    - `200 OK`: Chamados Recebidos serializados pelo `TicketListSerializer`.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Erros adicionais relacionados à requisição.
    """
    def get(self, request):
        tickets = self.get_user_tickets(request.user, "received")
        serializer = TicketListSerializer(tickets, many=True)
        return Response(serializer.data)


class CreateTicketResponseView(BaseView):
    """
    Endpoint para a criação de uma resposta para um chamado.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Parâmetros:
    - `POST /apis/chamados/responder/`: JSON contendo:
        - `ticket_id` (int): ID do chamado que está sendo respondido (Obrigatório).
        - `content` (str): Conteúdo da resposta ao chamado (Obrigatório).

    ### Retornos:
    - `201 CREATED`: Resposta ao chamado criado e serializado pelo ´TicketResponseSerializer´.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Informações do por que não foi possível criar o chamado.
    """
    def post(self, request):
        try:
            ticket_id = request.data.get('ticket_id')
            ticket: Ticket = get_object_or_404(Ticket, id=ticket_id)
        except Exception as e:
            raise ValidationError({'ticket_id': str(e)})

        custom_rule = lambda user: user.is_active
        self.permissions_check(request.user, weight=3, allowed_users=self.get_allowed_users(ticket),
                               custom_rules=[custom_rule])

        # Validar conteúdo
        content = request.data.get('content')
        if not content:
            raise ValidationError({"content": "O conteúdo não é válido."})

        # Criar resposta
        ticket_response = TicketResponse.objects.create(
            ticket=ticket,
            responder=request.user,
            content=content
        )

        # Retornar resposta criada
        return Response(
            TicketResponseSerializer(ticket_response).data,
            status=status.HTTP_201_CREATED
        )


class GetTicketResponsesView(APIView):
    """
    Endpoint para obter as respostas de um chamado.

    ### Autenticação:
    - Requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Parâmetros:
    - `GET /apis/chamados/respostas/`: Query params:
        - `ticket_id` (int): ID do chamado (Obrigatório).

    ### Retornos:
    - `200 OK`: Respostas do chamado serializadas.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Requisição inválida.
    - `404 NOT FOUND`: Ticket não encontrado.
    """
    def get(self, request):
        ticket_id = request.query_params.get('ticket_id')
        if not ticket_id:
            raise ValidationError({'ticket_id': 'Este campo é obrigatório.'})

        try:
            ticket_id = int(ticket_id)
        except ValueError:
            raise ValidationError({'ticket_id': 'O ID do chamado deve ser um número inteiro.'})

        # Tente buscar o ticket e pré-carregar as respostas
        ticket = Ticket.objects.filter(id=ticket_id).prefetch_related(
            Prefetch(
                'responses',
                queryset=TicketResponse.objects.select_related('responder')
            )
        ).first()

        if not ticket:
            raise NotFound({'ticket_id': 'Chamado não encontrado.'})

        # Serializar as respostas
        responses = ticket.responses.all()
        serializer = TicketResponseSerializer(responses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangeTicketStatusView(BaseView):
    """
    Endpoint para alterar a situação de um chamado.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Descrição:
    - Apenas quem Enviou/Recebeu o chamado pode alterar a situação do chamado.

    ### Parâmetros:
    - `POST /apis/chamados/status/`: JSON contendo:
        - `ticket_id` (int): ID do chamado alvo. (Obrigatório)
        - `new_status` (str): Novo status. (Obrigatório)

    ### Retornos:
    - `200 OK`: Alteração bem-sucedida.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Dados inválidos ou erro de permissão.

    ### Erros:
    - `ValidationError`: Se o usuário não tiver permissão ou se os dados fornecidos forem inválidos.
    """
    def post(self, request):
        try:
            ticket_id = int(request.data.get('ticket_id'))
            ticket: Ticket = get_object_or_404(Ticket, id=ticket_id)
        except Exception as e:
            raise ValidationError({'ticket_id': str(e)})
        self.permissions_check(self.request.user, weight=3, allowed_users=self.get_allowed_users(ticket))

        user = request.user
        new_status = request.data.get('new_status')

        # Validar entrada
        if not new_status:
            raise ValidationError({"new_status": "Status não fornecido."})

        # Alterar situação e verificar permissão
        self.change_ticket_status(ticket, user, new_status)

        return Response(
            {"message": f"Status do chamado do '{user.username}' alterado para '{new_status}' com sucesso!"},
            status=status.HTTP_200_OK
        )


class DeleteTicketView(BaseView):
    """
    Endpoint para deletar um chamado.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Descrição:
    - Apenas super usuários podem deletar um chamado.

    ### Parâmetros:
    - `POST /apis/chamados/remover/`: JSON contendo:
        - `ticket_id` (int): ID do chamado alvo. (Obrigatório)

    ### Retornos:
    - `200 OK`: Remoção bem-sucedida.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Dados inválidos ou erro de permissão.

    ### Erros:
    - `ValidationError`: Se o usuário não tiver permissão ou se os dados fornecidos forem inválidos.
    """
    def post(self, request):
        try:
            ticket_id = int(request.data.get('ticket_id'))
            ticket: Ticket = get_object_or_404(Ticket, id=ticket_id)
        except Exception as e:
            raise ValidationError({"ticket_id": str(e)})

        # Validar permissões
        self.permissions_check(request.user, allowed_users=self.get_allowed_users(ticket, only_sender=True),
                               weight=3,
                               error_message="Acesso restrito à super usuários ou ao remetente do ticket.")

        # Deletar ticket
        ticket.delete()
        return Response(
            {"message": f"Chamado #{ticket_id} removido com sucesso!"},
            status=status.HTTP_200_OK
        )

# Views de Setores
class CreateSectorView(BaseView):
    """
    Endpoint para a criação de um setor.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Descrição:
    - Apenas usuários staff podem criar um setor.

    ### Parâmetros:
    - `POST /apis/setores/criar/`: JSON contendo:
        - `name` (str): Nome do setor (Obrigatório).
        - `description` (str): Descrição do setor (Opcional).
        - `leader_id` (int): ID do usuário líder. (Opcional).

    ### Retornos:
    - `201 CREATED`: Setor criado.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Informações do por que não foi possível criar o setor.
    """
    def post(self, request):
        # Verificar permissão
        self.permissions_check(request.user, weight=1)

        # Obter dados do request (sem remover o líder, pois estamos criando)
        data_from_request = self.get_sector_infos_from_request(request, is_update=False)

        if not data_from_request['sector_name']:
            raise ValidationError({'name': 'Nome do setor não fornecido ou inválido.'})

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
    """
    Endpoint para alterar um setor.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Descrição:
    - Apenas usuários staff podem alterar um setor.

    ### Parâmetros:
    - `POST /apis/setores/alterar/`: JSON contendo:
        - `sector_id` (int): ID do setor alvo (Obrigatório).
        - `name` (str): Nome do setor (Opcional).
        - `description` (str): Descrição do setor (Opcional).
        - `leader_id` (int): ID do usuário líder. (Opcional) 0 = Remove o atual líder.

    ### Retornos:
    - `201 CREATED`: Setor criado.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Informações do por que não foi possível criar o setor.
    """
    def post(self, request):
        # Verificar permissão
        self.permissions_check(request.user, weight=1)

        try:
            # Buscar setor
            sector_id = int(request.data.get('sector_id'))
            sector: Sector = get_object_or_404(Sector, id=sector_id)
        except Exception as e:
            raise ValidationError({"sector_id": str(e)})

        # Obter novas informações do request
        new_data = self.get_sector_infos_from_request(request, is_update=True)

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
        Atualiza o campo 'leader' para None, se ele for explicitamente definido como None, sem alterar outros campos.
        """
        changed = []

        # Verificar o campo 'leader' separadamente
        if 'sector_leader' in new_data:
            if new_data['sector_leader'] == 0 and sector.leader is not None:
                sector.leader = None
                changed.append('sector_leader')

        new_data.pop('sector_leader', None)

        # Verificar outros campos
        for field, new_value in new_data.items():
            old_value = getattr(sector, field)
            if old_value != new_value:
                setattr(sector, field, new_value)
                changed.append(field)

        if changed:
            sector.save(update_fields=changed)

        return changed


class DeleteSectorView(BaseView):
    """
    Endpoint para deletar um setor.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Descrição:
    - Apenas super usuários podem deletar um setor.

    ### Parâmetros:
    - `POST /apis/setores/remover/`: JSON contendo:
        - `sector_id` (int): ID do chamado alvo. (Obrigatório)

    ### Retornos:
    - `200 OK`: Remoção bem-sucedida.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    - `400 BAD REQUEST`: Dados inválidos ou erro de permissão.

    ### Erros:
    - `ValidationError`: Se o usuário não tiver permissão ou se os dados fornecidos forem inválidos.
    """
    def post(self, request):
        self.permissions_check(request.user, weight=3, error_message="Acesso restrito à super usuários.")
        try:
            sector_id = int(request.data.get('sector_id'))
            sector: Sector = get_object_or_404(Sector, id=sector_id)
        except Exception as e:
            raise ValidationError({"sector_id": str(e)})
        sector.delete()

        return Response({"message": f"Setor #{sector_id} deletado com sucesso!"},
                        status=status.HTTP_200_OK)


class GetSectorsView(BaseView):
    """
    Endpoint para obter os setores do sistema.

    ### Autenticação:
    - Este endpoint requer autenticação via **Bearer Token** no cabeçalho HTTP:
        ```
        Authorization: Bearer <access_token>
        ```

    ### Parâmetros:
    - `GET /apis/setores/`

    ### Retornos:
    - `200 OK`: Setores serializados pelo `SectorSerializer`.
    - `401 UNAUTHORIZED`: Token de acesso não fornecido ou inválido.
    """
    def get(self, request):
        sectors = Sector.objects.all()
        serializer = SectorSerializer(sectors, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)
