from django.urls import path
from .views import (RegisterView, LoginView, LogoutView, GetUsersView, CreateTicketView, CreateTicketResponseView,
                    GetTicketResponsesView, GetSentTicketsView, GetReceivedTicketsView, ChangeTicketStatusView,
                    DeleteTicketView, GetSectorsView, CreateSectorView, DeleteSectorView, ChangeUserSectorView,
                    ChangeSectorView)
from rest_framework_simplejwt.views import TokenRefreshView

app_name = 'apis'


urlpatterns = [
    # Auth
    path('registrar/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Usuários GET
    path('usuarios/', GetUsersView.as_view(), name='user-list'),

    # Usuários POST
    path('usuarios/<int:user_id>/alterar/', ChangeUserSectorView.as_view(), name='user-change'),

    # Chamados GET
    path('chamados/enviados/', GetSentTicketsView.as_view(), name='sent-tickets'),
    path('chamados/recebidos/', GetReceivedTicketsView.as_view(), name='received-tickets'),
    path('chamados/<int:ticket_id>/respostas/', GetTicketResponsesView.as_view(), name='ticket-responses'),

    # Chamados POST
    path('chamados/criar/', CreateTicketView.as_view(), name='ticket-create'),
    path('chamados/<int:ticket_id>/responder/', CreateTicketResponseView.as_view(),
         name='create-ticket-response'),
    path('chamados/<int:ticket_id>/status/', ChangeTicketStatusView.as_view(), name='change-ticket-status'),
    path('chamados/<int:ticket_id>/remover/', DeleteTicketView.as_view(), name='delete-ticket'),

    # Setores GET
    path('setores/', GetSectorsView.as_view(), name='sector-list'),

    # Setores POST
    path('setores/criar/', CreateSectorView.as_view(), name='sector-create'),
    path('setores/<int:sector_id>/remover/', DeleteSectorView.as_view(), name='sector-delete'),
    path('setores/<int:sector_id>/alterar/', ChangeSectorView.as_view(), name='sector-change'),
]
