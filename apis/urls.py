"""
URL Patterns for the APIs module.

This module defines endpoints for user management, tickets, and sectors.
"""

from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView, GetUsersView, CreateTicketView, CreateTicketResponseView,
    GetTicketResponsesView, GetSentTicketsView, GetReceivedTicketsView, ChangeTicketStatusView,
    DeleteTicketView, GetSectorsView, CreateSectorView, DeleteSectorView, ChangeUserChangeView,
    ChangeSectorView
)
from rest_framework_simplejwt.views import TokenRefreshView

app_name = 'apis'

urlpatterns = [
    # Auth
    path('registrar/', RegisterView.as_view(), name='register'),  # Endpoint for user registration.
    path('login/', LoginView.as_view(), name='login'),  # Endpoint for user login.
    path('logout/', LogoutView.as_view(), name='logout'),  # Endpoint for user logout.
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh JWT token.

    # Users (GET)
    path('usuarios/', GetUsersView.as_view(), name='user-list'),  # Fetch a list of all users.

    # Users (POST)
    path('usuarios/alterar/', ChangeUserChangeView.as_view(), name='user-change'),  # Modify user sector or is_staff.

    # Tickets (GET)
    path('chamados/enviados/', GetSentTicketsView.as_view(), name='sent-tickets'),  # Fetch tickets sent by the user.
    path('chamados/recebidos/', GetReceivedTicketsView.as_view(), name='received-tickets'),  # Fetch tickets received by the user.
    path('chamados/respostas/', GetTicketResponsesView.as_view(), name='ticket-responses'),  # Fetch responses for a ticket.

    # Tickets (POST)
    path('chamados/criar/', CreateTicketView.as_view(), name='ticket-create'),  # Create a new ticket.
    path('chamados/responder/', CreateTicketResponseView.as_view(), name='create-ticket-response'),  # Add a response to a ticket.
    path('chamados/status/', ChangeTicketStatusView.as_view(), name='change-ticket-status'),  # Change ticket status.
    path('chamados/remover/', DeleteTicketView.as_view(), name='delete-ticket'),  # Delete a ticket (admin only).

    # Sectors (GET)
    path('setores/', GetSectorsView.as_view(), name='sector-list'),  # Fetch a list of all sectors.

    # Sectors (POST)
    path('setores/criar/', CreateSectorView.as_view(), name='sector-create'),  # Create a new sector (staff only).
    path('setores/remover/', DeleteSectorView.as_view(), name='sector-delete'),  # Delete a sector (admin only).
    path('setores/alterar/', ChangeSectorView.as_view(), name='sector-change'),  # Modify sector details (staff only).
]
