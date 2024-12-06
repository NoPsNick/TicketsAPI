from django.urls import path
from .views import (RegisterView, LoginView, LogoutView, GetUsersView, CreateTicketView, CreateTicketResponseView,
                    GetTicketResponsesView, GetSentTicketsView, GetReceivedTicketsView)
from rest_framework_simplejwt.views import TokenRefreshView

app_name = 'apis'


urlpatterns = [
    # Auth
    path('registrar/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('usuarios/', GetUsersView.as_view(), name='user-list'),

    # Chamados GET
    path('chamados/enviados/', GetSentTicketsView.as_view(), name='sent-tickets'),
    path('chamados/recebidos/', GetReceivedTicketsView.as_view(), name='received-tickets'),
    path('chamados/<int:ticket_id>/respostas/', GetTicketResponsesView.as_view(), name='ticket-responses'),

    # Chamados POST
    path('chamados/criar/', CreateTicketView.as_view(), name='create-ticket'),
    path('chamados/<int:ticket_id>/responder/', CreateTicketResponseView.as_view(),
         name='create-ticket-response'),
]
