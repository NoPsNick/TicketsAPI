from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class Ticket(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_READ = 'read'
    STATUS_CLOSED = 'closed'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pendente'),
        (STATUS_READ, 'Lido'),
        (STATUS_CLOSED, 'Finalizado')
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    sender = models.ForeignKey(User, related_name='sent_tickets', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_tickets', on_delete=models.CASCADE)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default=STATUS_PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def get_status_display_dict(cls):
        """
        Retorna um dicionário para mapear os status de exibição para valores internos.
        """
        return {display: value for value, display in cls.STATUS_CHOICES}


class TicketResponse(models.Model):
    ticket = models.ForeignKey(Ticket, related_name='responses', on_delete=models.CASCADE)
    responder = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Resposta ao ticket #{self.ticket.id} por {self.responder.username}"
