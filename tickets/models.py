from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class Ticket(models.Model):
    pending, read, closed = 'pending', 'read', 'closed'
    status_choices = [
        (pending, 'Pendente'),
        (read, 'Lido'),
        (closed, 'Finalizado')
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    sender = models.ForeignKey(User, related_name='sent_tickets', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_tickets', on_delete=models.CASCADE)
    status = models.CharField(max_length=50, choices=status_choices, default=pending)
    created_at = models.DateTimeField(auto_now_add=True)


class TicketResponse(models.Model):
    ticket = models.ForeignKey(Ticket, related_name='responses', on_delete=models.CASCADE)
    responder = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Resposta ao ticket #{self.ticket.id} por {self.responder.username}"
