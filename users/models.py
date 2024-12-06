from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

User_model = settings.AUTH_USER_MODEL


class Sector(models.Model):
    sector_name = models.CharField(verbose_name='Nome do Setor', max_length=120)
    sector_description = models.TextField(verbose_name='Descrição do Setor', default="", null=True, blank=True)
    sector_leader = models.ForeignKey(User_model, related_name='leader', on_delete=models.SET_NULL, null=True,
                                      blank=True)


class User(AbstractUser):
    sector = models.ForeignKey(Sector, on_delete=models.SET_NULL, default=None, null=True, blank=True)

    class Meta:
        ordering = ['username']
        verbose_name = "usuário"
        verbose_name_plural = "usuários"

    def __str__(self):
        return f'[{self.pk}] {self.username}'
