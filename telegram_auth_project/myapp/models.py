from django.contrib.auth.models import User
from django.db import models


class TelegramProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    telegram_id = models.BigIntegerField(unique=True, null=True, blank=True)
    telegram_username = models.CharField(max_length=150, null=True, blank=True)
    auth_token = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.telegram_username or f"User {self.user.username}"
