import logging
import hashlib
import hmac
import secrets
import time
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.views.generic import View

from .models import TelegramProfile


logger = logging.getLogger(__name__)


class LoginViaTelegramView(View):
    def get(self, request, *args, **kwargs):
        # Генерация токена для сессии и ссылки на Telegram
        telegram_auth = TelegramAuth(request)
        token = telegram_auth.generate_token()
        bot_username = 'myloginetbot'
        telegram_link = f"https://t.me/{bot_username}?start={token}"

        # Логируем для отладки
        logger.debug(f"Generated telegram link: {telegram_link}")

        return render(request, 'login.html', {'telegram_link': telegram_link})


class TelegramAuth:
    name = "telegram"
    ID_KEY = "id"

    def __init__(self, request):
        self.request = request
        self.response = request.GET

    def generate_token(self):
        # Генерация токена для сессии
        token = secrets.token_urlsafe(16)
        self.request.session['auth_token'] = token  # Сохраняем токен в сессии
        return token

    def verify_data(self):
        bot_token = '7982653482:AAEtitxQYmgSn6dNLvQGLpMdAst-80cK5z4'
        if bot_token is None:
            raise ValueError("SOCIAL_AUTH_TELEGRAM_BOT_TOKEN is not set")

        received_hash_string = self.response.get("hash")
        auth_date = self.response.get("auth_date")

        if received_hash_string is None or auth_date is None:
            raise ValueError("Missing parameters: hash or auth_date")

        # Формируем строку для проверки
        data_check_string = [f"{k}={v}" for k, v in self.response.items() if k != "hash"]
        data_check_string = "\n".join(sorted(data_check_string))
        secret_key = hashlib.sha256(bot_token.encode()).digest()
        built_hash = hmac.new(
            secret_key, msg=data_check_string.encode(), digestmod=hashlib.sha256
        ).hexdigest()
        current_timestamp = int(time.time())
        auth_timestamp = int(auth_date)

        # Проверка на дату
        if current_timestamp - auth_timestamp > 86400:
            raise ValueError("Auth date is outdated")

        if built_hash != received_hash_string:
            raise ValueError("Invalid hash supplied")

    def get_user_details(self):
        first_name = self.response.get("first_name", "")
        last_name = self.response.get("last_name", "")
        fullname = f"{first_name} {last_name}".strip()
        return {
            "username": self.response.get("username") or str(self.response[self.ID_KEY]),
            "first_name": first_name,
            "last_name": last_name,
            "fullname": fullname,
        }

    def authenticate_user(self):
        self.verify_data()
        user_details = self.get_user_details()

        # Поиск или создание пользователя
        telegram_id = self.response.get("id")
        telegram_username = self.response.get("username")
        try:
            profile = TelegramProfile.objects.get(telegram_id=telegram_id)
            user = profile.user
            profile.telegram_username = telegram_username
            profile.save()
        except TelegramProfile.DoesNotExist:
            user, created = User.objects.get_or_create(username=user_details['username'])
            if created:
                logger.info(f'Created new user: {user_details["username"]}')
            profile = TelegramProfile.objects.create(
                user=user,
                telegram_id=telegram_id,
                telegram_username=telegram_username
            )

        # Логиним пользователя
        login(self.request, user)
        self.request.session.modified = True
        self.request.session.save()

        return user


def telegram_callback(request):
    try:
        telegram_auth = TelegramAuth(request)
        user = telegram_auth.authenticate_user()  # Здесь происходит валидация
        logger.info(f'User {user.username} logged in successfully')
        return redirect('welcome')  # перенаправление на страницу welcome
    except ValueError as e:
        logger.error(f"Error during Telegram authentication: {e}")
        return HttpResponseBadRequest("Invalid Telegram authentication data.")


class WelcomeView(View):
    def get(self, request, *args, **kwargs):
        context = {'username': request.user.username}
        return render(request, 'welcome.html', context)

