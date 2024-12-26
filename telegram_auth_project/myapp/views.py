import logging

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render, redirect


from .models import TelegramProfile
import secrets

logger = logging.getLogger(__name__) # логирование добавлено для отладки
def login_via_telegram(request: HttpRequest) -> HttpResponse:

    """
    Отображает страницу со ссылкой для аутентификации через Телеграм и генерирует токен для сессии и ссылки на Телеграм
    """

    token = secrets.token_urlsafe(16)
    bot_username = 'myloginetbot'
    telegram_link = f"https://t.me/{bot_username}?start={token}"

    request.session['auth_token'] = token

    return render(request, 'login.html', {'telegram_link': telegram_link})


def telegram_callback(request: HttpRequest) -> HttpResponse:
    """Обрабатывает данные, полученные от Телеграм и логинит пользователя"""

    token = request.GET.get('token')
    telegram_id = request.GET.get('telegram_id')
    telegram_username = request.GET.get('username')

    if not token or not telegram_id or not telegram_username:
        logger.error(f'Missing parameters: token={token}, telegram_id={telegram_id}, username={telegram_username}')
        return redirect('login')

    try:
        profile = TelegramProfile.objects.get(telegram_id=telegram_id)
        user = profile.user
        profile.telegram_username = telegram_username
        profile.auth_token = token
        profile.save()
    except TelegramProfile.DoesNotExist:
        user, created = User.objects.get_or_create(username=telegram_username)
        if created:
            logger.info(f'Created new user: {telegram_username}')
            profile = TelegramProfile.objects.create(
                user=user,
                telegram_id=telegram_id,
                telegram_username=telegram_username,
                auth_token=token
            )
        else:
            logger.info(f'Found existing user: {telegram_username}')
            profile = TelegramProfile.objects.create(
                user=user,
                telegram_id=telegram_id,
                telegram_username=telegram_username,
                auth_token=token
            )

    logger.info(f'Logging in user: {user.username}')
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    if request.user.is_authenticated:
        logger.info(f"User {request.user.username} logged in successfully.")
    else:
        logger.error("User not logged in.")

    request.session.modified = True
    request.session.save()
    logger.info(f'Session updated for user: {user.username}')

    return redirect('/welcome/')


@login_required
def welcome_view(request: HttpRequest) -> HttpResponse:
    """Отображает страницу приветствия после успешной авторизации."""

    context = {'username': request.user.username}
    return render(request, 'welcome.html', context)
