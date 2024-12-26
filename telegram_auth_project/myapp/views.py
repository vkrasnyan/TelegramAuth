import logging
import secrets
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from django.views.generic import View, FormView

from .forms import TelegramCallbackForm
from .models import TelegramProfile

logger = logging.getLogger(__name__)


class LoginViaTelegramView(View):
    """
    Отображает страницу со ссылкой для аутентификации через Телеграм и генерирует токен для сессии и ссылки на Телеграм
    """
    def get(self, request, *args, **kwargs):
        token = secrets.token_urlsafe(16)
        bot_username = 'myloginetbot'
        telegram_link = f"https://t.me/{bot_username}?start={token}"

        request.session['auth_token'] = token

        logger.debug(f"Generated telegram link: {telegram_link}")

        return render(request, 'login.html', {'telegram_link': telegram_link})


class TelegramCallbackView(FormView):
    """Обрабатывает данные, полученные от Телеграм и логинит пользователя"""

    form_class = TelegramCallbackForm

    def get(self, request, *args, **kwargs):
        """Получаем параметры из GET-запроса"""

        token = request.GET.get('token')
        telegram_id = request.GET.get('telegram_id')
        telegram_username = request.GET.get('username')

        if not token or not telegram_id or not telegram_username:
            logger.error(f'Missing parameters: token={token}, telegram_id={telegram_id}, username={telegram_username}')
            return redirect('login')

        form = self.get_form()
        form.cleaned_data = {
            'token': token,
            'telegram_id': telegram_id,
            'username': telegram_username
        }

        return self.form_valid(form)

    def form_valid(self, form):
        """Логика обработки данных из формы"""

        token = form.cleaned_data['token']
        telegram_id = form.cleaned_data['telegram_id']
        telegram_username = form.cleaned_data['username']

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


        login(self.request, user, backend='django.contrib.auth.backends.ModelBackend')
        logger.info(f'Logged in user: {user.username}')

        self.request.session.modified = True
        self.request.session.save()
        return redirect('welcome')



class WelcomeView(View):
    """Отображает страницу приветствия после успешной авторизации."""

    def get(self, request, *args, **kwargs):
        context = {'username': request.user.username}
        return render(request, 'welcome.html', context)

