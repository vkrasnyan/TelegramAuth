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
    def get(self, request, *args, **kwargs):
        token = secrets.token_urlsafe(16)
        bot_username = 'myloginetbot'
        telegram_link = f"https://t.me/{bot_username}?start={token}"

        # Сохраняем token в сессии
        request.session['auth_token'] = token

        # Логируем
        logger.debug(f"Generated telegram link: {telegram_link}")

        return render(request, 'login.html', {'telegram_link': telegram_link})


class TelegramCallbackView(FormView):
    form_class = TelegramCallbackForm

    def get(self, request, *args, **kwargs):
        # Получаем параметры из GET-запроса
        token = request.GET.get('token')
        telegram_id = request.GET.get('telegram_id')
        telegram_username = request.GET.get('username')

        # Если не все параметры присутствуют, показываем ошибку
        if not token or not telegram_id or not telegram_username:
            logger.error(f'Missing parameters: token={token}, telegram_id={telegram_id}, username={telegram_username}')
            return redirect('login')

        # Заполняем форму
        form = self.get_form()
        form.cleaned_data = {
            'token': token,
            'telegram_id': telegram_id,
            'username': telegram_username
        }

        return self.form_valid(form)

    def form_valid(self, form):
        # Логика обработки данных из формы
        token = form.cleaned_data['token']
        telegram_id = form.cleaned_data['telegram_id']
        telegram_username = form.cleaned_data['username']

        try:
            # Ищем профиль Telegram
            profile = TelegramProfile.objects.get(telegram_id=telegram_id)
            user = profile.user
            profile.telegram_username = telegram_username
            profile.auth_token = token
            profile.save()
        except TelegramProfile.DoesNotExist:
            # Если профиль не найден, создаем новый пользовательский профиль
            user, created = User.objects.get_or_create(username=telegram_username)
            if created:
                logger.info(f'Created new user: {telegram_username}')
            profile = TelegramProfile.objects.create(
                user=user,
                telegram_id=telegram_id,
                telegram_username=telegram_username,
                auth_token=token
            )

        # Логиним пользователя
        login(self.request, user, backend='django.contrib.auth.backends.ModelBackend')
        logger.info(f'Logged in user: {user.username}')

        # Принудительно обновляем сессию
        self.request.session.modified = True
        self.request.session.save()

        # Редиректим на страницу welcome
        return redirect('welcome')



class WelcomeView(View):
    def get(self, request, *args, **kwargs):
        context = {'username': request.user.username}
        return render(request, 'welcome.html', context)

