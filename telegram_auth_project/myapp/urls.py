from django.urls import path
from .views import LoginViaTelegramView, telegram_callback, WelcomeView

urlpatterns = [
    path('login/', LoginViaTelegramView.as_view(), name='login'),
    path('telegram_callback/', telegram_callback, name='telegram_callback'),
    path('welcome/', WelcomeView.as_view(), name='welcome'),
]
