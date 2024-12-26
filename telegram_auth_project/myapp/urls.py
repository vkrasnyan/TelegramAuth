from django.urls import path
from .views import LoginViaTelegramView, TelegramCallbackView, WelcomeView

urlpatterns = [
    path('login/', LoginViaTelegramView.as_view(), name='login'),
    path('telegram_callback/', TelegramCallbackView.as_view(), name='telegram_callback'),
    path('welcome/', WelcomeView.as_view(), name='welcome'),
]
