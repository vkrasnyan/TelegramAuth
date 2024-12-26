from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_via_telegram, name='login'),
    path('telegram_callback/', views.telegram_callback, name='telegram_callback'),
    path('welcome/', views.welcome_view, name='welcome'),
]
