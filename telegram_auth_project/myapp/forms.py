from django import forms

class TelegramCallbackForm(forms.Form):
    token = forms.CharField()
    telegram_id = forms.CharField()
    username = forms.CharField()