import requests
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TOKEN = 'YourBotToken'
DJANGO_SERVER_URL = 'http://127.0.0.1:8000/telegram_callback'


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    token = context.args[0] if context.args else None
    if token:
        telegram_id = update.effective_user.id
        telegram_username = update.effective_user.username or f"user_{telegram_id}"

        response = requests.get(
            DJANGO_SERVER_URL,
            params={
                'token': token,
                'telegram_id': telegram_id,
                'username': telegram_username
            }
        )

        if response.status_code == 200:
            await update.message.reply_text("✅ Авторизация успешна! Можете вернуться на сайт.")
        else:
            await update.message.reply_text("❌ Ошибка авторизации. Попробуйте снова.")
    else:
        await update.message.reply_text("⚠️ Некорректная команда. Проверьте ссылку.")


app = ApplicationBuilder().token(TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.run_polling()
