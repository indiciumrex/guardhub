import requests

BOT = "{{secret:telegram_bot_token:inf5}}"


def notify(chat, text):
    requests.post(f"https://api.telegram.org/bot{BOT}/sendMessage", json={"chat_id": chat, "text": text})
