import os
import json
import base64
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

# Загружаем переменные из .env
load_dotenv()

# --- Настройки почты берем из окружения ---
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")

if not all([SENDER_EMAIL, SENDER_PASSWORD, RECEIVER_EMAIL]):
    raise ValueError("Необходимо заполнить SENDER_EMAIL, SENDER_PASSWORD и RECEIVER_EMAIL в .env файле!")

def load_key(filename, is_private=False):
    with open(filename, "rb") as key_file:
        if is_private:
            return serialization.load_pem_private_key(key_file.read(), password=None)
        return serialization.load_pem_public_key(key_file.read())

def process_and_send(file_path):
    # 1. Читаем файл
    with open(file_path, "rb") as f:
        file_data = f.read()

    sender_private_key = load_key("sender_private.pem", is_private=True)
    receiver_public_key = load_key("receiver_public.pem", is_private=False)

    # 2. Создаем ЭЦП (Подписываем данные)
    signature = sender_private_key.sign(
        file_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # Упаковываем файл и подпись в JSON
    payload = json.dumps({
        "filename": file_path,
        "content": base64.b64encode(file_data).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')
    }).encode('utf-8')

    # 3. Шифруем (Гибридное шифрование)
    # Генерируем симметричный ключ
    sym_key = Fernet.generate_key()
    fernet = Fernet(sym_key)
    
    # Шифруем данные симметричным ключом
    encrypted_payload = fernet.encrypt(payload)
    
    # Шифруем симметричный ключ открытым ключом получателя (RSA)
    encrypted_sym_key = receiver_public_key.encrypt(
        sym_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # 4. Отправка по Email
    msg = EmailMessage()
    msg['Subject'] = 'Зашифрованный файл с ЭЦП'
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg.set_content('Во вложении зашифрованный файл и зашифрованный ключ доступа.')

    msg.add_attachment(encrypted_payload, maintype='application', subtype='octet-stream', filename='payload.enc')
    msg.add_attachment(encrypted_sym_key, maintype='application', subtype='octet-stream', filename='key.enc')

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
    print("Файл успешно подписан, зашифрован и отправлен!")

# Создадим тестовый файл и отправим
if __name__ == "__main__":
    with open("secret_doc.txt", "w", encoding="utf-8") as f:
        f.write("Это очень секретный контракт: сумма 1 000 000 рублей.")

    process_and_send("secret_doc.txt")