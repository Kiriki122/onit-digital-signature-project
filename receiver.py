import os
import json
import base64
import imaplib
import email
from dotenv import load_dotenv # НОВОЕ
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet

# Загружаем переменные из .env
load_dotenv()

# --- Настройки почты берем из окружения ---
IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")
RECEIVER_PASSWORD = os.getenv("RECEIVER_PASSWORD")

if not all([RECEIVER_EMAIL, RECEIVER_PASSWORD]):
    raise ValueError("Необходимо заполнить RECEIVER_EMAIL и RECEIVER_PASSWORD в .env файле!")

def load_key(filename, is_private=False):
    with open(filename, "rb") as key_file:
        if is_private:
            return serialization.load_pem_private_key(key_file.read(), password=None)
        return serialization.load_pem_public_key(key_file.read())

def fetch_and_decrypt():
    # 1. Подключение к почте и скачивание вложений
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(RECEIVER_EMAIL, RECEIVER_PASSWORD)
    mail.select('inbox')

    # Ищем последнее письмо с нужной темой
    status, messages = mail.search('UTF-8', 'SUBJECT', '"Зашифрованный файл с ЭЦП"'.encode('utf-8'))
    if not messages[0]:
        print("Писем не найдено.")
        return

    latest_email_id = messages[0].split()[-1]
    status, msg_data = mail.fetch(latest_email_id, '(RFC822)')
    
    msg = email.message_from_bytes(msg_data[0][1])
    
    encrypted_payload = None
    encrypted_sym_key = None

    for part in msg.walk():
        if part.get_filename() == 'payload.enc':
            encrypted_payload = part.get_payload(decode=True)
        elif part.get_filename() == 'key.enc':
            encrypted_sym_key = part.get_payload(decode=True)

    if not encrypted_payload or not encrypted_sym_key:
        print("Вложения не найдены!")
        return

    print("Письмо получено. Начинаем расшифровку...")

    receiver_private_key = load_key("receiver_private.pem", is_private=True)
    sender_public_key = load_key("sender_public.pem", is_private=False)

    # 2. Расшифровка симметричного ключа (закрытым ключом получателя)
    sym_key = receiver_private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # 3. Расшифровка данных (симметричным ключом)
    fernet = Fernet(sym_key)
    decrypted_payload_bytes = fernet.decrypt(encrypted_payload)
    
    payload_data = json.loads(decrypted_payload_bytes.decode('utf-8'))
    
    file_content = base64.b64decode(payload_data['content'])
    signature = base64.b64decode(payload_data['signature'])
    original_filename = payload_data['filename']

    # 4. Проверка ЭЦП (открытым ключом отправителя)
    try:
        sender_public_key.verify(
            signature,
            file_content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("✅ ЭЦП ВЕРНА! Авторство подтверждено. Файл не был изменен.")
        
        # Сохраняем расшифрованный файл
        save_path = f"decrypted_{original_filename}"
        with open(save_path, "wb") as f:
            f.write(file_content)
        print(f"Файл сохранен как: {save_path}")

    except InvalidSignature:
        print("❌ ОШИБКА: ЭЦП недействительна! Файл был поврежден, изменен или отправлен злоумышленником.")

if __name__ == "__main__":
    fetch_and_decrypt()