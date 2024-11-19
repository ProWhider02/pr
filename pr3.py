import socket
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

HOST = "127.0.0.1"  # Локальний хост
PORT = 65432        # Порт


def save_key_to_file(key, filename):
    """Зберігає ключ у файл."""
    with open(filename, "wb") as key_file:
        key_file.write(key)


def load_key_from_file(filename):
    """Завантажує ключ із файлу."""
    with open(filename, "rb") as key_file:
        return key_file.read()


def generate_private_key(curve):
    """Генерація приватного ключа."""
    return ec.generate_private_key(curve)


def derive_symmetric_key(shared_secret):
    """Отримання симетричного ключа із спільного секрету."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)


def encrypt_message(key, message):
    """Шифрування повідомлення."""
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


def decrypt_message(key, nonce, ciphertext, tag):
    """Дешифрування повідомлення."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def server_mode():
    """Режим сервера."""
    server_private_key = generate_private_key(ec.SECP256R1())
    server_private_key_bytes = server_private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    server_public_key_bytes = server_private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    # Зберігаємо пари ключів у файли
    save_key_to_file(server_private_key_bytes, "server_private_key.pem")
    save_key_to_file(server_public_key_bytes, "server_public_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print("[Server] Очікування клієнта...")
        conn, addr = server_socket.accept()
        with conn:
            print(f"[Server] З'єднано з {addr}.")

            # Отримання публічного ключа клієнта
            client_public_key_bytes = conn.recv(1024)
            client_public_key = load_pem_public_key(client_public_key_bytes)

            # Відправка публічного ключа сервера
            conn.sendall(server_public_key_bytes)

            # Генерація спільного секрету
            shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
            symmetric_key = derive_symmetric_key(shared_key)

            # Збереження симетричного ключа у файл
            save_key_to_file(symmetric_key, "server_symmetric_key.key")
            print("[Server] Спільний ключ успішно узгоджено та збережено у файл.")

            while True:
                # Отримання зашифрованого повідомлення
                encrypted_message = conn.recv(1024)
                if not encrypted_message:
                    break
                nonce, ciphertext, tag = (
                    encrypted_message[:12],
                    encrypted_message[12:-16],
                    encrypted_message[-16:],
                )
                message = decrypt_message(symmetric_key, nonce, ciphertext, tag)
                print(f"[Server] Отримано повідомлення: {message.decode()}")

                # Відправка підтвердження клієнту
                response = "Повідомлення отримано.".encode("utf-8")
                nonce, ciphertext, tag = encrypt_message(symmetric_key, response)
                conn.sendall(nonce + ciphertext + tag)


def client_mode():
    """Режим клієнта."""
    client_private_key = generate_private_key(ec.SECP256R1())
    client_private_key_bytes = client_private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    client_public_key_bytes = client_private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    # Зберігаємо пари ключів у файли
    save_key_to_file(client_private_key_bytes, "client_private_key.pem")
    save_key_to_file(client_public_key_bytes, "client_public_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print("[Client] З'єднання встановлено.")

        # Надсилаємо публічний ключ клієнта
        client_socket.sendall(client_public_key_bytes)

        # Отримуємо публічний ключ сервера
        server_public_key_bytes = client_socket.recv(1024)
        server_public_key = load_pem_public_key(server_public_key_bytes)

        # Генеруємо спільний секрет
        shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
        symmetric_key = derive_symmetric_key(shared_key)

        # Збереження симетричного ключа у файл
        save_key_to_file(symmetric_key, "client_symmetric_key.key")
        print("[Client] Спільний ключ успішно узгоджено та збережено у файл.")

        while True:
            print("Оберіть дію: 1 - Надіслати текст, 2 - Надіслати файл, 3 - Вийти")
            choice = input("Ваш вибір: ")
            
            if choice == "1":
                message = input("Введіть текст повідомлення: ").encode("utf-8")
            elif choice == "2":
                file_path = input("Введіть шлях до файлу: ")
                try:
                    with open(file_path, "rb") as file:
                        message = file.read()
                except FileNotFoundError:
                    print("[Client] Файл не знайдено. Спробуйте ще раз.")
                    continue
            elif choice == "3":
                print("[Client] Вихід із програми.")
                break
            else:
                print("[Client] Невірний вибір. Спробуйте ще раз.")
                continue

            # Відправляємо зашифроване повідомлення серверу
            nonce, ciphertext, tag = encrypt_message(symmetric_key, message)
            client_socket.sendall(nonce + ciphertext + tag)

            # Отримуємо підтвердження
            encrypted_response = client_socket.recv(1024)
            nonce, ciphertext, tag = encrypted_response[:12], encrypted_response[12:-16], encrypted_response[-16:]
            response = decrypt_message(symmetric_key, nonce, ciphertext, tag)
            print(f"[Client] Відповідь від сервера: {response.decode()}")


if __name__ == "__main__":
    print("Оберіть режим: 1 - Сервер, 2 - Клієнт")
    choice = input("Ваш вибір: ")

    if choice == "1":
        server_mode()
    elif choice == "2":
        client_mode()
    else:
        print("Невірний вибір. Завершення програми.")
