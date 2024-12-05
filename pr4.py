import socket
import ssl
import threading
import os
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, random_serial_number
from cryptography.x509.oid import NameOID
from cryptography.x509 import DNSName, IPAddress, SubjectAlternativeName
from cryptography.hazmat.primitives.hashes import SHA256
from datetime import datetime, timedelta
import ipaddress

def generate_certificates():
    """Генерує сертифікати для сервера та клієнта."""
    def create_key_and_cert(name, alt_names):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = Name([
            NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kyiv"),
            NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),
            NameAttribute(NameOID.ORGANIZATION_NAME, f"{name} Org"),
            NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(SubjectAlternativeName(alt_names), critical=False)
            .sign(key, SHA256())
        )
        return key, cert

    def save_to_files(key, cert, key_path, cert_path):
        with open(key_path, "wb") as key_file:
            key_file.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    # Серверний сертифікат
    server_key, server_cert = create_key_and_cert(
        "Server",
        alt_names=[
            DNSName("localhost"),
            IPAddress(ipaddress.IPv4Address("127.0.0.1"))  # Виправлено формат IP-адреси
        ]
    )
    save_to_files(server_key, server_cert, "server.key", "server.pem")

    # Клієнтський сертифікат
    client_key, client_cert = create_key_and_cert(
        "Client",
        alt_names=[DNSName("localhost")]
    )
    save_to_files(client_key, client_cert, "client.key", "client.pem")



class SecureServer:
    """Сервер із підтримкою SSL/TLS."""
    def __init__(self, host="127.0.0.1", port=8443):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="server.pem", keyfile="server.key")
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(cafile="client.pem")

    def start(self):
        """Запуск сервера."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(f"[Сервер] Запущено на {self.host}:{self.port}")
            with self.context.wrap_socket(sock, server_side=True) as secure_sock:
                while True:
                    client_conn, client_addr = secure_sock.accept()
                    threading.Thread(target=self.handle_client, args=(client_conn, client_addr)).start()

    def handle_client(self, conn, addr):
        """Обробка підключення клієнта."""
        print(f"[Сервер] Клієнт підключився: {addr}")
        with conn:
            try:
                data = conn.recv(1024).decode('utf-8')
                message = json.loads(data)
                print(f"[Сервер] Отримано: {message}")
                response = json.dumps({"status": "success", "received": message})
                conn.send(response.encode('utf-8'))
            except Exception as e:
                print(f"[Сервер] Помилка: {e}")


class SecureClient:
    """Клієнт із підтримкою SSL/TLS."""
    def __init__(self, host="127.0.0.1", port=8443):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_cert_chain(certfile="client.pem", keyfile="client.key")
        self.context.load_verify_locations(cafile="server.pem")

    def connect(self):
        """Підключення до сервера."""
        with socket.create_connection((self.host, self.port)) as sock:
            with self.context.wrap_socket(sock, server_hostname="localhost") as secure_sock:
                print("[Клієнт] Підключено до сервера")
                self.exchange_data(secure_sock)

    def exchange_data(self, secure_sock):
        """Обмін даними з сервером."""
        try:
            message = json.dumps({"action": "send", "content": "Привіт, сервере!"})
            secure_sock.send(message.encode('utf-8'))
            response = secure_sock.recv(1024).decode('utf-8')
            print(f"[Клієнт] Відповідь сервера: {response}")
        except Exception as e:
            print(f"[Клієнт] Помилка: {e}")


if __name__ == "__main__":
    # Генеруємо сертифікати, якщо їх немає
    if not os.path.exists("server.key") or not os.path.exists("server.pem"):
        print("[Система] Генерація сертифікатів...")
        generate_certificates()

    # Головне меню
    print("1: Запустити сервер")
    print("2: Запустити клієнт")
    choice = input("Вибір: ").strip()

    if choice == "1":
        server = SecureServer()
        server.start()
    elif choice == "2":
        client = SecureClient()
        client.connect()
    else:
        print("[Система] Невірний вибір")
