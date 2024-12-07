import subprocess
import socket
from scapy.all import ARP, Ether, srp
from collections import defaultdict
import time

# Налаштування
INTERFACE = "Ethernet"  # Інтерфейс для сканування
THRESHOLD_PACKETS = 50  # Поріг пакетів для одного джерела
THRESHOLD_PORTS = 10    # Поріг різних портів для одного джерела
LOG_FILE = "captured_packets.log"  # Файл для збереження даних

# Дані про трафік
traffic_data = defaultdict(lambda: {"count": 0, "ports": set()})
alerted_ips = set()

# Функція для сканування мережі
def scan_network(network):
    print(f"Сканування мережі: {network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    active_hosts = []
    for element in answered_list:
        active_hosts.append(element[1].psrc)
        print(f"Знайдений активний хост: {element[1].psrc}")
    
    return active_hosts

# Функція для сканування портів
def scan_ports(ip):
    open_ports = []
    print(f"Сканування портів для {ip}...")
    for port in range(1, 1025):  # Скануємо порти з 1 по 1024
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Функція для визначення сервісу за портом
def get_service(port):
    try:
        service = socket.getservbyport(port)
    except OSError:
        service = "Unknown"
    return service

# Функція для налаштування брандмауера
def setup_firewall(block_ips=None, allow_ips=None, block_ports=None):
    # Для Windows використовуємо netsh для налаштування брандмауера
    if block_ips:
        for ip in block_ips:
            command = f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in action=block remoteip={ip}'
            subprocess.run(command, shell=True)
            print(f"Заборонено підключення з IP: {ip}")
    
    if allow_ips:
        for ip in allow_ips:
            command = f'netsh advfirewall firewall add rule name="Allow IP {ip}" dir=in action=allow remoteip={ip}'
            subprocess.run(command, shell=True)
            print(f"Дозволено підключення з IP: {ip}")
    
    if block_ports:
        for port in block_ports:
            command = f'netsh advfirewall firewall add rule name="Block Port {port}" dir=in action=block localport={port}'
            subprocess.run(command, shell=True)
            print(f"Заборонено підключення на порт: {port}")

# Функція для обробки пакетів
def process_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        traffic_data[src_ip]["count"] += 1
        traffic_data[src_ip]["last_seen"] = time.time()

        # Перевірка на підозрілу активність
        if traffic_data[src_ip]["count"] > THRESHOLD_PACKETS:
            log_alert(f"Підозрілий трафік з IP: {src_ip}")
        
        if packet.haslayer("TCP"):
            tcp_dst_port = packet["TCP"].dport
            if tcp_dst_port not in traffic_data[src_ip]["ports"]:
                traffic_data[src_ip]["ports"].add(tcp_dst_port)
            if len(traffic_data[src_ip]["ports"]) > THRESHOLD_PORTS:
                log_alert(f"Сканування портів з IP: {src_ip}")

# Функція для запису попереджень
def log_alert(message):
    print(f"[ALERT] {message}")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[ALERT] {message}\n")

# Основна функція для запуску
def main():
    # Крок 1: Сканування мережі
    network = "192.168.1.0/24"  # Приклад мережі для сканування
    active_ips = scan_network(network)

    # Крок 2: Сканування портів на знайдених хостах
    open_ports_data = {}
    for ip in active_ips:
        open_ports = scan_ports(ip)
        if open_ports:
            open_ports_data[ip] = open_ports
            print(f"Відкриті порти для {ip}: {open_ports}")

    # Крок 3: Визначення сервісів на відкритих портах
    for ip, ports in open_ports_data.items():
        for port in ports:
            service = get_service(port)
            print(f"IP: {ip}, Порт: {port}, Сервіс: {service}")

    # Крок 4: Налаштування брандмауера
    blocked_ips = ["192.168.1.10", "192.168.1.20"]  # Приклад заблокованих IP
    allowed_ips = ["192.168.1.30"]  # Приклад дозволених IP
    blocked_ports = [22, 80]  # Приклад заблокованих портів

    setup_firewall(block_ips=blocked_ips, allow_ips=allowed_ips, block_ports=blocked_ports)

if __name__ == "__main__":
    main()
