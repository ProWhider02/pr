from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP
from collections import defaultdict
import threading
import time
import prettytable

# Конфігурації
THRESHOLD_PACKETS = 100  # Поріг для кількості пакетів від одного джерела
THRESHOLD_PORTS = 10     # Поріг для унікальних портів від одного джерела
LOG_FILE = "captured_packets.log"  # Файл журналу
DATA_CLEANUP_INTERVAL = 60  # Інтервал очищення даних (секунди)

# Глобальні змінні
traffic_data = defaultdict(lambda: {"count": 0, "ports": set(), "last_seen": 0})
alerted_ips = set()

# Функція обробки пакетів
def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        # Оновлення даних про джерело
        traffic_data[src_ip]["count"] += 1
        traffic_data[src_ip]["ports"].add(dst_port)
        traffic_data[src_ip]["last_seen"] = current_time

        # Запис у журнал
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"Packet captured: Source IP: {src_ip}, Destination Port: {dst_port}\n")

        # Виявлення підозрілих дій
        if src_ip not in alerted_ips:
            if traffic_data[src_ip]["count"] > THRESHOLD_PACKETS:
                log_alert(f"Suspicious activity: {src_ip} sent over {THRESHOLD_PACKETS} packets!")
                alerted_ips.add(src_ip)

            if len(traffic_data[src_ip]["ports"]) > THRESHOLD_PORTS:
                log_alert(f"Port scanning detected from {src_ip}. Unique ports: {len(traffic_data[src_ip]['ports'])}")
                alerted_ips.add(src_ip)

# Функція запису попереджень
def log_alert(message):
    print(f"[ALERT] {message}")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[ALERT] {message}\n")

# Функція виводу підсумкової таблиці
def print_traffic_summary():
    table = prettytable.PrettyTable(["Source IP", "Packet Count", "Unique Ports"])
    for ip, data in traffic_data.items():
        table.add_row([ip, data["count"], len(data["ports"])])
    print(table)

# Функція очищення застарілих даних
def traffic_monitor_cleanup():
    while True:
        time.sleep(DATA_CLEANUP_INTERVAL)
        current_time = time.time()
        for ip in list(traffic_data.keys()):
            if current_time - traffic_data[ip]["last_seen"] > DATA_CLEANUP_INTERVAL:
                del traffic_data[ip]

# Функція вибору інтерфейсу
def select_interface():
    print("Доступні інтерфейси:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    try:
        selected = int(input("Оберіть інтерфейс (номер): "))
        return interfaces[selected]
    except (IndexError, ValueError):
        print("Неправильний вибір. Переконайтеся, що ввели коректний номер.")
        exit()

# Запуск сніффера
def start_sniffing(interface):
    print(f"Перехоплення трафіку на інтерфейсі: {interface}")
    try:
        with open(LOG_FILE, "w") as log_file:
            log_file.write("Packet capture started.\n")
        sniff(iface=interface, prn=process_packet, store=False)
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    # Вибір інтерфейсу
    interface = select_interface()

    # Запуск очищення даних у фоновому потоці
    cleanup_thread = threading.Thread(target=traffic_monitor_cleanup, daemon=True)
    cleanup_thread.start()

    # Запуск сніффера
    start_sniffing(interface)
