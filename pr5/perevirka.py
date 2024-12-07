from scapy.all import get_if_list, get_if_addr

print("Доступні інтерфейси:")
interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    try:
        ip_address = get_if_addr(iface)
    except:
        ip_address = "IP не визначено"
    print(f"{i}: {iface} (IP: {ip_address})")

selected = int(input("Оберіть інтерфейс (номер): "))
interface = interfaces[selected]
print(f"Обрано інтерфейс: {interface}")
