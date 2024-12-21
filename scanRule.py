import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, get_if_list

# Słownik do przechowywania unikalnych portów dla każdego źródłowego IP
src_to_ports = defaultdict(set)

# Słownik do przechowywania czasu ostatniej aktywności każdego IP
last_seen = {}

# Słownik do przechowywania informacji, czy dla danego IP wykryto już skanowanie
port_scan_detected = defaultdict(bool)

# Słownik do przechowywania stanu połączeń TCP
tcp_connections = defaultdict(lambda: {"syn": False, "ack": False, "data": False})

# Limit czasu (w sekundach), po którym IP zostaje usunięte
TIMEOUT = 300  # 5 minut

# Próg skanowania – co najmniej 10 portów z jednego IP
SCAN_THRESHOLD = 10

def process_packet(packet):
    """
    Przetwarza pojedynczy pakiet, wykrywając skanowanie portów i usuwając nieaktywne IP.

    :param packet: Słownik z informacjami o pakiecie (src_ip, dst_port).
    """
    current_time = time.time()  # Aktualny czas w sekundach od epoki UNIX

    # Usuwanie IP, które były nieaktywne przez dłuższy czas
    inactive_ips = [ip for ip, last_time in last_seen.items() if current_time - last_time > TIMEOUT]
    for ip in inactive_ips:
        del src_to_ports[ip]
        del last_seen[ip]
        # Jeśli śledzimy też czy skan został wykryty, możemy to wyzerować:
        if ip in port_scan_detected:
            del port_scan_detected[ip]

    # Przetwarzanie bieżącego pakietu
    src_ip = packet["src_ip"]
    dst_port = packet["dst_port"]

    # Aktualizacja czasu ostatniej aktywności
    last_seen[src_ip] = current_time

    # Aktualizacja zestawu portów dla danego IP
    if dst_port not in src_to_ports[src_ip]:
        src_to_ports[src_ip].add(dst_port)

        # Możemy wciąż wyświetlać aktualną liczbę portów, np. w formie debug:
        print(f"[DEBUG] {src_ip} -> port {dst_port}, liczba portów: {len(src_to_ports[src_ip])}")

        # Sprawdzamy, czy osiągnęliśmy próg 10 portów.
        if len(src_to_ports[src_ip]) >= SCAN_THRESHOLD and not port_scan_detected[src_ip]:
            print(f"Port scanning detected from {src_ip}: scanned at least {len(src_to_ports[src_ip])} ports!")
            port_scan_detected[src_ip] = True

def monitor_pkts(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport

        # UWAGA: pkt[TCP].flags to liczba, nie string:
        flags = pkt[TCP].flags

        # Klucz identyfikujący połączenie
        connection_id = (src_ip, dst_ip, src_port, dst_port)

        # Prosty mechanizm wykrywania handshake (SYN -> SYN-ACK -> ACK z danymi)
        # Flaga SYN (0x02)
        if flags & 0x02 and not (flags & 0x10):  # SYN samodzielny
            tcp_connections[connection_id]["syn"] = True

        # Flaga SYN-ACK to 0x12 w zapisie heksadecymalnym (18 w dziesiętnym)
        if flags == 0x12:  # SYN + ACK
            tcp_connections[connection_id]["ack"] = True

        # Flaga ACK (0x10); sprawdzamy czy w pakiecie są dane
        if (flags & 0x10) and len(pkt[TCP].payload) > 0:
            tcp_connections[connection_id]["data"] = True

        # Jeśli mamy SYN, SYN-ACK i ACK z danymi, uznajemy połączenie za zestawione
        if (tcp_connections[connection_id]["syn"] and 
            tcp_connections[connection_id]["ack"] and 
            tcp_connections[connection_id]["data"]):
            print(f"Communication detected between {src_ip}:{src_port} and {dst_ip}:{dst_port}")
            del tcp_connections[connection_id]

        # Uzupełniamy słownik danych dla funkcji process_packet
        packet_data = {"src_ip": src_ip, "dst_port": dst_port}
        process_packet(packet_data)

if __name__ == "__main__":
    print(get_if_list())
    sniff(iface="lo", filter="ip", prn=monitor_pkts)
