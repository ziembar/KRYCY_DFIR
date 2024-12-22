import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, get_if_list


class RuleDetector():

    def __init__(self):
        # Słownik do przechowywania unikalnych portów dla każdego źródłowego IP
        self.src_to_ports = defaultdict(set)

        # Słownik do przechowywania czasu ostatniej aktywności każdego IP
        self.last_seen = {}

        # Słownik do przechowywania informacji, czy dla danego IP wykryto już skanowanie
        self.port_scan_detected = defaultdict(bool)

        # Słownik do przechowywania stanu połączeń TCP
        self.tcp_connections = defaultdict(lambda: {"syn": False, "ack": False, "data": False})

        # Limit czasu (w sekundach), po którym IP zostaje usunięte (5 minut)
        self.TIMEOUT = 300  

        # Próg skanowania – co najmniej 10 portów z jednego IP
        self.SCAN_THRESHOLD = 10

        # Globalna zmienna do zliczania przetworzonych pakietów
        self.packet_count = 0

    def process_packet(self, packet):
        print("PROCESSING PACKET")
        """
        Przetwarza pojedynczy pakiet, wykrywając skanowanie portów i usuwając nieaktywne IP.

        :param packet: Słownik z informacjami o pakiecie (src_ip, dst_port).
        """
        current_time = time.time()  # Aktualny czas w sekundach od epoki UNIX

        # Usuwanie IP, które były nieaktywne przez dłuższy czas
        inactive_ips = [ip for ip, last_time in self.last_seen.items() 
                        if current_time - last_time > self.TIMEOUT]
        for ip in inactive_ips:
            del self.src_to_ports[ip]
            del self.last_seen[ip]
            if ip in self.port_scan_detected:
                del self.port_scan_detected[ip]

        # Przetwarzanie bieżącego pakietu
        src_ip = packet['src_ip']
        dst_port = packet["dst_port"]

        # Aktualizacja czasu ostatniej aktywności
        self.last_seen[src_ip] = current_time

        # Dodajemy nowy port (jeśli jeszcze nie było go w zbiorze)
        if dst_port not in self.src_to_ports[src_ip]:
            self.src_to_ports[src_ip].add(dst_port)

            # Sprawdzamy, czy osiągnęliśmy próg (SCAN_THRESHOLD).
            if (len(self.src_to_ports[src_ip]) >= self.SCAN_THRESHOLD 
                    and not self.port_scan_detected[src_ip]):
                print(f"Port scanning detected from {src_ip}: "
                    f"scanned at least {len(self.src_to_ports[src_ip])} ports!")
                self.port_scan_detected[src_ip] = True

    def monitor_pkts(self, pkt, end=False):
        print(pkt)
        self.packet_count += 1


        src_ip = pkt.src_ip
        dst_ip = pkt.dst_ip
        src_port = pkt.src_port
        dst_port = pkt.dst_port

        # Convert the dictionary to a single hex value

        # Klucz identyfikujący połączenie
        connection_id = (src_ip, dst_ip, src_port, dst_port)

        # Mechanizm wykrywania handshake (SYN -> SYN+ACK -> ACK z danymi)
        # Flaga SYN to bit 0x02
        if (pkt.syn) and not (pkt.ack):  # SYN bez ACK
            self.tcp_connections[connection_id]["syn"] = True

        # Flaga SYN-ACK to 0x12 (dec 18)
        if pkt.syn and pkt.ack:  # SYN z ACK
            self.tcp_connections[connection_id]["ack"] = True

        # Flaga ACK (0x10) + payload > 0 -> mamy dane
        if pkt.ack and len(pkt.ip_packet) > 0:
            self.tcp_connections[connection_id]["data"] = True

        # Jeśli mamy SYN, SYN-ACK i ACK z danymi, uznajemy połączenie za zestawione
        if (self.tcp_connections[connection_id]["syn"]
            and self.tcp_connections[connection_id]["ack"]
            and self.tcp_connections[connection_id]["data"]):
            print(f"Communication detected between {src_ip}:{src_port} "
                f"and {dst_ip}:{dst_port}")
            del self.tcp_connections[connection_id]

        # Uzupełniamy słownik danych dla funkcji process_packet
        packet_data = {"src_ip": src_ip, "dst_port": dst_port}
        self.process_packet(packet_data)

    def print_summary(self):
        """
        Funkcja wyświetlająca podsumowanie na koniec działania programu
        (np. po naciśnięciu Ctrl+C).
        """
        print("\n=== SUMMARY ===")
        print(f"Total processed packets : {self.packet_count}")
        
        # Liczba unikalnych IP (tylko te, co się pojawiły, nawet jeśli nie skanowały)
        unique_ips = len(self.src_to_ports)
        print(f"Unique source IPs       : {unique_ips}")

        # Liczba IP oznaczonych jako skanujące
        scanning_ips_list = [ip for ip, scanned in self.port_scan_detected.items() if scanned]
        print(f"IPs flagged for scanning: {len(scanning_ips_list)}")

        # Wyświetlamy listę skanerów z przeskanowanymi portami
        if scanning_ips_list:
            print("\nList of IPs flagged as scanners and their scanned ports:")
            for ip in scanning_ips_list:
                # Dla pewności bierzemy listę przeskanowanych portów i sortujemy
                ports_list = sorted(self.src_to_ports.get(ip, []))
                print(f"  - {ip} -> scanned ports: {ports_list}")
        else:
            print("No scanners were detected.")

        print("=== END ===\n")

if __name__ == "__main__":

    # Inicjalizujemy obiekt klasy RuleDetector
    rule_detector = RuleDetector()
    try:
        print("Available interfaces:", get_if_list())
        print("Starting sniffing on interface: lo (loopback). Press Ctrl+C to stop.\n")

        sniff(iface="lo", filter="ip", prn=rule_detector.monitor_pkts)

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    finally:
        # Wyświetlamy podsumowanie
        rule_detector.print_summary()
