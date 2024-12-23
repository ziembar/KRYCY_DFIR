import time
import datetime
import json
from collections import defaultdict
from scapy.all import sniff, IP, TCP, get_if_list
from Enrichment_Service import get_ip_location
import json

class RuleDetector:
    """
    Klasa realizująca wykrywanie:
    1. Skanowania portów (liczba różnych portów przekracza próg).
    2. Dużego ruchu łącznie (przekroczenie zadanej liczby pakietów z jednego IP).
    3. Częstego ruchu (zbyt wiele pakietów w krótkim okresie).
    4. Dużego flow (suma bajtów w połączeniu TCP przekracza określony próg).
    """

    def __init__(self,
                 scan_threshold=10,
                 large_traffic_threshold=1000,
                 frequent_traffic_window=60,
                 frequent_traffic_threshold=50,
                 timeout=300,
                 flow_size_threshold=50000):
        """
        Inicjalizujemy strukturę danych i progi do wykrywania.

        :param scan_threshold:        Minimalna liczba unikalnych portów -> skanowanie.
        :param large_traffic_threshold: Próg łącznej liczby pakietów z jednego IP.
        :param frequent_traffic_window: Okno czasowe (w sekundach) do sprawdzania częstego ruchu.
        :param frequent_traffic_threshold: Liczba pakietów w ww. oknie -> częsty ruch.
        :param timeout: Czas (w sekundach), po którym nieaktywne IP są usuwane.
        :param flow_size_threshold:   Próg bajtów w całym flow (src_ip, dst_ip, src_port, dst_port).
        """

        # --- Progi / konfiguracja ---
        self.SCAN_THRESHOLD = scan_threshold
        self.LARGE_TRAFFIC_THRESHOLD = large_traffic_threshold
        self.FREQUENT_TRAFFIC_WINDOW = frequent_traffic_window
        self.FREQUENT_TRAFFIC_THRESHOLD = frequent_traffic_threshold
        self.TIMEOUT = timeout
        self.FLOW_SIZE_THRESHOLD = flow_size_threshold

        # -----------------------------
        # Słowniki do głównej logiki
        # -----------------------------
        # 1. Skanowanie portów
        self.src_to_ports = defaultdict(set)       # IP -> zbiór portów
        self.last_seen = {}                        # IP -> timestamp ostatniego pakietu
        self.port_scan_detected = defaultdict(bool)# IP -> czy wykryto skan

        # 2. Stan połączeń TCP (zliczamy także bajty w flow).
        #    Każde połączenie identyfikujemy krotką (src_ip, dst_ip, src_port, dst_port).
        #    Dodatkowo: 'start_time' do zapisu momentu pierwszego pakietu w danym flow.
        self.tcp_connections = defaultdict(lambda: {
            "syn": False, 
            "ack": False, 
            "data": False,
            "flow_bytes": 0, 
            "big_flow_detected": False,
            "start_time": None
        })

        # -----------------------------
        # Zmienne do reguł dużego i częstego ruchu (per IP)
        # -----------------------------
        self.ip_packet_count = defaultdict(int)      # IP -> liczba pakietów
        self.ip_packet_times = defaultdict(list)      # IP -> lista timestampów
        self.large_traffic_detected = defaultdict(bool)
        self.frequent_traffic_detected = defaultdict(bool)

        # -----------------------------
        # Statystyki
        # -----------------------------
        self.packet_count = 0  # łączna liczba przetworzonych pakietów

    # -----------------------------
    # Reguły: duży ruch i częsty ruch (dla IP)
    # -----------------------------
    def check_large_traffic(self, src_ip):
        """
        Sprawdza, czy dany IP przekroczył próg łącznej liczby pakietów.
        Jeśli tak, i jeszcze nie oznaczony, wypisuje ostrzeżenie.
        """
        if (self.ip_packet_count[src_ip] > self.LARGE_TRAFFIC_THRESHOLD
                and not self.large_traffic_detected[src_ip]):
            print(f"[SUSPICIOUS] IP {src_ip} - Large traffic: "
                  f"ponad {self.LARGE_TRAFFIC_THRESHOLD} pakietów łącznie.")
            self.large_traffic_detected[src_ip] = True

    def check_frequent_traffic(self, src_ip):
        """
        Sprawdza, czy dany IP wysłał więcej niż FREQUENT_TRAFFIC_THRESHOLD pakietów
        w ciągu ostatnich FREQUENT_TRAFFIC_WINDOW sekund.
        Jeśli tak, i jeszcze nie był oznaczony, wyświetla ostrzeżenie.
        """
        current_time = time.time()

        # Usuwamy pakiety starsze niż FREQUENT_TRAFFIC_WINDOW
        self.ip_packet_times[src_ip] = [
            t for t in self.ip_packet_times[src_ip]
            if current_time - t <= self.FREQUENT_TRAFFIC_WINDOW
        ]

        if (len(self.ip_packet_times[src_ip]) > self.FREQUENT_TRAFFIC_THRESHOLD
                and not self.frequent_traffic_detected[src_ip]):
            print(f"[SUSPICIOUS] IP {src_ip} - Frequent traffic: "
                  f"ponad {self.FREQUENT_TRAFFIC_THRESHOLD} pakietów w "
                  f"ostatnich {self.FREQUENT_TRAFFIC_WINDOW} sekundach.")
            self.frequent_traffic_detected[src_ip] = True

    # -----------------------------
    # Nowa reguła: duży flow (w tcp_connections)
    # -----------------------------
    def check_large_flow(self, connection_id, src_ip, dst_ip, src_port, dst_port):
        """
        Sprawdza, czy w tym połączeniu (flow) suma payloadu (flow_bytes) przekroczyła FLOW_SIZE_THRESHOLD.
        Jeśli tak, a jeszcze nie ostrzegaliśmy, wyświetla ostrzeżenie.
        """
        flow_info = self.tcp_connections[connection_id]
        if flow_info["flow_bytes"] > self.FLOW_SIZE_THRESHOLD and not flow_info["big_flow_detected"]:
            print(f"[SUSPICIOUS] Flow {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                  f"exceeded {self.FLOW_SIZE_THRESHOLD} bytes of TCP payload.")
            flow_info["big_flow_detected"] = True

    # -----------------------------
    # Główne przetwarzanie pakietu (dla IP, portu)
    # -----------------------------
    def process_packet(self, packet):
        """
        Przetwarza pakiet od strony IP (np. do wykrywania port scan, duży/częsty ruch).
        :param packet: słownik { "src_ip": ..., "dst_port": ... }
        """
        current_time = time.time()

        # 1. Usuwanie IP, które były nieaktywne przez dłuższy czas
        inactive_ips = [ip for ip, last_time in self.last_seen.items()
                         if current_time - last_time > self.TIMEOUT]
        for ip in inactive_ips:
            del self.src_to_ports[ip]
            del self.last_seen[ip]
            if ip in self.port_scan_detected:
                del self.port_scan_detected[ip]
            # Czyścimy dane z reguł dużego / częstego ruchu
            if ip in self.large_traffic_detected:
                del self.large_traffic_detected[ip]
            if ip in self.frequent_traffic_detected:
                del self.frequent_traffic_detected[ip]
            if ip in self.ip_packet_count:
                del self.ip_packet_count[ip]
            if ip in self.ip_packet_times:
                del self.ip_packet_times[ip]
            # UWAGA: Połączenia (tcp_connections) będziemy czyścić osobno,
            #        np. gdy stwierdzimy, że dane połączenie jest nieaktywne.

        # 2. Rejestrujemy aktywność
        src_ip = packet["src_ip"]
        dst_port = packet["dst_port"]
        self.last_seen[src_ip] = current_time

        self.ip_packet_count[src_ip] += 1
        self.ip_packet_times[src_ip].append(current_time)

        # 3. Wykrywanie skanowania portów
        if dst_port not in self.src_to_ports[src_ip]:
            self.src_to_ports[src_ip].add(dst_port)
            if (len(self.src_to_ports[src_ip]) >= self.SCAN_THRESHOLD
                    and not self.port_scan_detected[src_ip]):
                print(f"Port scanning detected from {src_ip}: "
                      f"scanned at least {len(self.src_to_ports[src_ip])} ports!")
                self.port_scan_detected[src_ip] = True

        # 4. Sprawdzamy duży / częsty ruch (dla IP)
        self.check_large_traffic(src_ip)
        self.check_frequent_traffic(src_ip)

    # -----------------------------
    # Funkcja wywoływana dla każdego pakietu (Scapy sniff)
    # -----------------------------
    def monitor_pkts(self, pkt):
        """
        Callback wywoływany przez sniff() przy każdym odebranym pakiecie.
        """
        self.packet_count += 1

        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags

            connection_id = (src_ip, dst_ip, src_port, dst_port)
            conn_info = self.tcp_connections[connection_id]

            # Jeśli to pierwszy pakiet w tym flow, zapisz datę/czas
            if conn_info["start_time"] is None:
                conn_info["start_time"] = datetime.datetime.utcnow().isoformat()

            # Zliczamy rozmiar payloadu w tym połączeniu (flow)
            conn_info["flow_bytes"] += len(pkt[TCP].payload)

            # Sprawdź próg dużego flow
            self.check_large_flow(connection_id, src_ip, dst_ip, src_port, dst_port)

            # Prosta logika trackowania handshake (SYN -> SYN+ACK -> ACK z danymi)
            if (flags & 0x02) and not (flags & 0x10):  # SYN bez ACK
                conn_info["syn"] = True
            if flags == 0x12:  # SYN+ACK = 0x12
                conn_info["ack"] = True
            if (flags & 0x10) and len(pkt[TCP].payload) > 0:  # ACK z danymi
                conn_info["data"] = True

            # Jeśli mamy SYN, SYN-ACK i ACK z danymi => komunikacja (połączenie zestawione)
            if conn_info["syn"] and conn_info["ack"] and conn_info["data"]:
                print(f"Communication detected between {src_ip}:{src_port} and {dst_ip}:{dst_port}")

            # Sprawdź także reguły IP
            packet_data = {"src_ip": src_ip, "dst_port": dst_port}
            self.process_packet(packet_data)

    def print_summary(self):
        print("\n=== SUMMARY ===")
        print(f"Total processed packets : {self.packet_count}")

        # Unikalne IP
        unique_ips = len(self.src_to_ports)
        print(f"Unique source IPs       : {unique_ips}")

        # IP, które wykryliśmy jako skanujące
        scanning_ips_list = [ip for ip, scanned in self.port_scan_detected.items() if scanned]
        print(f"IPs flagged for scanning: {len(scanning_ips_list)}")
        if scanning_ips_list:
            print("\nList of IPs flagged as scanners and their scanned ports:")
            for ip in scanning_ips_list:
                ports_list = sorted(self.src_to_ports.get(ip, []))
                location = get_ip_location(ip)
                if location:
                    print(f"  - {ip} ({location['kraj']}, {location['miasto']}, ISP: {location['dostawca_usług_internetowych']}) -> scanned ports: {ports_list}")
                else:
                    print(f"  - {ip} -> scanned ports: {ports_list} (location information not available)")
        else:
            print("No IPs were flagged for port scanning.")

        # IP z dużym / częstym ruchem
        large_traffic_list = [ip for ip, flagged in self.large_traffic_detected.items() if flagged]
        frequent_traffic_list = [ip for ip, flagged in self.frequent_traffic_detected.items() if flagged]

        if large_traffic_list:
            print("\nList of IPs flagged for large traffic:")
            for ip in large_traffic_list:
                print(f"  - {ip}: total packets -> {self.ip_packet_count.get(ip, 0)}")

        if frequent_traffic_list:
            print("\nList of IPs flagged for frequent traffic:")
            for ip in frequent_traffic_list:
                count_last_window = len(self.ip_packet_times[ip])  # Ostatni stan listy
                print(f"  - {ip}: {count_last_window} packets in {self.FREQUENT_TRAFFIC_WINDOW} s window")

        # Połączenia (flow), które przekroczyły próg bajtów (FLOW_SIZE_THRESHOLD)
        big_flows = [
            (conn_id, info)
            for conn_id, info in self.tcp_connections.items()
            if info["flow_bytes"] > self.FLOW_SIZE_THRESHOLD
        ]
        if big_flows:
            print(f"\nList of flows that exceeded {self.FLOW_SIZE_THRESHOLD} bytes of payload:")
            for (src_ip, dst_ip, s_port, d_port), info in big_flows:
                print(f"  - {src_ip}:{s_port} -> {dst_ip}:{d_port}, total = {info['flow_bytes']} bytes")

        # ==============================
        #   NIEBEZPIECZNE POŁĄCZENIA
        # ==============================
        print("\n=== DANGEROUS TCP CONNECTIONS (once per src_ip-dst_ip) ===")

        dangerous_connections_list = []
        already_reported_pairs = set()  # Tutaj zapamiętamy, że (src_ip, dst_ip) już zapisaliśmy

        for (src_ip, dst_ip, s_port, d_port), conn_info in self.tcp_connections.items():
            reasons = []

            # Sprawdzamy, dlaczego IP/flow zostało uznane za niebezpieczne
            if self.port_scan_detected[src_ip]:
                reasons.append("Port scanning")
            if self.large_traffic_detected[src_ip]:
                reasons.append("Large traffic")
            if self.frequent_traffic_detected[src_ip]:
                reasons.append("Frequent traffic")
            if conn_info["big_flow_detected"]:
                reasons.append("Big flow")

            # Jeśli jest jakikolwiek powód i jeszcze nie dodawaliśmy (src_ip, dst_ip)
            if reasons and (src_ip, dst_ip) not in already_reported_pairs:
                record = {
                    "timestamp": conn_info.get("start_time", "[Unknown time]"),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "scanned_ports": ", ".join(map(str, sorted(self.src_to_ports[src_ip]))),
                    "flow_bytes": conn_info["flow_bytes"],
                    # "query" to lista powodów oznaczenia jako niebezpieczne
                    "query": reasons
                }
                dangerous_connections_list.append(record)
                already_reported_pairs.add((src_ip, dst_ip))

        # Zapisujemy do pliku JSON tylko, jeśli są jakieś niebezpieczne połączenia
        if dangerous_connections_list:
            with open("scannerRes.json", "w") as f:
                json.dump(dangerous_connections_list, f, indent=2)
            print(f"[INFO] Zapisano {len(dangerous_connections_list)} niebezpiecznych wpisów do 'scannerRes.json'.")
        else:
            print("No dangerous TCP connections detected.")

        print("=== END ===\n")




# ---------------------------------
# Przykładowe użycie klasy RuleDetector
# ---------------------------------
if __name__ == "__main__":
    detector = RuleDetector(
        scan_threshold=10,            
        large_traffic_threshold=1000, 
        frequent_traffic_window=60,   
        frequent_traffic_threshold=50,
        timeout=300,                  
        flow_size_threshold=50000      # Próg sumy payloadu w bajtach w danym flow
    )

    print("Available interfaces:", get_if_list())
    print("Starting sniffing on interface: lo (loopback). Press Ctrl+C to stop.\n")

    try:
        sniff(iface="lo", filter="ip", prn=detector.monitor_pkts)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    finally:
        detector.print_summary()
