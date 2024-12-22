import json
# Jeśli Twój plik z klasą RuleDetector nazywa się np. rule_detector.py
# zaimportuj go w ten sposób:
from youRule import RuleDetector

# Zakładamy, że kod SigRules znajduje się w pliku sigmaRulePCAP.py
# z odpowiednimi klasami i funkcjami (SigRules, print_summary itp.)
from sigmaRulePCAP import SigRules, print_summary

# Do przechwytywania ruchu wykorzystamy Scapy
from scapy.all import sniff

def main():
    # Pobierz ścieżkę do pliku PCAP od użytkownika
    pcap_path = input("Podaj ścieżkę do pliku .pcap: ")
    interfaceToScan = input("Podaj interfejs do skanu: ")

    # Pliki Sigma (załóżmy, że są w stałych ścieżkach)
    sigma_files = [
        "sigma/sigmaOne.yml",
        "sigma/sigmaTwo.yml"
    ]

    # 1) Utwórz i uruchom obiekt SigRules
    sig_rules = SigRules(pcap_file=pcap_path, sigma_files=sigma_files)
    analysis_results = sig_rules.analyze()

    # 2) Utwórz obiekt RuleDetector z wybranymi parametrami
    detector = RuleDetector(
        scan_threshold=10,             # próg unikalnych portów (wykrywanie skanowania)
        large_traffic_threshold=1000,  # próg łącznej liczby pakietów z jednego IP
        frequent_traffic_window=60,    # okno w sekundach dla "częstego ruchu"
        frequent_traffic_threshold=50, # liczba pakietów w oknie do wykrycia "częstego ruchu"
        timeout=300,                   # po jakim czasie (s) "czyścimy" nieaktywne IP
        flow_size_threshold=50000      # próg bajtów w sumie payloadu dla jednego flow
    )

    # 3) Rozpocznij sniffowanie na interfejsie podanym przez użytkownika
    print(f"\nRozpoczynam sniffing na interfejsie: {interfaceToScan}. Naciśnij Ctrl+C, aby przerwać.\n")

    try:
        sniff(iface=interfaceToScan, filter="ip", prn=detector.monitor_pkts)
    except KeyboardInterrupt:
        print("\n[!] Przerwano przez użytkownika (Ctrl+C).")
    finally:
        # Po zakończeniu wypisz podsumowanie z RuleDetector
        detector.print_summary()

    # 4) Wyświetl wyniki z analizy SigRules
    print("\nDetected Logs (Sigma):")
    print(json.dumps(analysis_results, indent=2))
    print_summary(analysis_results)

if __name__ == "__main__":
    main()
