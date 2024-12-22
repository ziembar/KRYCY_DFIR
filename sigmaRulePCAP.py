import yaml
import pyshark
import json
from Enrichment_Service import Enrichment


class SigRules:
    """
    Klasa do analizy plików PCAP za pomocą reguł Sigma zapisanych w formacie YAML.
    """
    def __init__(self, pcap_file, sigma_files):
        """
        Inicjalizuje klasę z plikiem PCAP i listą plików Sigma.
        """
        self.pcap_file = pcap_file
        self.sigma_files = sigma_files

    @staticmethod
    def parse_sigma_file(file_path):
        """
        Parsuje plik YAML z regułą Sigma i wyciąga kryteria detekcji (selection.query).
        """
        with open(file_path, 'r') as f:
            sigma_rule = yaml.safe_load(f)
        detection = sigma_rule.get("detection", {})
        selection = detection.get("selection", {})
        query = selection.get("query", None)
        
        # Obsługa listy i tekstu
        if isinstance(query, str):
            return [query]
        elif isinstance(query, list):
            return query
        return []

    @staticmethod
    def analyze_pcap_with_sigma(pcap_path, criteria_list):
        """
        Analizuje plik PCAP i sprawdza, czy zapytania DNS spełniają kryteria Sigma.
        """
        detected_logs = []
        capture = pyshark.FileCapture(pcap_path, display_filter='dns')
        
        for packet in capture:
            try:
                if hasattr(packet.dns, 'qry_name'):
                    query_name = packet.dns.qry_name.lower()
                    if any(criteria in query_name for criteria in criteria_list):
                        detected_logs.append({
                            "timestamp": packet.sniff_time.isoformat(),
                            "query": query_name,
                            "source_ip": packet.ip.src,
                            "destination_ip": packet.ip.dst
                        })
            except AttributeError:
                continue

        capture.close()
        return detected_logs

    def analyze(self):
        """
        Analizuje plik PCAP z wieloma regułami Sigma.
        """
        results = {}
        for sigma_file in self.sigma_files:
            criteria = self.parse_sigma_file(sigma_file)
            rule_name = sigma_file.split('/')[-1]
            results[rule_name] = self.analyze_pcap_with_sigma(self.pcap_file, criteria)
        return results

def print_summary(analysis_results):
    enrich = Enrichment()
    """
    Wyświetla szczegółowe informacje o dopasowaniach i podsumowuje wyniki analizy.
    """
    total_matches = 0
    print("\n=== DETAILED MATCHES ===")
    for rule_name, logs in analysis_results.items():
        print(f"\nRule: {rule_name}")
        if logs:
            for match in logs:
                print(f"  - Timestamp     : {match['timestamp']}")
                print(f"    Query         : {match['query']}")
                print(f"    Source IP     : {match['source_ip']}")
                print(f"    Destination IP: {match['destination_ip']}")
                location = enrich.get_ip_location(match['destination_ip'])
                total_matches += 1
        else:
            print("  (No matches found for this rule)")

    print("\n=== SUMMARY ===")
    print(f"Total rules checked: {len(analysis_results)}")
    print(f"Total matches found: {total_matches}")
    print("=== END ===\n")


if __name__ == "__main__":
    pcap_file = "zzz.pcap"
    sigma_files = [
        "sigma/sigmaOne.yml",
        "sigma/sigmaTwo.yml"
    ]

    sig_rules = SigRules(pcap_file, sigma_files)
    analysis_results = sig_rules.analyze()

    print("\nDetected Logs:")
    print(json.dumps(analysis_results, indent=2))
    print_summary(analysis_results)
    print(analysis_results)
    additional_data = {'sigmaOne.yml': [{'timestamp': '2024-12-21T01:08:19.253461', 'query': 's1.tor-gateways.de', 'source_ip': '8.8.8.810', 'destination_ip': '8.8.8.8'}, {'timestamp': '2024-12-21T01:08:19.253503', 'query': 's1.tor-gateways.de', 'source_ip': '8.8.8.810', 'destination_ip': '8.8.8.8'}, {'timestamp': '2024-12-21T01:08:19.339807', 'query': 's1.tor-gateways.de', 'source_ip': '8.8.8.8', 'destination_ip': '8.8.8.810'}, {'timestamp': '2024-12-21T01:08:19.379514', 'query': 's1.tor-gateways.de', 'source_ip': '8.8.8.8', 'destination_ip': '8.8.8.810'}, {'timestamp': '2024-12-21T01:08:21.682856', 'query': 's1.tor-gateways.de', 'source_ip': '8.8.8.810', 'destination_ip': '8.8.8.8'}, {'timestamp': '2024-12-21T01:08:21.682899', 'query': 's1.tor-gateways.de', 'source_ip': '8.8.8.810', 'destination_ip': '8.8.8.8'}, {'timestamp': '2024-12-21T01:08:21.723257', 'query': 's1.tor-gateways.de', 'source_ip': '8.8.8.8', 'destination_ip': '8.8.8.810'}, {'timestamp': '2024-12-21T01:08:21.729974', 'query': 's1.tor-gateways.de', 'source_ip': '8.8.8.8', 'destination_ip': '8.8.8.810'}], 'sigmaTwo.yml': [{'timestamp': '2024-12-21T01:08:03.640043', 'query': 'api.telegram.org', 'source_ip': '8.8.8.810', 'destination_ip': '8.8.8.8'}, {'timestamp': '2024-12-21T01:08:03.640129', 'query': 'api.telegram.org', 'source_ip': '8.8.8.810', 'destination_ip': '8.8.8.8'}, {'timestamp': '2024-12-21T01:08:03.678984', 'query': 'api.telegram.org', 'source_ip': '8.8.8.8', 'destination_ip': '8.8.8.810'}, {'timestamp': '2024-12-21T01:08:03.701756', 'query': 'api.telegram.org', 'source_ip': '8.8.8.8', 'destination_ip': '8.8.8.810'}]}
    print_summary(additional_data)
