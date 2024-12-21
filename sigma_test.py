import pandas as pd
from nfstream import NFStreamer
from sigma.parser.collection import SigmaCollectionParser
from sigma.parser.exceptions import SigmaParseError
from sigma.backends.base import Backend

def check_packet_against_sigma_rule(packet, sigma_rule):
    # Extract detection conditions from the Sigma rule
    detection_conditions = sigma_rule.detection.detections['selection'].detection_items
    
    # Check if the packet matches the detection conditions
    for condition in detection_conditions:
        field = condition.field
        values = [item.value for item in condition.value]
        
        if field in packet and packet[field] in values:
            return True
    return False

def check_nfstream_against_sigma_rules(nfstream_data, sigma_rules):
    matches = []
    
    for index, packet in nfstream_data.iterrows():
        for sigma_rule in sigma_rules:
            if check_packet_against_sigma_rule(packet, sigma_rule):
                matches.append(packet)
                print(f"ALERT: {sigma_rule.title}")
    
    return pd.DataFrame(matches)


class SigmaDetector:
    def __init__(self, sigma_rules_folder):
        """
        Inicjalizuje obiekt SigmaDetector, który ładuje wszystkie reguły Sigma z podanego folderu.

        :param sigma_rules_folder: Ścieżka do folderu z plikami reguł Sigma.
        """
        if not os.path.isdir(sigma_rules_folder):
            raise ValueError(f"Folder {sigma_rules_folder} nie istnieje.")

        # Lista plików w folderze
        self.sigma_files = [os.path.join(sigma_rules_folder, f) for f in os.listdir(sigma_rules_folder) if f.endswith('.yml') or f.endswith('.yaml')]
        if not self.sigma_files:
            raise ValueError(f"Brak plików Sigma w folderze {sigma_rules_folder}.")

        # Wczytanie wszystkich reguł Sigma do kolekcji
        self.sigma_collection = []
        for sigma_file in self.sigma_files:
            try:
                with open(sigma_file, 'r') as f:
                    sigma_content = f.read()
                rules = SigmaCollection.from_yaml(sigma_content)
                self.sigma_collection.extend(rules.rules)
            except Exception as e:
                print(f"Nie udało się wczytać reguły z pliku {sigma_file}: {e}")

        print(self.sigma_collection[0])

    def detect(self, df):
        """
        Przeprowadza detekcję na podanym DataFrame przy użyciu załadowanych reguł Sigma.

        :param df: DataFrame z danymi, na których mają zostać przeprowadzone testy.
        :return: DataFrame z dopasowaniami reguł Sigma.
        """
        matches = []

        # Dopasowanie każdej reguły do danych
        for rule in self.sigma_collection:
            for index, row in df.iterrows():
                log_entry = row.to_dict()  # Zamień wiersz na słownik
                try:
                    rule_logic = rule.get_rule()
                    match = eval(rule_logic, {}, log_entry)
                    if match:
                        matches.append(row)
                        print("ALERT: ", rule.title)
                except Exception as e:
                    print(f"Błąd podczas dopasowywania reguły: {e}")

        # Zwróć dopasowane wiersze jako DataFrame
        return pd.DataFrame(matches) if matches else pd.DataFrame(columns=df.columns)
    

# Example usage
rules_directory = 'sigma'
sigma_rules = import_sigma_rules(rules_directory)

# Load NFStream data
nfstream_data = NFStreamer(source="malicious_traffic.pcap", statistical_analysis=True).to_pandas()

# Check NFStream data against Sigma rules
matches = check_nfstream_against_sigma_rules(nfstream_data, sigma_rules)
print(matches)