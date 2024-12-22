import json

# Zakładamy, że kod SigRules znajduje się w pliku sigmaRulePCAP.py
# z odpowiednimi klasami i funkcjami (SigRules, print_summary itp.)
from sigmaRulePCAP import SigRules, print_summary

def main():
    # Pobierz ścieżkę do pliku PCAP od użytkownika
    pcap_path = input("Podaj ścieżkę do pliku .pcap: ")

    # Pliki Sigma (załóżmy, że są w stałych ścieżkach)
    sigma_files = [
        "sigma/sigmaOne.yml",
        "sigma/sigmaTwo.yml"
    ]

    # Utwórz obiekt reguł i uruchom analizę
    sig_rules = SigRules(pcap_file=pcap_path, sigma_files=sigma_files)
    analysis_results = sig_rules.analyze()

    # Wyświetl wyniki
    print("\nDetected Logs:")
    print(json.dumps(analysis_results, indent=2))
    print_summary(analysis_results)

if __name__ == "__main__":
    main()