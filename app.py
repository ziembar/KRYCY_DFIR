import ML_detect
import core

tree = ML_detect.DecisionTree( "pcap/maliciousFINAL.pcap", "pcap/normalFINAL.pcap", "pcap/malicious_traffic.pcap", "pcap/normal_traffic.pcap")
y_mix = tree.classify_pcap("pcap/MIX.pcap")
print(y_mix)
num_zeros = y_mix.count(0)
num_ones = y_mix.count(1)
print(f"Number of false: {num_zeros}")
print(f"Number of positives: {num_ones}")