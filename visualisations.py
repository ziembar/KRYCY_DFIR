from nfstream import NFStreamer
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from core import import_pcap, clean_data, filter_ipv6

def generate_flow_statistics(dataset):
    plt.figure(figsize=(14, 10))

    # 1. Plot of flow duration
    plt.subplot(3, 2, 1)
    plt.plot(dataset['dst2src_duration_ms'], color='blue')
    plt.title('Flow Duration Plot')
    plt.xlabel('Index')
    plt.ylabel('Duration (ms)')
    plt.grid(True)

    # 2. Histogram of packet count
    plt.subplot(3, 2, 2)
    plt.hist(dataset['bidirectional_packets'], bins=30, color='green', alpha=0.7)
    plt.axvline(dataset['bidirectional_packets'].mean(), color='red', linestyle='dashed', linewidth=1)
    plt.axvline(dataset['bidirectional_packets'].median(), color='yellow', linestyle='dashed', linewidth=1)
    plt.title('Bidirectional Packet Count Histogram')
    plt.xlabel('Packet Count')
    plt.ylabel('Frequency')
    plt.legend({'Mean': dataset['bidirectional_packets'].mean(), 'Median': dataset['bidirectional_packets'].median()})
    plt.grid(True)

    # 3. Scatter plot of bytes vs packets
    plt.subplot(3, 2, 3)
    plt.scatter(dataset['bidirectional_packets'], dataset['bidirectional_bytes'], alpha=0.5, color='purple')
    plt.title('Bytes vs Packets Scatter Plot')
    plt.xlabel('Bidirectional Packets')
    plt.ylabel('Bidirectional Bytes')
    plt.grid(True)

# 4. Combined Histogram of Source and Destination Port
    plt.subplot(3, 2, 4)
    plt.hist(dataset['src_port'], bins=30, color='orange', alpha=0.7, label='Source Port')
    plt.hist(dataset['dst_port'], bins=30, color='cyan', alpha=0.5, label='Destination Port')
    plt.title('Source and Destination Port Histogram')
    plt.xlabel('Port')
    plt.ylabel('Frequency')
    plt.legend()
    plt.grid(True)

    # 6. Scatter plot of Source vs. Destination Port
    plt.subplot(3, 2, 6)
    plt.scatter(dataset['dst_port'], dataset['src_port'], alpha=0.5, marker='.', color='brown')
    plt.title('Source vs. Destination Port')
    plt.xlabel('Destination Port')
    plt.ylabel('Source Port')
    plt.grid(True)


    data = dataset.select_dtypes(include=[np.number])
    if 'label' in data.columns:
        # Obliczanie korelacji wszystkich cech z etykietą
        correlation_with_label = data.corr()['label'].sort_values(key=abs, ascending=False)

        # Usunięcie korelacji etykiety z samą sobą
        correlation_with_label = correlation_with_label.drop('label', errors='ignore')

        # Wybór 10 najbardziej skorelowanych cech
        top_10_correlated_features = correlation_with_label.head(10)

        print("10 cech najbardziej skorelowanych z etykietą:\n", top_10_correlated_features)

        # Wizualizacja korelacji tych cech z etykietą
        plt.figure(figsize=(10, 6))
        sns.barplot(x=top_10_correlated_features.index, y=top_10_correlated_features.values, palette='viridis')
        plt.title('Top 10 cech najbardziej skorelowanych z etykietą')
        plt.xlabel('Cechy')
        plt.ylabel('Współczynnik korelacji')
        plt.xticks(rotation=45)  # Obrót etykiet osi X dla lepszej czytelności
    else:
        print("Brak kolumny 'label' w danych.")


    plt.show()

def generate_network_graph(dataset):
    G = nx.Graph()

    # Add nodes and edges
    for index, row in dataset.iterrows():
        src_ip = row['src_ip']
        dst_ip = row['dst_ip']
        packets = row['bidirectional_packets']

        if not G.has_node(src_ip):
            G.add_node(src_ip)
        if not G.has_node(dst_ip):
            G.add_node(dst_ip)

        if G.has_edge(src_ip, dst_ip):
            G[src_ip][dst_ip]['weight'] += packets
        else:
            G.add_edge(src_ip, dst_ip, weight=packets)

    # Node size based on the number of connections
    node_size = [G.degree(node) * 100 for node in G.nodes()]

    # Edge width based on the number of packets
    edge_width = [G[u][v]['weight'] / 10 for u, v in G.edges()]

    pos = nx.spring_layout(G, k=0.5, iterations=50)
    plt.figure(figsize=(14, 10))

    nx.draw_networkx_nodes(G, pos, node_size=node_size, node_color='blue', alpha=0.7)
    nx.draw_networkx_edges(G, pos, width=edge_width, edge_color='gray', alpha=0.5)
    nx.draw_networkx_labels(G, pos, font_size=10, font_color='black')

    plt.title('Network Graph of IP Connections')
    plt.show()

def create_packet_matrix(dataset):
    # Get unique IPs
    unique_ips = list(set(dataset['src_ip']).union(set(dataset['dst_ip'])))
    
    # Create an empty DataFrame with unique IPs as both rows and columns
    packet_matrix = pd.DataFrame(0, index=unique_ips, columns=unique_ips)
    
    # Populate the DataFrame with the number of packets exchanged
    for index, row in dataset.iterrows():
        src_ip = row['src_ip']
        dst_ip = row['dst_ip']
        packets = row['bidirectional_packets']
        
        packet_matrix.at[src_ip, dst_ip] += packets
        packet_matrix.at[dst_ip, src_ip] += packets  # Assuming bidirectional packets
    
    return packet_matrix

def show_correlation(data):
    data = data.select_dtypes(include=[np.number])

    if 'label' in data.columns:
        # Obliczanie korelacji wszystkich cech z etykietą
        correlation_with_label = data.corr()['label'].sort_values(key=abs, ascending=False)

        # Usunięcie korelacji etykiety z samą sobą
        correlation_with_label = correlation_with_label.drop('label', errors='ignore')

        # Wybór 10 najbardziej skorelowanych cech
        top_10_correlated_features = correlation_with_label.head(10)

        print("10 cech najbardziej skorelowanych z etykietą:\n", top_10_correlated_features)

        # Wizualizacja korelacji tych cech z etykietą
        plt.figure(figsize=(10, 6))
        sns.barplot(x=top_10_correlated_features.index, y=top_10_correlated_features.values, palette='viridis')
        plt.title('Top 10 cech najbardziej skorelowanych z etykietą')
        plt.xlabel('Cechy')
        plt.ylabel('Współczynnik korelacji')
        plt.xticks(rotation=45)  # Obrót etykiet osi X dla lepszej czytelności
    else:
        print("Brak kolumny 'label' w danych.")


    plt.show()



if __name__ == "__main__":
    dataset = import_pcap('pcap/malicious_traffic.pcap')
    dataset = filter_ipv6(dataset)
    dataset = clean_data(dataset)

    # learning_set = create_learning_set("normal_traffic.pcap", "malicious_traffic.pcap")
    # print(learning_set.head())

    # show_correlation(learning_set)
    generate_flow_statistics(dataset)
    generate_network_graph(dataset)
    print(create_packet_matrix(dataset))
