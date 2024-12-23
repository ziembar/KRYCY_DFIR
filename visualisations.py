import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from core import import_pcap, clean_data, filter_ipv6
from datetime import datetime

def generate_flow_statistics(dataset):
    plt.figure(figsize=(14, 10))

    # 1. Plot of flow duration
    plt.subplot(3, 1, 3)
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
    plt.subplot(3, 2, 1)
    plt.scatter(dataset['dst_port'], dataset['src_port'], alpha=0.5, marker='.', color='brown')
    plt.title('Source vs. Destination Port')
    plt.xlabel('Destination Port')
    plt.ylabel('Source Port')
    plt.grid(True)

    plt.tight_layout(pad=3.0)
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

def ML_summary(df):
    fig, axes = plt.subplots(2, 2, figsize=(10, 10))  # Reduced figure size
    sns.countplot(y='src_ip', data=df, order=df['src_ip'].value_counts().index, ax=axes[0, 0])
    axes[0, 0].set_title('Source IP Addresses')
    axes[0, 0].set_xlabel('Count')
    axes[0, 0].set_ylabel('Source IP')

    # Plot of destination ports
    sns.countplot(y='dst_port', data=df, order=df['dst_port'].value_counts().index, ax=axes[0, 1])
    axes[0, 1].set_title('Destination Ports')
    axes[0, 1].set_xlabel('Count')
    axes[0, 1].set_ylabel('Destination Port')

    # Plot of protocols
    sns.countplot(y='protocol', data=df, order=df['protocol'].value_counts().index, ax=axes[1, 0])
    axes[1, 0].set_title('Protocols')
    axes[1, 0].set_xlabel('Count')
    axes[1, 0].set_ylabel('Protocol')

    # Histogram of bidirectional duration
    sns.histplot(df['bidirectional_duration_ms'], bins=30, kde=True, ax=axes[1, 1])
    axes[1, 1].set_title('Histogram of Bidirectional Duration')
    axes[1, 1].set_xlabel('Duration (ms)')
    axes[1, 1].set_ylabel('Frequency')


    plt.tight_layout(pad=3.0)
    plt.show()

def visualize_attack_timeline(MLresult, RuleResult, SigmaResult):

    rows = []

    # 1) Dane z silnika ML (czerwony) – ms epoki -> datetime (UTC)
    for item in MLresult:
        dt = datetime.utcfromtimestamp(item["bidirectional_first_seen_ms"] / 1000.0)
        rows.append({
            "timestamp": dt,
            "source": "ML"
        })

    # 2) Dane z silnika reguł (niebieski) – 'timestamp' (ISO8601)
    for item in RuleResult:
        dt = datetime.fromisoformat(item["timestamp"])
        rows.append({
            "timestamp": dt,
            "source": "Rule"
        })

    # 3) Dane z reguł Sigma (zielony) – 'timestamp' (ISO8601)
    for item in SigmaResult:
        dt = datetime.fromisoformat(item["timestamp"])
        rows.append({
            "timestamp": dt,
            "source": "Sigma"
        })

    # Jeżeli brak danych, przerywamy
    if not rows:
        print("[INFO] Brak danych do wizualizacji.")
        return

    # Konwersja do DataFrame
    df = pd.DataFrame(rows)
    # Zaokrąglamy timestamp do sekund (opcjonalnie)
    df["timestamp"] = df["timestamp"].dt.floor("s")

    # Grupujemy po (timestamp, source), liczymy liczbę zdarzeń
    grouped = df.groupby(["timestamp", "source"]).size().reset_index(name="count")

    # Pivot: kolumny: ML/Rule/Sigma, index: timestamp, values: count
    pivoted = grouped.pivot(index="timestamp", columns="source", values="count").fillna(0)

    # Wykres liniowy
    fig, ax = plt.subplots(figsize=(12, 6))

    # Jeśli kolumny istnieją, rysujemy
    if "ML" in pivoted.columns:
        ax.plot(pivoted.index, pivoted["ML"], color="red", marker="o", label="ML")
    if "Rule" in pivoted.columns:
        ax.plot(pivoted.index, pivoted["Rule"], color="blue", marker="o", label="Rule")
    if "Sigma" in pivoted.columns:
        ax.plot(pivoted.index, pivoted["Sigma"], color="green", marker="o", label="Sigma")

    ax.set_title("Attacks Over Time by Source (Line Chart)")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Number of Attacks")

    # Zawężenie osi X do [pierwsza_detekcja, ostatnia_detekcja]
    ax.set_xlim(pivoted.index.min(), pivoted.index.max())

    ax.legend(title="Source")
    ax.grid(True)
    fig.autofmt_xdate()  # automatycznie obraca etykiety osi X
    plt.tight_layout()
    plt.show()


def merge_ml_sigma(results):
    # Convert lists of dictionaries to DataFrames
    combined_results = pd.DataFrame(results)

    # Ensure the DataFrame has the necessary columns
    if not all(col in combined_results.columns for col in ['source_ip', 'source']):
        raise ValueError("Input data must have 'source_ip' and 'source' columns")

    # Group by source_ip and source, then count occurrences
    grouped = combined_results.groupby(['source_ip', 'source']).size().reset_index(name='count')

    # Pivot the DataFrame to have sources as columns, filling missing values with 0
    pivoted = grouped.pivot(index='source_ip', columns='source', values='count').fillna(0)

    # Plot the data
    pivoted.plot(kind='bar', stacked=True, figsize=(12, 6), colormap='viridis')
    plt.title('Detections by Source for Each source_ip')
    plt.xlabel('Source IP')
    plt.ylabel('Number of Detections')
    plt.legend(title='Source')
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
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

