import click
from scapy.all import sniff, rdpcap, sendp, get_if_list, wrpcap
from ML_detect import DecisionTree
import os
import pickle
import threading
import csv

# Initialize the decision tree model
packet_detections = {"tree_classifier": {"count": 0, "packets": []}}
stop_sniffing = threading.Event()  # Shared event to control sniffing

def process_packet(packet, tree):
    print(packet)
    # Example placeholder logic
    # data = pd.DataFrame([packet])
    # data = tree.preprocess_data(data)
    # prediction = tree.classify_packet(data)
    # packet_detections['tree_classifier'] += int(prediction)

def monitor(interface):
    """Monitor packets on a specified interface with a graceful stop."""
    global stop_sniffing

    tree_pickle_path = "tree_classifier.pkl"

    if os.path.exists(tree_pickle_path):
        with open(tree_pickle_path, "rb") as f:
            tree = pickle.load(f)
    else:
        tree = DecisionTree("pcap/maliciousFINAL.pcap", "pcap/normalFINAL.pcap")
        with open(tree_pickle_path, "wb") as f:
            pickle.dump(tree, f)

    def sniff_packets():
        packets = []
        sniff(
            iface=interface,
            prn=lambda packet: (packets.append(packet), process_packet(packet, tree)),
            store=1,
            stop_filter=lambda _: stop_sniffing.is_set()
        )
        # Save captured packets to a pcap file
        pcap_file = "captured_packets.pcap"
        wrpcap(pcap_file, packets)
        return pcap_file

    try:
        packets = []
        sniff(
            iface=interface,
            prn=lambda packet: (packets.append(packet), process_packet(packet, tree)),
            store=1,
            stop_filter=lambda _: stop_sniffing.is_set()
        )
        # Save captured packets to a pcap file
        pcap_file = "captured_packets.pcap"
        wrpcap(pcap_file, packets)

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    finally:
        packets, detection_array = tree.classify_pcap("captured_packets.pcap")
        packet_detections["tree_classifier"]['packets'] = packets
        packet_detections["tree_classifier"]['count'] = len(packets)

    show_detections()


def replay(pcap_file, interface):
    """Replay packets from a pcap file on a specified interface."""
    packets = rdpcap(pcap_file)
    sendp(packets, iface=interface, verbose=1)

@click.group()
def cli():
    pass

@cli.command()
def list_interfaces():
    """List available network interfaces."""
    interfaces = get_if_list()
    click.echo("Available interfaces:")
    for iface in interfaces:
        click.echo(f"- {iface}")

@cli.command()
@click.option('--interface', prompt='Interface to monitor', help='Network interface to monitor packets on.')
def monitor_packets(interface):
    """Monitor packets on a specified interface."""
    monitor(interface)

@cli.command()
@click.option('--pcap-file', prompt='Path to PCAP file', help='Path to the PCAP file to replay.')
@click.option('--interface', prompt='Interface to replay on', help='Network interface to replay packets on.')
def replay_packets(pcap_file, interface):
    """Replay packets from a PCAP file."""
    replay(pcap_file, interface)

def show_detections():
    """Show packet detection summaries."""
    click.echo("Packet Detections Summary:")
    for classifier, data in packet_detections.items():
        click.echo(f"{classifier}: {data['count']} detections")
        print(data['packets'])
        data['packets'].to_csv('detections.csv', index=False)

if __name__ == "__main__":
    cli()
