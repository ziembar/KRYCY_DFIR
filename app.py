import pickle
import click
from scapy.all import sniff, rdpcap, sendp, get_if_list, wrpcap
from nfstream import NFStreamer, NFPlugin
import os
import pandas as pd
import numpy as np
from ml_model import DecisionTreeClassifierWrapper
from scanRule import RuleDetector

# Initialize the decision tree model
packet_detections = {"tree_classifier": {"count": 0, "packets": []}}

def clean_dataframe(df):
    """Convert all non-numeric columns to numeric and handle missing values."""
    for column in df.columns:
        if df[column].dtype == 'object':
            df[column] = pd.to_numeric(df[column], errors='coerce')
    df = df.fillna(0)
    for col in df.columns:
        if df[col].nunique() == 1:
            df.drop(col, inplace=True, axis=1)
    return df

def monitor(interface):
    """Monitor packets on a specified interface with a graceful stop."""
    global stop_sniffing


    # Initialize the custom model class
    
    feature_columns = []  # Initialize as empty, to be populated later

    if os.path.exists("ml.pkl"):
        rf_model = DecisionTreeClassifierWrapper().load("ml.pkl")

    else:
        malicious_df = NFStreamer(source="pcap/maliciousFINAL.pcap").to_pandas()
        normal_df = NFStreamer(source="pcap/normalFINAL.pcap").to_pandas()

        malicious_df_test = NFStreamer(source="pcap/traffic_test_malicious.pcap").to_pandas()
        normal_df_test = NFStreamer(source="pcap/normal_traffic.pcap").to_pandas()

        malicious_df["label"] = 1
        normal_df["label"] = 0

        malicious_df_test["label"] = 1
        normal_df_test["label"] = 0

        df = pd.concat([malicious_df, normal_df])
        df_test = pd.concat([malicious_df_test, normal_df_test])

        df = clean_dataframe(df)
        df_test = df_test[df.columns]

        feature_columns = [col for col in df.columns if col not in ["client_fingerprint", "expiration_id","label", "timestamp", "id", "src_ip", "dst_ip", "src_mac", "dst_mac"]]
        X = df[feature_columns]

        X_test = df_test[feature_columns]
        y = df["label"]

        y_test = df_test["label"]

        rf_model = DecisionTreeClassifierWrapper()

        # rf_model.train(X, y, X_test, y_test)
        rf_model.train(X, y)


    rule_detector = RuleDetector()

    class ModelPrediction(NFPlugin):
        
        def on_init(self, packet, flow):
            print(packet)
            self.my_detector.monitor_pkts(packet)

        def on_expire(self, flow):
            to_predict = np.array([
                pd.to_numeric(getattr(flow, attr), errors='coerce') for attr in rf_model.feature_columns
            ]).reshape((1, -1))
            to_predict = np.nan_to_num(to_predict)
            flow.udps.model_prediction = rf_model.predict(pd.DataFrame(to_predict, columns=rf_model.feature_columns))[0]

    try:
        # Capture packets and perform predictions
        ml_streamer = NFStreamer(source=interface, udps=ModelPrediction(my_model=rf_model, my_detector=rule_detector))
        for flow in ml_streamer:
            print(f"Flow Prediction: {flow.udps.model_prediction}")

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    rule_detector.print_summary()


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



    @cli.command()
    def model_stats():
        """Get current ML model statistics."""
        if os.path.exists("ml.pkl"):
            rf_model = DecisionTreeClassifierWrapper().load("ml.pkl")
            rf_model.show_details()
        else:
            click.echo("No trained model found. Please train the model first.")

    cli.add_command(model_stats)
if __name__ == "__main__":
    cli()