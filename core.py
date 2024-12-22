from nfstream import NFStreamer
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import networkx as nx
import warnings
import matplotlib.pyplot as plt


def import_pcap(filename):

    warnings.filterwarnings("ignore")
    streamer = NFStreamer(source=filename)
    return streamer.to_pandas()

 
def clean_data(dataset):
# Usuwanie kolumn, które mają tylko jedną unikalną wartość lub brakujące wartości
    for col in dataset.columns:
        if dataset[col].nunique() == 1:
            dataset.drop(col, inplace=True, axis=1)

    return dataset


def filter_ipv6(dataset):
    # Filter out rows with IPv6 addresses
    dataset = dataset[~dataset['src_ip'].str.contains(':')]
    dataset = dataset[~dataset['dst_ip'].str.contains(':')]
    return dataset