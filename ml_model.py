import os
from matplotlib import pyplot as plt
from sklearn.tree import DecisionTreeClassifier
import pickle
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, accuracy_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.tree import plot_tree
from nfstream import NFStreamer
from Enrichment_Service import get_ip_location

import visualisations

protocols = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IP-in-IP",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SwIPe",
    54: "NARP",
    55: "MOBILE",
    56: "TLSP",
    57: "SKIP",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    61: "Any host internal protocol",
    62: "CFTP",
    63: "Any local network",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    68: "Any distributed file system",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCU",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "TTP",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPF",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "OS",
    95: "MICP",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: "Any private encryption scheme",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    114: "Any 0-hop protocol",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM",
    123: "PTP",
    124: "IS-IS over IPv4",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "Mobility Header",
    136: "UDPLite",
    137: "MPLS-in-IP",
    138: "manet",
    139: "HIP",
    140: "Shim6",
    141: "WESP",
    142: "ROHC",
    143: "Ethernet",
    144: "AGGFRAG",
    145: "NSH",
    146: "Unassigned",
    252: "Unassigned",
    253: "Use for experimentation and testing",
    254: "Use for experimentation and testing",
    255: "Reserved"
}

class DecisionTreeClassifierWrapper:
    def __init__(self):

        if os.path.exists("ml.pkl"):
            with open("ml.pkl", "rb") as f:
                loaded_obj = pickle.load(f)
                self.__dict__.update(loaded_obj.__dict__)
                return
            
        self.model = DecisionTreeClassifier()
        self.feature_columns = []
        
        malicious_df = NFStreamer(source="pcap/maliciousFINAL.pcap").to_pandas()
        malicious_df2 = NFStreamer(source="pcap/zzz.pcap").to_pandas()
        malicious_df = pd.concat([malicious_df, malicious_df2])

        normal_df = NFStreamer(source="pcap/normalFINAL.pcap").to_pandas()

        malicious_df["label"] = 1
        normal_df["label"] = 0

        df = pd.concat([malicious_df, normal_df])

        df = self.clean_dataframe(df)

        feature_columns = [col for col in df.columns if col not in ["client_fingerprint", "expiration_id","label", "id", "src_ip", "dst_ip", "src_mac", "dst_mac"]]
        X = df[feature_columns]
        y = df["label"]
        self.train(X, y)



    def clean_dataframe(self, df):
        """Convert all non-numeric columns to numeric and handle missing values."""
        for column in df.columns:
            if df[column].dtype == 'object':
                df[column] = pd.to_numeric(df[column], errors='coerce')
        df = df.fillna(0)
        for col in df.columns:
            if df[col].nunique() == 1:
                df.drop(col, inplace=True, axis=1)
        return df

    def train_and_evaluate_decision_tree(self, max_depth=None, criterion='gini'):
        tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
        tree_model.fit(self.train_X, self.train_y)

        accuracy, precision, recall, f1, conf_matrix = self.evaluate_model(tree_model)

        return tree_model, accuracy, precision, recall, f1, conf_matrix


    def binary_search_best_model(self, criteria=['gini', 'entropy']):
        print("Starting binary search for the best decision tree model...")
        best_model = None
        best_false_positives = 99999999
        best_params = {'max_depth': None, 'criterion': None}
        best_stats = None
        
        for criterion in criteria:
            for max_depth in range(20, 0, -1):
                model, accuracy, precision, recall, f1, conf_matrix = self.train_and_evaluate_decision_tree(max_depth=max_depth, criterion=criterion)
                stats = [accuracy, precision, recall, f1, conf_matrix]
                
                false_positives = conf_matrix[0][1]
                print("max-depth: ", max_depth, " criterion: ", criterion, " false positives: ", false_positives, " f1: ", f1)
                
                if best_model is None or  (false_positives < best_false_positives and abs(f1 - best_f1) <= 0.05 * best_f1):
                    best_model = model
                    best_stats = stats
                    best_params['max_depth'] = max_depth
                    best_params['criterion'] = criterion
                    best_false_positives = false_positives
                    best_f1 = f1

        return best_model, best_params, best_stats

    def train(self, train_X, train_y, test_X=None, test_y=None):

        if test_X is None or test_y is None:
            train_X, test_X, train_y, test_y = train_test_split(train_X, train_y, test_size=0.2, random_state=42)
        self.train_X = train_X
        self.train_y = train_y

        self.test_X = test_X
        self.test_y = test_y
        self.feature_columns = train_X.columns

        self.model, self.params, self.stats = self.binary_search_best_model()
        with open("ml.pkl", "wb") as f:
            pickle.dump(self, f)

    def predict(self, X):
        return self.model.predict(X)

    def predict_packets(self, df_original):
        df = df_original.copy()

        for column in df.columns:
            if df[column].dtype == 'object':
                df[column] = pd.to_numeric(df[column], errors='coerce')
        df = df.fillna(0)
        df = df[self.feature_columns]
        
        predictions = self.model.predict(df)
        df = df_original.iloc[predictions == 1]

        
        df['protocol'] = df['protocol'].map(protocols)

        visualisations.ML_summary(df)

        result = []
        for _, row in df.iterrows():
            packet_info = {
                "source_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "protocol": row["protocol"],
                "dst_port": row["dst_port"],
                "ip_version": row["ip_version"],
                "bidirectional_duration_ms": row["bidirectional_duration_ms"],
                "bidirectional_first_seen_ms": row["bidirectional_first_seen_ms"],
                "source": "ML"
            }
            result.append(packet_info)
        print("============ ML PODSUMOWANIE =============")
        print(f"Spośród {len(df_original)} przepływów, {len(result)} zostało zaklasyfikowanych jako złośliwe.")
        print(f"Połączenia {len(df['src_ip'].unique())} adresów IP zostały zaklasyfikowane jako złośliwe.")

        return result

    def test(self):
        accuracy, precision, recall, f1, conf_matrix = self.evaluate_model()
        print("========================== Model parameters ======================")
        print("Max tree depth:", self.params['max_depth'])
        print("Criterion:", self.params['criterion'])
        print("========================== Model evaluation ======================")
        print("Accuracy: ", round(accuracy, 3))
        print("Precision: ", round(precision, 3))
        print("Recall: ", round(recall, 3))
        print("F1: ", round(f1, 3))
        print("Confusion matrix: ")
        print(conf_matrix)

    def evaluate_model(self, model=None):
        if model is None:
            model = self.model
        predictions = model.predict(self.test_X)
        
        accuracy = accuracy_score(self.test_y, predictions)
        precision = precision_score(self.test_y, predictions)
        recall = recall_score(self.test_y, predictions)
        f1 = f1_score(self.test_y, predictions)
        conf_matrix = confusion_matrix(self.test_y, predictions)

        return accuracy, precision, recall, f1, conf_matrix
    
    def show_details(self):
        self.test()

        plt.figure(figsize=(20,10))
        plot_tree(self.model, filled=True, feature_names=self.feature_columns, class_names=['Normal', 'Malicious'], fontsize=10)
        plt.title("Wizualizacja drzewa decyzyjnego")
        plt.show()

if __name__ == "__main__":    
    tree = DecisionTreeClassifierWrapper()
    tree.show_details()

    print(tree.predict_packets("pcap/traffic_test_malicious.pcap"))