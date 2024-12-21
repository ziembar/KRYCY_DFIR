from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier, plot_tree
from ipywidgets import interactive
import os
from nfstream import NFStreamer
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import networkx as nx
import matplotlib.pyplot as plt
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
import core
from datasketch import MinHash, MinHashLSH

import visualisations

# def string_to_lsh_float(s, lsh):
#     m = MinHash(num_perm=8)  # Reduced number of permutations for faster processing
#     for token in s:
#         m.update(token.encode('utf8'))
#     if s not in lsh.keys:
#         lsh.insert(s, m)
#     return float(int.from_bytes(m.digest(), byteorder='big') % (10**8)) / (10**8)

# def preprocess_data(data):
#     print("Preprocessing data...")
#     # Initialize LSH
#     lsh = MinHashLSH(threshold=0.5, num_perm=8)  # Reduced number of permutations
    
#     # Convert string columns to floats using LSH
#     for column in data.select_dtypes(include=['object']).columns:
#         print(f"Processing column: {column}")
#         data[column] = data[column].apply(lambda x: string_to_lsh_float(x, lsh))
    
#     return data



def encode_column(column):
    le = LabelEncoder()
    le.fit(column)
    return le.transform(column)

def preprocess_data(data):
    print("Preprocessing data...")
    
    # Convert string columns to numerical values using LabelEncoder
    for column in data.select_dtypes(include=['object']).columns:
        print(f"Processing column: {column}")
        data[column] = encode_column(data[column])
    
    return data


def train_and_evaluate_decision_tree(X_train, y_train, X_test, y_test, max_depth=None, criterion='gini'):
    tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
    tree_model.fit(X_train, y_train)

    accuracy, precision, recall, f1, conf_matrix = evaluate_model(tree_model, X_test, y_test)

    return tree_model, accuracy, precision, recall, f1, conf_matrix


def evaluate_model(model, X_test, y_test):
    print("Evaluating model...")
    predictions = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)
    conf_matrix = confusion_matrix(y_test, predictions)

    print(f"Accuracy: {accuracy:.4f}, f1: {f1:.4f}")
    
    return accuracy, precision, recall, f1, conf_matrix



def split_data(data):
    X = data.drop('label', axis=1)
    y = data['label']

    data_arr = []
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.7, random_state=420) #X_train, X_test, y_train, y_test

    X_test = preprocess_data(X_test)
    X_train = preprocess_data(X_train)
    return X_train, X_test, y_train, y_test


def create_set(normal_traffic, malicious_traffic):
    print("Creating learning set...")
    normal_flows = core.import_pcap(normal_traffic)
    normal_flows['label'] = 0 

    # Wczytanie ruchu złośliwego
    malicious_flows = core.import_pcap(malicious_traffic)
    malicious_flows['label'] = 1  # Oznaczenie ruchu jako złośliwego

    data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
    data = core.filter_ipv6(data)
    data = core.clean_data(data)
    data = data.drop_duplicates()
    print(data.head())
    return data


def binary_search_best_model(data, criteria=['gini', 'entropy']):
    print("Starting binary search for the best decision tree model...")
    best_model = None
    best_f1 = 0
    best_params = {'max_depth': None, 'criterion': None}
    
    for criterion in criteria:
        print(f"Criterion: {criterion}")
        low, high = 1, 200  # Initial range for max_depth
        while low <= high:
            mid = (low + high) // 2
            print(f"Low: {low}, Mid: {mid}, High: {high}")

            model, _, _, _, f1, _ = train_and_evaluate_decision_tree(data['X_train'], data['y_train'], data['X_test'], data['y_test'], max_depth=mid, criterion=criterion)
            
            
            if f1 > best_f1:
                best_f1 = f1
                best_model = model
                best_params['max_depth'] = mid
                best_params['criterion'] = criterion
                low = mid + 1
            else:
                high = mid - 1
    
    print(f"Best Model Parameters: {best_params}")
    print(f"Best Accuracy: {best_f1:.4f}")
    
    return best_model, best_params, best_f1




def test_model_on_new_data(model, normal_traffic, malicious_traffic, training_columns):
    # Load and preprocess the new data
    normal_flows = core.import_pcap(normal_traffic)
    normal_flows['label'] = 0 

    # Wczytanie ruchu złośliwego
    malicious_flows = core.import_pcap(malicious_traffic)
    malicious_flows['label'] = 1  # Oznaczenie ruchu jako złośliwego

    new_data = pd.concat([normal_flows, malicious_flows], ignore_index=True)

    X_new = new_data.drop(columns=['label'])
    y_new = new_data['label']

    X_new = X_new[training_columns]
    
    # Preprocess the data
    X_new = preprocess_data(X_new)

    # Evaluate the model on the new data
    accuracy, precision, recall, f1, conf_matrix = evaluate_model(model, X_new, y_new)
    
    print(f"New Data Evaluation - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}")
    print(f"Confusion Matrix:\n{conf_matrix}")
    
    return accuracy, precision, recall, f1, conf_matrix



if __name__ == "__main__":
    ds = create_set("maliciousFINAL.pcap", "normalFINAL.pcap")

    # Remove columns 'src_mac' and 'src_ip'
    # ds = ds.drop(columns=['src_mac', 'src_ip', 'dst_mac', 'dst_ip'])
    # ds = create_set("malicious_traffic.pcap", "normal_traffic.pcap")

    visualisations.show_correlation(ds)

    X_train, X_test, y_train, y_test = split_data(ds)

    data_dict = {
        'X_train': X_train,
        'X_test': X_test,
        'y_train': y_train,
        'y_test': y_test
    }

    model, params, accuracy = binary_search_best_model(data_dict)
    print("Model accuracy: ", accuracy)
    print("Model parameters: ", params)



    print("Testowanie modelu na nowych danych...")
    test_model_on_new_data(model, "normal_traffic.pcap", "malicious_traffic.pcap", data_dict['X_train'].columns)



    plt.figure(figsize=(20,10))
    plot_tree(model, filled=True, feature_names=ds.columns, class_names=['Normal', 'Malicious'], fontsize=10)
    plt.title("Wizualizacja drzewa decyzyjnego")
    plt.show()