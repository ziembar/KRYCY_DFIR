from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier, plot_tree
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import core

import visualisations

class DecisionTree:
    def encode_column(self, column):
        le = LabelEncoder()
        le.fit(column)
        return le.transform(column)

    def preprocess_data(self, data):
        print("Preprocessing data...")
        
        # Convert string columns to numerical values using LabelEncoder
        for column in data.select_dtypes(include=['object']).columns:
            print(f"Processing column: {column}")
            data[column] = self.encode_column(data[column])
        
        return data


    def train_and_evaluate_decision_tree(self, X_train, y_train, X_test, y_test, max_depth=None, criterion='gini'):
        tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
        tree_model.fit(X_train, y_train)

        accuracy, precision, recall, f1, conf_matrix = self.evaluate_model(tree_model, X_test, y_test)

        return tree_model, accuracy, precision, recall, f1, conf_matrix


    def evaluate_model(self, model, X_test, y_test):
        print("Evaluating model...")
        predictions = model.predict(X_test)
        
        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(y_test, predictions)
        recall = recall_score(y_test, predictions)
        f1 = f1_score(y_test, predictions)
        conf_matrix = confusion_matrix(y_test, predictions)

        print(f"Accuracy: {accuracy:.4f}, f1: {f1:.4f}")
        
        return accuracy, precision, recall, f1, conf_matrix



    def split_data(self, data):
        X = data.drop('label', axis=1)
        y = data['label']

        data_arr = []
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.7, random_state=420) #X_train, X_test, y_train, y_test

        X_test = self.preprocess_data(X_test)
        X_train = self.preprocess_data(X_train)
        return X_train, X_test, y_train, y_test


    def create_set(self, normal_traffic, malicious_traffic):
        print("Creating learning set...")
        normal_flows = core.import_pcap(normal_traffic)
        normal_flows['label'] = 0 

        # Wczytanie ruchu złośliwego
        malicious_flows = core.import_pcap(malicious_traffic)
        malicious_flows['label'] = 1  # Oznaczenie ruchu jako złośliwego

        data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
        data = core.clean_data(data)
        data = data.drop_duplicates()
        print(data.head())
        return data


    def binary_search_best_model(self, data, criteria=['gini', 'entropy']):
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

                model, _, _, _, f1, _ = self.train_and_evaluate_decision_tree(data['X_train'], data['y_train'], data['X_test'], data['y_test'], max_depth=mid, criterion=criterion)
                
                
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




    def test_model_on_new_data(self, model,malicious_traffic, normal_traffic, training_columns):
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
        X_new = self.preprocess_data(X_new)

        # Evaluate the model on the new data
        accuracy, precision, recall, f1, conf_matrix = self.evaluate_model(model, X_new, y_new)
        
        print(f"New Data Evaluation - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1 Score: {f1:.4f}")
        print(f"Confusion Matrix:\n{conf_matrix}")
        
        return accuracy, precision, recall, f1, conf_matrix
    

    def classify_pcap(self, pcap_file):
        print("Classifying pcap file...")
        data = core.import_pcap(pcap_file)
        data = core.filter_ipv6(data)
        data = data[self.training_columns]
        data = self.preprocess_data(data)
        
        predictions = self.model.predict(data)
        return predictions

    def classify_packet(self, packet):
        print("Classifying packet...")
        data = pd.DataFrame([packet])
        data = self.preprocess_data(data)
        
        prediction = self.model.predict(data)
        return prediction


    def __init__(self, malicious_traffic, normal_traffic, malicious_traffic2, normal_traffic2):
        ds = self.create_set( malicious_traffic, normal_traffic)

        # Remove columns 'src_mac' and 'src_ip'
        ds = ds.drop(columns=['src_mac', 'src_ip', 'dst_mac', 'dst_ip'])
        # ds = create_set("malicious_traffic.pcap", "normal_traffic.pcap")

        visualisations.show_correlation(ds)

        X_train, X_test, y_train, y_test = self.split_data(ds)

        self.training_columns = X_train.columns

        data_dict = {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test
        }

        self.model, self.params, self.accuracy = self.binary_search_best_model(data_dict)
        print("Model accuracy: ", self.accuracy)
        print("Model parameters: ", self.params)


        print("Testowanie modelu na nowych danych...")
        self.test_model_on_new_data(self.model, malicious_traffic2, normal_traffic2, self.training_columns)

        plt.figure(figsize=(20,10))
        plot_tree(self.model, filled=True, feature_names=ds.columns, class_names=['Normal', 'Malicious'], fontsize=10)
        plt.title("Wizualizacja drzewa decyzyjnego")
        plt.show()