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

    def preprocess_data(self, data, encoder=None):
        if encoder is None:
            encoder = LabelEncoder()
            for column in data.select_dtypes(include=['object']).columns:
                data[column] = encoder.fit_transform(data[column])
        else:
            for column in data.select_dtypes(include=['object']).columns:
                data[column] = encoder.transform(data[column])

        return data



    def train_and_evaluate_decision_tree(self, X_train, y_train, X_test, y_test, max_depth=None, criterion='gini'):
        tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
        tree_model.fit(X_train, y_train)

        accuracy, precision, recall, f1, conf_matrix = self.evaluate_model(tree_model, X_test, y_test)

        return tree_model, accuracy, precision, recall, f1, conf_matrix


    def evaluate_model(self, model, X_test, y_test):
        predictions = model.predict(X_test)
        
        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(y_test, predictions)
        recall = recall_score(y_test, predictions)
        f1 = f1_score(y_test, predictions)
        conf_matrix = confusion_matrix(y_test, predictions)

        
        return accuracy, precision, recall, f1, conf_matrix



    def split_data(self, data):
        X = data.drop('label', axis=1)
        y = data['label']

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.7, random_state=420)
        encoder = LabelEncoder()
        X_train = self.preprocess_data(X_train, encoder=encoder)
        X_test = self.preprocess_data(X_test, encoder=encoder)
        return X_train, X_test, y_train, y_test


    def create_set(self, normal_traffic, malicious_traffic):
        normal_flows = core.import_pcap(normal_traffic)
        normal_flows['label'] = 0 

        # Wczytanie ruchu złośliwego
        malicious_flows = core.import_pcap(malicious_traffic)
        malicious_flows['label'] = 1  # Oznaczenie ruchu jako złośliwego

        data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
        data = core.clean_data(data)
        data = data.drop_duplicates()
        return data


    def binary_search_best_model(self, data, criteria=['gini', 'entropy']):
        print("Starting binary search for the best decision tree model...")
        best_model = None
        best_precision = 0
        best_params = {'max_depth': None, 'criterion': None}
        best_stats = None
        
        for criterion in criteria:
            low, high = 1, 100  # Initial range for max_depth
            while low <= high:
                mid = (low + high) // 2

                model, accuracy, precision, recall, f1, conf_matrix = self.train_and_evaluate_decision_tree(data['X_train'], data['y_train'], data['X_test'], data['y_test'], max_depth=mid, criterion=criterion)
                stats = [accuracy, precision, recall, f1, conf_matrix]
                
                if precision > best_precision:
                    best_f1 = f1
                    best_model = model
                    best_stats = stats
                    best_params['max_depth'] = mid
                    best_params['criterion'] = criterion
                    low = mid + 1
                else:
                    high = mid - 1
        
        return best_model, best_params, best_stats




    def test_model_on_new_data(self, model, malicious_traffic, normal_traffic):
        # Load and preprocess the new data
        normal_flows = core.import_pcap(normal_traffic)
        normal_flows['label'] = 0 

        # Wczytanie ruchu złośliwego
        malicious_flows = core.import_pcap(malicious_traffic)
        malicious_flows['label'] = 1  # Oznaczenie ruchu jako złośliwego

        new_data = pd.concat([normal_flows, malicious_flows], ignore_index=True)

        visualisations.show_correlation(new_data)

        X_new = new_data.drop(columns=['label'])
        y_new = new_data['label']

        X_new = X_new[self.training_columns]
        
        # Preprocess the data
        X_new = self.preprocess_data(X_new)

        # Evaluate the model on the new data
        accuracy, precision, recall, f1, conf_matrix = self.evaluate_model(model, X_new, y_new)
        
        print(f"New Data Evaluation")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        print(f"Confusion Matrix:\n{conf_matrix}")
        
        return accuracy, precision, recall, f1, conf_matrix
    

    def classify_pcap(self, pcap_file):
        org_data = core.import_pcap(pcap_file)
        data = org_data[self.training_columns]
        data = self.preprocess_data(data)
        print(data)
        predictions = self.model.predict(data)
        print(predictions)

        detected_frames = org_data.iloc[predictions == 1]
        print(detected_frames)
        return detected_frames, predictions

    def classify_packet(self, packet):
        data = pd.DataFrame([packet])
        data = self.preprocess_data(data)
        
        prediction = self.model.predict(data)
        return prediction
    
    def show_details(self):
        print("Model accuracy: ", self.stats[0])
        print("Model precision: ", self.stats[1])
        print("Model recall: ", self.stats[2])
        print("Model f1: ", self.stats[3])
        print("Model confusion matrix: ", self.stats[4])
        print("Model parameters: ", self.params)

        visualisations.show_correlation(self.ds)

        plt.figure(figsize=(20,10))
        plot_tree(self.model, filled=True, feature_names=self.training_columns, class_names=['Normal', 'Malicious'], fontsize=10)
        plt.title("Wizualizacja drzewa decyzyjnego")
        plt.show()


    def __init__(self, malicious_traffic, normal_traffic):
        ds = self.create_set( malicious_traffic, normal_traffic)

        ds = ds.drop(columns=['src_mac', 'src_ip', 'dst_mac', 'dst_ip'])
        self.ds = ds
        
        X_train, X_test, y_train, y_test = self.split_data(ds)

        self.training_columns = X_train.columns

        data_dict = {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test
        }

        self.model, self.params, self.stats = self.binary_search_best_model(data_dict)



if __name__ == "__main__":
    tree = DecisionTree("pcap/maliciousFINAL.pcap", "pcap/normalFINAL.pcap")
    tree.show_details()
    tree.test_model_on_new_data(tree.model, "pcap/malicious.pcap", "pcap/normalFINAL.pcap")
    tree.classify_pcap("pcap/maliciousFINAL.pcap")


