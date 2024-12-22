from matplotlib import pyplot as plt
from sklearn.tree import DecisionTreeClassifier
import pickle
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, accuracy_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.tree import plot_tree

import visualisations

class DecisionTreeClassifierWrapper:
    def __init__(self):
        self.model = DecisionTreeClassifier()
        self.feature_columns = []
        self.test_X = None
        self.test_y = None

    def train_and_evaluate_decision_tree(self, max_depth=None, criterion='gini'):
        tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
        tree_model.fit(self.train_X, self.train_y)

        accuracy, precision, recall, f1, conf_matrix = self.evaluate_model(tree_model)

        return tree_model, accuracy, precision, recall, f1, conf_matrix


    def binary_search_best_model(self, criteria=['gini', 'entropy']):
        print("Starting binary search for the best decision tree model...")
        best_model = None
        best_false_positives = 0
        best_params = {'max_depth': None, 'criterion': None}
        best_stats = None
        
        for criterion in criteria:
            for max_depth in range(20, 0, -1):
                model, accuracy, precision, recall, f1, conf_matrix = self.train_and_evaluate_decision_tree(max_depth=max_depth, criterion=criterion)
                stats = [accuracy, precision, recall, f1, conf_matrix]
                
                false_positives = conf_matrix[0][1]
                print("max-depth: ", max_depth, " criterion: ", criterion, " false positives: ", false_positives, " f1: ", f1)
                
                if  f1 > best_f1 or best_model is None:
                    best_f1 = f1
                    best_model = model
                    best_stats = stats
                    best_params['max_depth'] = max_depth
                    best_params['criterion'] = criterion

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

    @staticmethod
    def load(path):
        with open(path, "rb") as f:
            return pickle.load(f)

    def test(self):
        accuracy, precision, recall, f1, conf_matrix = self.evaluate_model()
        print("Model accuracy: ", accuracy)
        print("Model precision: ", precision)
        print("Model recall: ", recall)
        print("Model f1: ", f1)
        print("Model confusion matrix: ", conf_matrix)

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
        # visualisations.show_correlation(self.ds)

        self.test()

        plt.figure(figsize=(20,10))
        plot_tree(self.model, filled=True, feature_names=self.feature_columns, class_names=['Normal', 'Malicious'], fontsize=10)
        plt.title("Wizualizacja drzewa decyzyjnego")
        plt.show()