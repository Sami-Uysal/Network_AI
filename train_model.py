import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

def load_data(file):
    data = pd.read_csv(file)

    data.fillna(0, inplace=True)

    data['proto'] = data['proto'].astype('category').cat.codes

    X = data[['dur', 'proto', 'sbytes', 'dbytes']]
    y = data['label']
    return X, y


X, y = load_data("data/UNSW_NB15_training-set.csv")


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


clf = RandomForestClassifier()
clf.fit(X_train, y_train)


feature_names = ["dur", "proto", "sbytes", "dbytes"]
joblib.dump((clf, feature_names), "trained_model.pkl")

