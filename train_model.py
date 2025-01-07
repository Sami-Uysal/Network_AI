import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

def load_data(file):
    data = pd.read_csv(file)

    data.fillna(0, inplace=True)

    data['proto'] = data['proto'].astype('category').cat.codes

    X = data[['dur', 'proto']]
    y = data['label']
    return X, y


X, y = load_data("data/UNSW_NB15_training-set.csv")


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


clf = RandomForestClassifier()
clf.fit(X_train, y_train)


joblib.dump(clf, "trained_model.pkl")

