import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

def load_data(file):
    data = pd.read_json(file, lines=True)
    data.fillna(0, inplace=True)
    X = data[['length', 'proto']]  # Basit özellikler
    y = data['label']  # Etiketler (1 = Zararlı, 0 = Normal)
    return X, y


X, y = load_data("packets.json")


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


clf = RandomForestClassifier()
clf.fit(X_train, y_train)


joblib.dump(clf, "trained_model.pkl")


y_pred = clf.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
