import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib


def load_data(file):
    data = pd.read_csv(file)

    data.fillna(0, inplace=True)

    data['proto'] = data['proto'].astype('category').cat.codes

    X = data[['dur', 'proto']]
    y = data['label']
    return X, y


X_test, y_test = load_data("data/UNSW_NB15_testing-set.csv")

model = joblib.load("trained_model.pkl")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=1)
recall = recall_score(y_test, y_pred, zero_division=1)
f1 = f1_score(y_test, y_pred, zero_division=1)

print(f"Doğruluk (Accuracy): {accuracy:.2f}")
print(f"Kesinlik (Precision): {precision:.2f}")
print(f"Hatırlama (Recall): {recall:.2f}")
print(f"F1-Skoru: {f1:.2f}")
