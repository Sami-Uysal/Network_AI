from scapy.all import sniff
from feature_extractor import extract_features
import joblib


model = joblib.load("trained_model.pkl")

def analyze_packet(packet):
    features = extract_features(packet)
    X = [[features.get('length', 0), features.get('proto', 0)]]
    prediction = model.predict(X)[0]
    print(f"Packet classified as: {'Malicious' if prediction == 1 else 'Normal'}")


sniff(filter="ip", prn=analyze_packet)
