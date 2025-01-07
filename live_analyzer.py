import pandas as pd
from scapy.all import sniff
from feature_extractor import extract_features
import joblib


model = joblib.load("trained_model.pkl")

def analyze_packet(packet):
    features = extract_features(packet)

    X = pd.DataFrame([{
        'dur': features.get('length', 0),
        'proto': features.get('proto', 0)
    }])

    try:
        prediction = model.predict(X)[0]
        print(f"Paket sınıflandırıldı: {'Kötü Amaçlı' if prediction == 1 else 'Normal'}")
    except Exception as e:
        print(f"Analiz sırasında hata: {e}")


sniff(filter="ip", prn=analyze_packet)
