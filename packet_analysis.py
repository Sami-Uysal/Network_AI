import pandas as pd
from feature_extractor import extract_features
from model_loader import load_model

MODEL_PATH = "trained_model.pkl"
model, feature_names = load_model(MODEL_PATH)

def analyze_packet(packet, tree, details_box, packets_list):
    try:
        features = extract_features(packet)

        input_data = pd.DataFrame([[
            features.get('dur', 0),
            features.get('proto', 0),
            features.get('sbytes', 0),
            features.get('dbytes', 0)
        ]], columns=feature_names)

        prediction = model.predict(input_data)[0]
        result = "Normal" if prediction == 0 else "Kötü Amaçlı"

        summary = f"{features.get('src_ip', 'Bilinmiyor')} → {features.get('dst_ip', 'Bilinmiyor')}, " \
                  f"Proto: {features.get('proto', 'N/A')}"

        tree.insert("", "end", values=(packet.time, summary, result))

        packets_list.append(packet)
    except Exception as e:
        details_box.config(state="normal")
        details_box.insert("1.0", f"Hata: {e}\n")
        details_box.config(state="disabled")
