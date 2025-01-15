import joblib

def load_model(model_path):
    try:
        model_data = joblib.load(model_path)

        clf = model_data[0]
        feature_names = model_data[1]

        print(f"Model başarıyla yüklendi: {model_path}")
        return clf, feature_names
    except Exception as e:
        raise RuntimeError(f"Model yükleme hatası: {e}")
