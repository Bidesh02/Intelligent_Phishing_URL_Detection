import os
import sys
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report

# Configure paths relative to the project directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_detector.pkl")


def load_dataset(dataset_path: str, nrows: int = 1000):
    """Loads and preprocesses a sample from the dataset."""
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at: {dataset_path}")

    print(f"Loading dataset from: {dataset_path}...")
    df = pd.read_csv(dataset_path, nrows=nrows)

    # Drop non-feature columns as done in notebook
    df = df.drop_duplicates()
    df_clean = df.drop(
        columns=["FILENAME", "URL", "Domain", "TLD", "Title"],
        errors="ignore",
    )

    X = df_clean.drop("label", axis=1)
    # Target transformation (1 = Phishing, 0 = Legitimate)
    y = 1 - df_clean["label"]

    return X, y


def test_model(model_path: str = MODEL_PATH, dataset_path: str = DATASET_PATH):
    """Loads the saved model and evaluates it on test data."""
    if not os.path.exists(model_path):
        print(f"[!] Model file not found at: {model_path}")
        print("    Please run the training notebook 'phishing_detection.ipynb' first to generate and save the model.")
        return False

    print(f"Loading model from: {model_path}...")
    model = joblib.load(model_path)
    print("Model loaded successfully!")

    X_test, y_test = load_dataset(dataset_path, nrows=500)

    print("\nRunning predictions on sample test data...")
    predictions = model.predict(X_test)

    acc = accuracy_score(y_test, predictions)
    print(f"\nAccuracy on sample: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=["Legitimate (0)", "Phishing (1)"]))

    return True


if __name__ == "__main__":
    print("=" * 60)
    print(" Intelligent Phishing URL Detection - Model Test")
    print("=" * 60)
    print(f"Base Directory : {BASE_DIR}")
    print(f"Model Path     : {MODEL_PATH}")
    print(f"Dataset Path   : {DATASET_PATH}")
    print("-" * 60)

    success = test_model()
    if not success:
        sys.exit(1)
