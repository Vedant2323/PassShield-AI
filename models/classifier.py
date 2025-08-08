import os
import re
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

class PasswordClassifier:
    def __init__(self, model_path='models/password_classifier.joblib'):
        self.model_path = model_path
        self.model = None
        
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                print(f"✅ Model loaded from {model_path}")
            except Exception as e:
                print(f"⚠️ Error loading model: {e}")

    def model_exists(self):
        return self.model is not None

    def extract_features(self, password):
        return {
            'length': len(password),
            'has_digits': int(bool(re.search(r'\d', password))),
            'has_lowercase': int(bool(re.search(r'[a-z]', password))),
            'has_uppercase': int(bool(re.search(r'[A-Z]', password))),
            'has_special': int(bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))),
            'digits_ratio': sum(c.isdigit() for c in password) / len(password) if password else 0,
            'uppercase_ratio': sum(c.isupper() for c in password) / len(password) if password else 0,
            'unique_char_ratio': len(set(password)) / len(password) if password else 0,
        }

    def prepare_data(self, file_path):
        print(f"📥 Loading dataset from {file_path}...")
        df = pd.read_csv(file_path)

        X = pd.DataFrame([self.extract_features(p) for p in df['password']])
        y = df['label']

        print(f"📊 Dataset size: {len(y)} | Weak: {sum(y)} | Strong: {len(y)-sum(y)}")
        return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    def train(self, file_path):
        X_train, X_test, y_train, y_test = self.prepare_data(file_path)

        print("🌲 Training Random Forest...")
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            class_weight='balanced',  # important for balanced datasets
            random_state=42
        )
        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"✅ Accuracy: {acc:.4f}")
        print(classification_report(y_test, y_pred))

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print(f"💾 Model saved to {self.model_path}")

    def predict(self, password):
        if not self.model:
            raise RuntimeError("Model not loaded or trained.")
        features = pd.DataFrame([self.extract_features(password)])
        return bool(self.model.predict(features)[0])
