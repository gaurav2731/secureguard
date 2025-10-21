"""
Machine Learning module for SecureGuard
"""
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

class MLDetector:
    def __init__(self):
        self.model = None
        self.feature_extractors = []
    
    def load_model(self, model_path):
        """Load trained ML model"""
        self.model = joblib.load(model_path)
    
    def analyze_packet(self, packet_data):
        """Analyze packet using ML model"""
        features = self.extract_features(packet_data)
        return self.model.predict_proba([features])[0]
    
    def train_model(self, training_data):
        """Train new ML model on custom data"""
        X, y = self.prepare_training_data(training_data)
        self.model = RandomForestClassifier()
        self.model.fit(X, y)
    
    def extract_features(self, packet_data):
        """Extract features from packet data"""
        features = []
        for extractor in self.feature_extractors:
            features.extend(extractor(packet_data))
        return features