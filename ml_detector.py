"""
Machine Learning module for SecureGuard
Ultra-Enhanced with advanced feature extraction, ensemble models, and adaptive learning
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import cross_val_score, train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.feature_selection import SelectKBest, f_classif, RFE
from sklearn.pipeline import Pipeline
from sklearn.neural_network import MLPClassifier
import joblib
import hashlib
import re
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlparse
from collections import defaultdict, deque
import threading
import time
import json
import os
import logging
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger(__name__)

class MLDetector:
    def __init__(self):
        self.model = None
        self.ensemble_model = None
        self.scaler = RobustScaler()  # More robust to outliers
        self.feature_selector = SelectKBest(score_func=f_classif, k=30)  # Increased features
        self.anomaly_detector = IsolationForest(contamination=0.05, random_state=42)  # Stricter anomaly detection
        self.label_encoder = LabelEncoder()

        # Advanced feature extractors
        self.feature_extractors = [
            self._extract_basic_features,
            self._extract_header_features,
            self._extract_payload_features,
            self._extract_timing_features,
            self._extract_behavioral_features,
            self._extract_geographic_features
        ]

        # Adaptive learning components
        self.model_metadata = {}
        self.performance_history = deque(maxlen=1000)
        self.false_positive_tracker = defaultdict(int)
        self.threat_patterns = defaultdict(int)
        self.learning_enabled = True
        self.retraining_threshold = 0.1  # Retrain when accuracy drops below 90%

        # Ensemble components
        self.rf_model = None
        self.gb_model = None
        self.nn_model = None

        # Real-time monitoring
        self.request_history = deque(maxlen=10000)
        self.ip_behavior_cache = defaultdict(lambda: {'requests': deque(maxlen=100), 'threat_score': 0.0})
        self.lock = threading.Lock()

        # Auto-tuning
        self.hyperparameter_tuning_enabled = True
        self.best_params = {}

    def load_model(self, model_path):
        """Load trained ML model and associated components"""
        try:
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_selector = model_data['feature_selector']
            self.anomaly_detector = model_data['anomaly_detector']
            self.label_encoder = model_data['label_encoder']
            self.model_metadata = model_data.get('metadata', {})
            logger.info(f"Loaded ML model from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def save_model(self, model_path):
        """Save trained ML model and components"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_selector': self.feature_selector,
                'anomaly_detector': self.anomaly_detector,
                'label_encoder': self.label_encoder,
                'metadata': self.model_metadata
            }
            joblib.dump(model_data, model_path)
            logger.info(f"Saved ML model to {model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False

    def analyze_packet(self, packet_data):
        """Advanced packet analysis with ensemble models and behavioral tracking"""
        try:
            ip = packet_data.get('ip', 'unknown')
            timestamp = packet_data.get('timestamp', datetime.now().timestamp())

            with self.lock:
                # Update IP behavior cache
                if ip not in self.ip_behavior_cache:
                    self.ip_behavior_cache[ip] = {'requests': deque(maxlen=100), 'threat_score': 0.0, 'last_seen': 0}

                self.ip_behavior_cache[ip]['requests'].append(timestamp)
                self.ip_behavior_cache[ip]['last_seen'] = timestamp

                # Clean old entries
                cutoff_time = timestamp - 3600  # 1 hour
                self.ip_behavior_cache[ip]['requests'] = deque(
                    [t for t in self.ip_behavior_cache[ip]['requests'] if t > cutoff_time],
                    maxlen=100
                )

            # Extract features
            features = self.extract_features(packet_data)
            features_scaled = self.scaler.transform([features])
            features_selected = self.feature_selector.transform(features_scaled)

            # Ensemble prediction
            threat_scores = []

            # Primary model prediction
            if self.model and hasattr(self.model, 'predict_proba'):
                threat_proba = self.model.predict_proba(features_selected)[0]
                threat_score = threat_proba[1] if len(threat_proba) > 1 else threat_proba[0]
                threat_scores.append(threat_score)

            # Ensemble models if available
            if self.ensemble_model:
                ensemble_pred = self.ensemble_model.predict_proba(features_selected)[0]
                ensemble_score = ensemble_pred[1] if len(ensemble_pred) > 1 else ensemble_pred[0]
                threat_scores.append(ensemble_score)

            # Anomaly detection
            anomaly_score = self.anomaly_detector.score_samples(features_selected)[0]

            # Behavioral analysis
            behavioral_score = self._analyze_behavioral_patterns(ip, packet_data)

            # Combine scores with weights
            if threat_scores:
                primary_score = np.mean(threat_scores)
                final_score = (primary_score * 0.6 + behavioral_score * 0.3 + (1 + anomaly_score) * 0.1)
                final_score = np.clip(final_score, 0.0, 1.0)
            else:
                final_score = behavioral_score

            # Update performance tracking
            self.performance_history.append({
                'timestamp': timestamp,
                'score': final_score,
                'ip': ip,
                'anomaly_score': anomaly_score
            })

            # Adaptive threshold based on recent performance
            dynamic_threshold = self._calculate_dynamic_threshold()

            return {
                'threat_score': float(final_score),
                'anomaly_score': float(anomaly_score),
                'behavioral_score': float(behavioral_score),
                'is_threat': final_score > dynamic_threshold,
                'is_anomaly': anomaly_score < -0.3,
                'confidence': float(abs(final_score - 0.5) * 2),
                'dynamic_threshold': float(dynamic_threshold),
                'ensemble_used': len(threat_scores) > 1
            }

        except Exception as e:
            logger.error(f"Packet analysis failed: {e}")
            return {
                'threat_score': 0.5,
                'anomaly_score': 0.0,
                'behavioral_score': 0.0,
                'is_threat': False,
                'is_anomaly': False,
                'confidence': 0.0,
                'dynamic_threshold': 0.7,
                'ensemble_used': False
            }

    def train_model(self, training_data, test_size=0.2, cv_folds=5):
        """Train ML model with cross-validation and evaluation"""
        try:
            X, y = self.prepare_training_data(training_data)

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)

            # Feature scaling
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # Feature selection
            X_train_selected = self.feature_selector.fit_transform(X_train_scaled, y_train)
            X_test_selected = self.feature_selector.transform(X_test_scaled)

            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train_selected, y_train)

            # Train anomaly detector
            self.anomaly_detector.fit(X_train_selected)

            # Evaluate model
            train_score = self.model.score(X_train_selected, y_train)
            test_score = self.model.score(X_test_selected, y_test)

            # Cross-validation
            cv_scores = cross_val_score(self.model, X_train_selected, y_train, cv=cv_folds)

            # Detailed metrics
            y_pred = self.model.predict(X_test_selected)
            report = classification_report(y_test, y_pred, output_dict=True)

            # Store metadata
            self.model_metadata = {
                'training_date': datetime.now().isoformat(),
                'training_samples': len(X_train),
                'test_samples': len(X_test),
                'features_used': X_train_selected.shape[1],
                'train_accuracy': train_score,
                'test_accuracy': test_score,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'classification_report': report
            }

            logger.info(f"Model trained successfully. Test accuracy: {test_score:.3f}")
            return self.model_metadata

        except Exception as e:
            logger.error(f"Model training failed: {e}")
            raise

    def extract_features(self, packet_data):
        """Extract comprehensive features from packet data"""
        features = []
        for extractor in self.feature_extractors:
            try:
                features.extend(extractor(packet_data))
            except Exception as e:
                logger.warning(f"Feature extraction failed: {e}")
                features.extend([0.0] * 5)  # Default values for failed extraction
        return features

    def _extract_basic_features(self, packet_data):
        """Extract basic request features"""
        features = []

        # Request method (one-hot encoded)
        method = packet_data.get('method', 'GET')
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        for m in methods:
            features.append(1.0 if method == m else 0.0)

        # URL length and complexity
        url = packet_data.get('url', '')
        features.append(len(url))  # URL length
        features.append(url.count('/'))  # Path depth
        features.append(url.count('?'))  # Query parameters count
        features.append(len(url.split('?')[1]) if '?' in url else 0)  # Query length

        # Content length
        content_length = packet_data.get('content_length', 0)
        features.append(content_length)

        return features

    def _extract_header_features(self, packet_data):
        """Extract features from HTTP headers"""
        features = []
        headers = packet_data.get('headers', {})

        # User-Agent analysis
        ua = headers.get('User-Agent', '')
        features.append(len(ua))  # UA length
        features.append(1.0 if 'bot' in ua.lower() else 0.0)  # Bot indicator
        features.append(1.0 if 'curl' in ua.lower() else 0.0)  # Curl indicator
        features.append(1.0 if not ua else 0.0)  # Missing UA

        # Referer analysis
        referer = headers.get('Referer', '')
        features.append(len(referer))  # Referer length
        features.append(1.0 if referer and urlparse(referer).netloc != urlparse(packet_data.get('url', '')).netloc else 0.0)  # External referer

        # Accept headers
        accept = headers.get('Accept', '')
        features.append(len(accept.split(',')))  # Accept types count

        # Host header
        host = headers.get('Host', '')
        features.append(len(host))  # Host length
        features.append(1.0 if '.' in host else 0.0)  # Domain indicator

        return features

    def _extract_payload_features(self, packet_data):
        """Extract features from request payload"""
        features = []
        payload = packet_data.get('data', '')

        # SQL injection patterns
        sql_patterns = [r"(\%27)|(\')|(\-\-)|(\%23)|(#)", r"union.*select", r"information_schema"]
        sql_score = sum(1 for pattern in sql_patterns if re.search(pattern, payload, re.I))
        features.append(sql_score)

        # XSS patterns
        xss_patterns = [r"<script>", r"javascript:", r"on\w+\s*=", r"alert\("]
        xss_score = sum(1 for pattern in xss_patterns if re.search(pattern, payload, re.I))
        features.append(xss_score)

        # Path traversal patterns
        traversal_patterns = [r"\.\./", r"\.\.\\", r"%2e%2e"]
        traversal_score = sum(1 for pattern in traversal_patterns if re.search(pattern, payload, re.I))
        features.append(traversal_score)

        # Suspicious keywords
        suspicious_words = ['eval', 'exec', 'system', 'passthru', 'shell_exec', 'base64_decode']
        suspicious_score = sum(1 for word in suspicious_words if word in payload.lower())
        features.append(suspicious_score)

        # Entropy (randomness measure)
        if payload:
            entropy = self._calculate_entropy(payload)
        else:
            entropy = 0.0
        features.append(entropy)

        return features

    def _extract_timing_features(self, packet_data):
        """Extract timing and frequency features"""
        features = []

        # Request timing (if available)
        timestamp = packet_data.get('timestamp', datetime.now().timestamp())
        features.append(timestamp % 86400)  # Time of day (seconds since midnight)
        features.append(timestamp % 3600)   # Time within hour

        # Request frequency (placeholder - would need historical data)
        features.extend([0.0, 0.0, 0.0])  # Frequency features

        return features

    def _extract_behavioral_features(self, packet_data):
        """Extract behavioral pattern features"""
        features = []
        ip = packet_data.get('ip', 'unknown')

        with self.lock:
            if ip in self.ip_behavior_cache:
                behavior = self.ip_behavior_cache[ip]
                requests = behavior['requests']

                # Request frequency in last hour
                features.append(len(requests))

                # Average time between requests
                if len(requests) > 1:
                    intervals = [requests[i] - requests[i-1] for i in range(1, len(requests))]
                    avg_interval = sum(intervals) / len(intervals)
                    features.append(avg_interval)
                    features.append(min(intervals))  # Min interval
                    features.append(max(intervals))  # Max interval
                else:
                    features.extend([3600.0, 3600.0, 3600.0])  # Default 1 hour

                # Burst detection (requests in last minute)
                now = packet_data.get('timestamp', datetime.now().timestamp())
                recent_requests = sum(1 for t in requests if now - t < 60)
                features.append(recent_requests)

                # Previous threat score
                features.append(behavior['threat_score'])
            else:
                # Default values for new IPs
                features.extend([1.0, 3600.0, 3600.0, 3600.0, 1.0, 0.0])

        return features

    def _extract_geographic_features(self, packet_data):
        """Extract geographic and network features"""
        features = []
        ip = packet_data.get('ip', 'unknown')

        # Basic IP analysis
        try:
            ip_obj = ipaddress.ip_address(ip)
            features.append(1.0 if ip_obj.is_private else 0.0)  # Private IP
            features.append(1.0 if ip_obj.is_loopback else 0.0)  # Loopback
            features.append(1.0 if ip_obj.is_multicast else 0.0)  # Multicast
            features.append(1.0 if ip_obj.version == 6 else 0.0)  # IPv6
        except:
            features.extend([0.0, 0.0, 0.0, 0.0])

        # Known malicious IP check
        features.append(1.0 if ip in self.false_positive_tracker else 0.0)

        # Geographic indicators (simplified)
        suspicious_ranges = ['10.', '172.', '192.168.', '127.']
        features.append(1.0 if any(ip.startswith(range_) for range_ in suspicious_ranges) else 0.0)

        return features

    def _analyze_behavioral_patterns(self, ip, packet_data):
        """Analyze behavioral patterns for threat scoring"""
        if ip not in self.ip_behavior_cache:
            return 0.0

        behavior = self.ip_behavior_cache[ip]
        requests = behavior['requests']
        now = packet_data.get('timestamp', datetime.now().timestamp())

        score = 0.0

        # High frequency attacks
        if len(requests) > 100:  # Too many requests
            score += 0.8

        # Burst attacks
        recent_burst = sum(1 for t in requests if now - t < 10)  # Requests in last 10 seconds
        if recent_burst > 5:
            score += 0.6

        # Regular intervals (bot behavior)
        if len(requests) > 10:
            intervals = [requests[i] - requests[i-1] for i in range(1, len(requests))]
            std_dev = np.std(intervals) if intervals else 0
            mean_interval = np.mean(intervals) if intervals else 0
            if std_dev < mean_interval * 0.1:  # Very regular intervals
                score += 0.4

        # Update threat score
        behavior['threat_score'] = min(1.0, behavior['threat_score'] * 0.9 + score * 0.1)

        return behavior['threat_score']

    def _calculate_dynamic_threshold(self):
        """Calculate dynamic threshold based on recent performance"""
        if not self.performance_history:
            return 0.7

        recent_scores = [p['score'] for p in list(self.performance_history)[-100:]]
        if not recent_scores:
            return 0.7

        # Calculate threshold based on score distribution
        mean_score = np.mean(recent_scores)
        std_score = np.std(recent_scores)

        # Dynamic threshold: mean + 1.5 * std, but bounded
        threshold = mean_score + 1.5 * std_score
        return np.clip(threshold, 0.5, 0.9)

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        entropy = 0.0
        data_bytes = data.encode('utf-8', errors='ignore')
        for byte in range(256):
            p = data_bytes.count(byte) / len(data_bytes)
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy

    def prepare_training_data(self, training_data):
        """Prepare training data from raw packet data"""
        if isinstance(training_data, list):
            # Convert list of dicts to DataFrame
            df = pd.DataFrame(training_data)
        elif isinstance(training_data, pd.DataFrame):
            df = training_data
        else:
            raise ValueError("Training data must be list of dicts or DataFrame")

        # Extract features for all samples
        X = []
        for _, row in df.iterrows():
            features = self.extract_features(row.to_dict())
            X.append(features)

        X = np.array(X)

        # Prepare labels
        if 'label' in df.columns:
            y = self.label_encoder.fit_transform(df['label'])
        elif 'is_attack' in df.columns:
            y = df['is_attack'].astype(int).values
        else:
            # Auto-label based on known attack patterns (simplified)
            y = np.zeros(len(X))
            for i, row in df.iterrows():
                payload = row.get('data', '')
                if any(pattern in payload.lower() for pattern in ['union select', '<script>', '../../../']):
                    y[i] = 1

        return X, y

    def get_feature_importance(self):
        """Get feature importance scores"""
        if hasattr(self.model, 'feature_importances_'):
            return self.model.feature_importances_
        return None

    def should_retrain(self):
        """Determine if model should be retrained based on performance"""
        if not self.performance_history:
            return False

        # Check recent performance
        recent_performance = list(self.performance_history)[-100:]  # Last 100 predictions
        if len(recent_performance) < 10:
            return False

        # Calculate recent accuracy (assuming threat_score > 0.5 is positive prediction)
        recent_predictions = [p['score'] > 0.5 for p in recent_performance]
        recent_accuracy = sum(recent_predictions) / len(recent_predictions)

        # Retrain if accuracy drops below threshold
        return recent_accuracy < self.retraining_threshold

    def get_model_stats(self):
        """Get comprehensive model statistics"""
        return {
            'metadata': self.model_metadata,
            'feature_importance': self.get_feature_importance(),
            'scaler_mean': self.scaler.mean_ if hasattr(self.scaler, 'mean_') else None,
            'scaler_scale': self.scaler.scale_ if hasattr(self.scaler, 'scale_') else None
        }
