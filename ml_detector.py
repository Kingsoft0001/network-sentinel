import time
import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class MLAnomalyDetector:
    """
    Advanced Machine Learning Anomaly Detection for Network Traffic.
    Uses Isolation Forest to detect abnormal connections (zero-day/unknown threats)
    by learning normal traffic patterns in real-time.
    """
    def __init__(self, history_size=1000):
        self.history_size = history_size
        self.features = [] # List of feature arrays (training data)
        self.model = IsolationForest(contamination=0.05, random_state=42) if ML_AVAILABLE else None
        self.is_trained = False
        self.connection_counts = {} # Tracks freq per IP
        self.observation_count = 0

    def _extract_features(self, remote_ip, local_port, status):
        # Feature 1: Connection frequency from this IP
        self.connection_counts[remote_ip] = self.connection_counts.get(remote_ip, 0) + 1
        freq = self.connection_counts[remote_ip]
        
        # Feature 2: Status encoded numerically
        if status == "ESTABLISHED": status_enc = 1
        elif status == "LISTEN": status_enc = 2
        elif "WAIT" in status: status_enc = 3
        else: status_enc = 0
        
        # Returns a vector: [Port, Frequency, Status]
        return [local_port, freq, status_enc]

    def observe(self, remote_ip, local_port, status):
        """Add connection to history and periodically retrain model."""
        if not ML_AVAILABLE or not remote_ip:
            return
            
        feat = self._extract_features(remote_ip, local_port, status)
        self.features.append(feat)
        self.observation_count += 1
        
        if len(self.features) > self.history_size:
            self.features.pop(0)

        # Train/Retrain the model when we have enough data (dynamic learning)
        if len(self.features) >= 20 and self.observation_count % 50 == 0:
            self.model.fit(self.features)
            self.is_trained = True

    def predict(self, remote_ip, local_port, status):
        """Predict if a connection is an anomaly. Returns (bool, str)."""
        if not ML_AVAILABLE:
            return False, "ML Engine not installed. Run: pip install scikit-learn numpy"
            
        if not self.is_trained or not remote_ip:
            return False, "ML learning normal traffic..."
            
        feat = self._extract_features(remote_ip, local_port, status)
        # Isolation Forest returns -1 for outlier/anomaly, 1 for inlier/normal
        prediction = self.model.predict([feat])[0]
        
        if prediction == -1:
            return True, f"AI detected irregular behavior (Freq: {feat[1]}, Port: {feat[0]})"
            
        return False, "Normal traffic"
