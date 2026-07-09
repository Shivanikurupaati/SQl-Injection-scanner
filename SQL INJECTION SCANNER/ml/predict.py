"""
Prediction module for SQL injection detection.
Loads trained model and provides real-time predictions.
"""

import pickle
import numpy as np
from pathlib import Path
from typing import Dict, Tuple
import sys
import os

# Handle imports for both package and direct execution
# This needs to work in multiple contexts: as a package, from backend, or directly
_ml_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_ml_dir)

# Ensure parent directory is in path for absolute imports
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

# Ensure ml directory is in path for direct imports
if _ml_dir not in sys.path:
    sys.path.insert(0, _ml_dir)

try:
    # Try relative import first (when ml is a package)
    from .feature_extractor import SQLFeatureExtractor
except ImportError:
    try:
        # Try absolute import (when ml is in sys.path)
        from ml.feature_extractor import SQLFeatureExtractor
    except ImportError:
        # If both fail, use direct import (when running directly)
        from feature_extractor import SQLFeatureExtractor


class SQLInjectionPredictor:
    """Predictor class for SQL injection detection."""
    
    def __init__(self, model_dir='models'):
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.feature_extractor = None
        self.model_name = None
        self.load_model()
    
    def load_model(self):
        """Load trained model, scaler, and feature extractor."""
        model_path = self.model_dir / 'sql_injection_model.pkl'
        scaler_path = self.model_dir / 'scaler.pkl'
        feature_extractor_path = self.model_dir / 'feature_extractor.pkl'
        
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model not found at {model_path}. Please train the model first using train_model.py"
            )
        
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        if scaler_path.exists():
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
        
        if feature_extractor_path.exists():
            # Ensure SQLFeatureExtractor is importable for pickle
            # This is needed because pickle needs to import the class
            try:
                from .feature_extractor import SQLFeatureExtractor
            except ImportError:
                try:
                    from ml.feature_extractor import SQLFeatureExtractor
                except ImportError:
                    current_dir = os.path.dirname(os.path.abspath(__file__))
                    if current_dir not in sys.path:
                        sys.path.insert(0, current_dir)
                    from feature_extractor import SQLFeatureExtractor
            
            with open(feature_extractor_path, 'rb') as f:
                self.feature_extractor = pickle.load(f)
        else:
            self.feature_extractor = SQLFeatureExtractor()
        
        # Load model info if available
        info_path = self.model_dir / 'model_info.json'
        if info_path.exists():
            import json
            with open(info_path, 'r') as f:
                info = json.load(f)
                self.model_name = info.get('model_name', 'Unknown')
        
        print(f"Model loaded successfully! (Type: {self.model_name or type(self.model).__name__})")
    
    def predict(self, query: str) -> Dict[str, any]:
        """
        Predict if a query is SQL injection.
        Handles both raw SQL queries and URLs with parameters.
        
        Args:
            query: SQL query string or URL to check
            
        Returns:
            Dictionary with prediction results
        """
        if not query or not isinstance(query, str):
            return {
                'is_sql_injection': False,
                'confidence': 0.0,
                'query': query,
                'error': 'Invalid query input'
            }
        
        # Check if input is a URL
        import urllib.parse
        parsed_url = urllib.parse.urlparse(query)
        
        # If it looks like a URL (has scheme and netloc) or has parameters
        if (parsed_url.scheme and parsed_url.netloc) or '?' in query:
            # Extract parameters
            params = urllib.parse.parse_qs(parsed_url.query)
            
            if not params:
                # No parameters to inject into
                return {
                    'is_sql_injection': False,
                    'confidence': 0.99,
                    'probability_safe': 0.99,
                    'probability_injection': 0.01,
                    'query': query,
                    'note': 'No parameters found in URL'
                }
            
            # Check each parameter value
            max_injection_prob = 0.0
            worst_param = None
            worst_value = None
            
            for param, values in params.items():
                for value in values:
                    # Heuristic: If value is purely alphanumeric, it's likely safe
                    # unless it contains SQL keywords (which we can check simply)
                    if value.isalnum():
                        continue

                    # Predict on the value
                    features = self.feature_extractor.extract_features(value)
                    features = features.reshape(1, -1)
                    
                    if self.scaler:
                        features = self.scaler.transform(features)
                    
                    prob_injection = float(self.model.predict_proba(features)[0][1])
                    
                    if prob_injection > max_injection_prob:
                        max_injection_prob = prob_injection
                        worst_param = param
                        worst_value = value
            
            # Determine result based on worst parameter
            is_injection = max_injection_prob > 0.5
            
            return {
                'is_sql_injection': is_injection,
                'confidence': max_injection_prob if is_injection else (1 - max_injection_prob),
                'probability_safe': 1 - max_injection_prob,
                'probability_injection': max_injection_prob,
                'query': query,
                'vulnerable_parameter': worst_param,
                'suspicious_value': worst_value
            }

        # Fallback: Treat as raw SQL query (legacy behavior)
        features = self.feature_extractor.extract_features(query)
        features = features.reshape(1, -1)
        
        # Scale features if scaler is available
        if self.scaler:
            features = self.scaler.transform(features)
        
        # Predict
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        
        # Get confidence (probability of predicted class)
        confidence = float(probabilities[prediction])
        
        result = {
            'is_sql_injection': bool(prediction == 1),
            'confidence': confidence,
            'probability_safe': float(probabilities[0]),
            'probability_injection': float(probabilities[1]),
            'query': query
        }
        
        return result
    
    def predict_batch(self, queries: list) -> list:
        """
        Predict for multiple queries.
        
        Args:
            queries: List of SQL query strings
            
        Returns:
            List of prediction dictionaries
        """
        results = []
        for query in queries:
            results.append(self.predict(query))
        return results


def main():
    """CLI interface for predictions."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Predict SQL Injection')
    parser.add_argument('query', type=str, help='SQL query to check')
    parser.add_argument('--model-dir', type=str, default='models', help='Model directory')
    
    args = parser.parse_args()
    
    predictor = SQLInjectionPredictor(model_dir=args.model_dir)
    result = predictor.predict(args.query)
    
    print(f"\nQuery: {result['query']}")
    print(f"Is SQL Injection: {result['is_sql_injection']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Probability (Safe): {result['probability_safe']:.4f}")
    print(f"Probability (Injection): {result['probability_injection']:.4f}")


if __name__ == '__main__':
    main()

