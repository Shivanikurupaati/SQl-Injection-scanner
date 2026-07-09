"""
Training script for SQL Injection Detection Model.
Supports downloading datasets from Kaggle and training multiple ML models.
"""

import os
import pandas as pd
import numpy as np
import pickle
import json
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, classification_report, confusion_matrix
)
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
import sys
import os

# Handle imports for both package and direct execution
try:
    from .feature_extractor import SQLFeatureExtractor
except ImportError:
    try:
        from ml.feature_extractor import SQLFeatureExtractor
    except ImportError:
        # If both fail, add current directory to path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from feature_extractor import SQLFeatureExtractor

import warnings
warnings.filterwarnings('ignore')


class SQLInjectionModelTrainer:
    """Trainer class for SQL injection detection models."""
    
    def __init__(self, model_dir='models'):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.feature_extractor = SQLFeatureExtractor()
        self.scaler = StandardScaler()
        self.models = {}
        self.best_model = None
        self.best_model_name = None
        
    def load_kaggle_dataset(self, dataset_path=None, kaggle_dataset=None):
        """
        Load dataset from Kaggle or local file.
        
        Args:
            dataset_path: Path to local CSV file
            kaggle_dataset: Kaggle dataset name (e.g., 'username/dataset-name')
            
        Returns:
            DataFrame with 'query' and 'label' columns
        """
        if kaggle_dataset:
            try:
                import kaggle
                print(f"Downloading dataset from Kaggle: {kaggle_dataset}")
                # Download dataset
                kaggle.api.dataset_download_files(kaggle_dataset, path='data', unzip=True)
                # Find CSV files
                csv_files = list(Path('data').glob('*.csv'))
                if csv_files:
                    dataset_path = str(csv_files[0])
                    print(f"Found dataset file: {dataset_path}")
            except ImportError:
                print("Kaggle API not installed. Install with: pip install kaggle")
                print("Or provide a local dataset path.")
                return None
            except Exception as e:
                print(f"Error downloading from Kaggle: {e}")
                print("Falling back to generating synthetic dataset...")
                return self.generate_synthetic_dataset()
        
        if dataset_path and os.path.exists(dataset_path):
            print(f"Loading dataset from: {dataset_path}")
            df = pd.read_csv(dataset_path)
            
            # Handle different column name variations
            query_cols = ['query', 'Query', 'sql', 'SQL', 'payload', 'Payload', 'text', 'Text', 'input', 'Input']
            label_cols = ['label', 'Label', 'is_sql_injection', 'is_sqli', 'target', 'Target', 'class', 'Class']
            
            query_col = next((col for col in query_cols if col in df.columns), None)
            label_col = next((col for col in label_cols if col in df.columns), None)
            
            if query_col and label_col:
                df = df[[query_col, label_col]].copy()
                df.columns = ['query', 'label']
                # Normalize labels to 0/1
                df['label'] = df['label'].map({0: 0, 1: 1, '0': 0, '1': 1, 
                                               'safe': 0, 'unsafe': 1, 
                                               'normal': 0, 'sql_injection': 1,
                                               False: 0, True: 1})
                return df
            else:
                print(f"Warning: Could not find expected columns. Available: {df.columns.tolist()}")
                return None
        else:
            print("No dataset path provided. Generating synthetic dataset...")
            return self.generate_synthetic_dataset()
    
    def generate_synthetic_dataset(self, n_samples=10000):
        """
        Generate synthetic dataset with SQL injection and safe queries.
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            DataFrame with synthetic data
        """
        print("Generating synthetic dataset...")
        
        # Safe SQL queries
        safe_queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT name, email FROM customers",
            "INSERT INTO products (name, price) VALUES ('Product', 10.99)",
            "UPDATE users SET email = 'new@email.com' WHERE id = 5",
            "DELETE FROM orders WHERE status = 'cancelled'",
            "SELECT COUNT(*) FROM transactions",
            "SELECT * FROM users ORDER BY name ASC",
            "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
            "SELECT * FROM products WHERE category = 'electronics'",
            "SELECT AVG(price) FROM products",
        ]
        
        # SQL injection payloads (complex examples)
        injection_queries = [
            # Classic injection
            "admin' OR '1'='1",
            "admin' OR '1'='1' --",
            "admin' OR '1'='1' /*",
            "' OR 1=1 --",
            "' OR 'a'='a",
            "' OR 1=1#",
            
            # Union-based
            "' UNION SELECT NULL, NULL, NULL --",
            "' UNION SELECT username, password FROM users --",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
            "1' UNION SELECT NULL, version() --",
            
            # Boolean-based blind
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1' AND SUBSTRING(@@version,1,1)='5' --",
            
            # Time-based
            "'; WAITFOR DELAY '00:00:05' --",
            "'; SELECT SLEEP(5) --",
            "'; BENCHMARK(5000000,MD5(1)) --",
            "1'; SELECT pg_sleep(5) --",
            
            # Error-based
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
            "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT version()), 0x7e), 1) --",
            "' AND (SELECT * FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
            
            # Stacked queries
            "'; DROP TABLE users --",
            "'; DELETE FROM users WHERE '1'='1' --",
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'pass') --",
            
            # Second-order
            "admin' UNION SELECT '<?php eval($_POST[cmd]); ?>' INTO OUTFILE '/var/www/shell.php' --",
            
            # Encoded/obfuscated
            "%27%20OR%20%271%27%3D%271",
            "CHAR(39) OR CHAR(49)=CHAR(49)",
            "0x27204F52202731273D2731",
            "CONCAT(CHAR(39), ' OR ', CHAR(39), '1', CHAR(39), '=', CHAR(39), '1')",
            
            # Information schema
            "' UNION SELECT table_name FROM information_schema.tables --",
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --",
            
            # NoSQL injection
            "'; return true; var x = '",
            "$where: function() { return true; }",
            
            # Advanced patterns
            "' OR IF(1=1, SLEEP(5), 0) --",
            "' OR CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END --",
            "1' AND IF(ASCII(SUBSTRING(@@version,1,1))>53, SLEEP(5), 0) --",
        ]
        
        # Generate dataset
        queries = []
        labels = []
        
        # Add safe queries
        for _ in range(n_samples // 2):
            base_query = np.random.choice(safe_queries)
            # Add some variation
            if np.random.random() > 0.5:
                queries.append(base_query)
            else:
                # Add safe variations
                queries.append(base_query.replace('1', str(np.random.randint(1, 100))))
            labels.append(0)
        
        # Add injection queries
        for _ in range(n_samples // 2):
            base_query = np.random.choice(injection_queries)
            # Add variations
            if np.random.random() > 0.3:
                queries.append(base_query)
            else:
                # Combine with safe queries
                safe = np.random.choice(safe_queries)
                queries.append(f"{safe} {base_query}")
            labels.append(1)
        
        # Shuffle
        indices = np.random.permutation(len(queries))
        queries = [queries[i] for i in indices]
        labels = [labels[i] for i in indices]
        
        df = pd.DataFrame({'query': queries, 'label': labels})
        print(f"Generated {len(df)} samples ({df['label'].sum()} injections, {len(df) - df['label'].sum()} safe)")
        return df
    
    def prepare_features(self, df):
        """Extract features from queries."""
        print("Extracting features...")
        X = np.array([self.feature_extractor.extract_features(query) for query in df['query']])
        y = df['label'].values
        return X, y
    
    def train_models(self, X_train, y_train):
        """Train multiple ML models."""
        print("\nTraining models...")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        models_to_train = {
            'RandomForest': RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=200,
                max_depth=10,
                learning_rate=0.1,
                random_state=42,
                eval_metric='logloss'
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=200,
                max_depth=10,
                learning_rate=0.1,
                random_state=42
            ),
            'LogisticRegression': LogisticRegression(
                max_iter=1000,
                random_state=42,
                n_jobs=-1
            ),
            'SVM': SVC(
                kernel='rbf',
                probability=True,
                random_state=42
            )
        }
        
        for name, model in models_to_train.items():
            print(f"Training {name}...")
            if name == 'LogisticRegression' or name == 'SVM':
                model.fit(X_train_scaled, y_train)
            else:
                model.fit(X_train, y_train)
            self.models[name] = model
        
        print("All models trained successfully!")
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate all trained models."""
        print("\nEvaluating models...")
        X_test_scaled = self.scaler.transform(X_test)
        
        results = {}
        
        for name, model in self.models.items():
            if name == 'LogisticRegression' or name == 'SVM':
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            else:
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            }
            
            print(f"\n{name} Results:")
            print(f"  Accuracy:  {accuracy:.4f}")
            print(f"  Precision: {precision:.4f}")
            print(f"  Recall:    {recall:.4f}")
            print(f"  F1-Score:  {f1:.4f}")
        
        # Select best model based on F1 score
        best_model_name = max(results, key=lambda x: results[x]['f1'])
        self.best_model = self.models[best_model_name]
        self.best_model_name = best_model_name
        
        print(f"\n{'='*50}")
        print(f"Best Model: {best_model_name}")
        print(f"F1-Score: {results[best_model_name]['f1']:.4f}")
        print(f"{'='*50}")
        
        return results
    
    def save_model(self):
        """Save the best model and scaler."""
        if self.best_model is None:
            print("No model to save!")
            return
        
        model_path = self.model_dir / 'sql_injection_model.pkl'
        scaler_path = self.model_dir / 'scaler.pkl'
        feature_extractor_path = self.model_dir / 'feature_extractor.pkl'
        
        # Save model
        with open(model_path, 'wb') as f:
            pickle.dump(self.best_model, f)
        print(f"Model saved to {model_path}")
        
        # Save scaler
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        print(f"Scaler saved to {scaler_path}")
        
        # Save feature extractor
        with open(feature_extractor_path, 'wb') as f:
            pickle.dump(self.feature_extractor, f)
        print(f"Feature extractor saved to {feature_extractor_path}")
        
        # Save model info
        info = {
            'model_name': self.best_model_name,
            'feature_count': len(self.feature_extractor.extract_features("test")),
            'feature_names': self.feature_extractor.get_feature_names()
        }
        
        with open(self.model_dir / 'model_info.json', 'w') as f:
            json.dump(info, f, indent=2)
        print(f"Model info saved to {self.model_dir / 'model_info.json'}")
    
    def train(self, dataset_path=None, kaggle_dataset=None, test_size=0.2):
        """Main training pipeline."""
        # Load dataset
        df = self.load_kaggle_dataset(dataset_path, kaggle_dataset)
        if df is None or len(df) == 0:
            print("Failed to load dataset!")
            return
        
        # Prepare features
        X, y = self.prepare_features(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"\nDataset split:")
        print(f"  Training: {len(X_train)} samples")
        print(f"  Testing:  {len(X_test)} samples")
        
        # Train models
        self.train_models(X_train, y_train)
        
        # Evaluate models
        results = self.evaluate_models(X_test, y_test)
        
        # Save best model
        self.save_model()
        
        return results


def main():
    """Main function to run training."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train SQL Injection Detection Model')
    parser.add_argument('--dataset', type=str, help='Path to local dataset CSV file')
    parser.add_argument('--kaggle', type=str, help='Kaggle dataset name (e.g., username/dataset-name)')
    parser.add_argument('--test-size', type=float, default=0.2, help='Test set size ratio')
    
    args = parser.parse_args()
    
    trainer = SQLInjectionModelTrainer()
    trainer.train(
        dataset_path=args.dataset,
        kaggle_dataset=args.kaggle,
        test_size=args.test_size
    )


if __name__ == '__main__':
    main()

