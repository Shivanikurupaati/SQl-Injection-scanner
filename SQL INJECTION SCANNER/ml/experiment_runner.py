"""
Experiment runner for SQLInjectionModelTrainer.
Runs multiple experiments with different random seeds and reports accuracy variability.
"""
import os
import random
import numpy as np
import pandas as pd
from pathlib import Path

from ml.feature_extractor import SQLFeatureExtractor

def set_seeds(seed: int):
    os.environ['PYTHONHASHSEED'] = str(seed)
    random.seed(seed)
    np.random.seed(seed)


class SimpleTrainer:
    """Lightweight trainer that mirrors main training flow but allows seed control."""
    def __init__(self, model_dir='models'):
        self.model_dir = Path(model_dir)
        self.feature_extractor = SQLFeatureExtractor()
        self.scaler = None

    def prepare_features(self, df):
        X = np.array([self.feature_extractor.extract_features(q) for q in df['query']])
        y = df['label'].values
        return X, y

    def generate_synthetic(self, n_samples=10000):
        # Reuse code pattern from train_model but keep it simple and deterministic under seed
        # We'll create simple safe/injection lists and sample with numpy
        safe = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT name FROM customers WHERE id = 2",
            "SELECT COUNT(*) FROM transactions",
            "SELECT * FROM products WHERE category = 'electronics'",
        ]
        inj = [
            "admin' OR '1'='1' --",
            "' OR 1=1 --",
            "' UNION SELECT NULL, NULL --",
            "'; DROP TABLE users --",
            "'; SELECT SLEEP(5) --",
        ]

        queries = []
        labels = []
        half = n_samples // 2
        for _ in range(half):
            q = np.random.choice(safe)
            if np.random.rand() > 0.5:
                q = q.replace('1', str(np.random.randint(1, 100)))
            queries.append(q)
            labels.append(0)

        for _ in range(n_samples - half):
            q = np.random.choice(inj)
            if np.random.rand() > 0.3:
                queries.append(q)
            else:
                queries.append(np.random.choice(safe) + ' ' + q)
            labels.append(1)

        indices = np.random.permutation(len(queries))
        queries = [queries[i] for i in indices]
        labels = [labels[i] for i in indices]
        return pd.DataFrame({'query': queries, 'label': labels})


def run_once(seed: int, n_samples=10000, test_size=0.2):
    set_seeds(seed)
    trainer = SimpleTrainer()
    df = trainer.generate_synthetic(n_samples=n_samples)
    X, y = trainer.prepare_features(df)

    # Split with seed
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=seed, stratify=y)

    # Scale
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Create models with seed-aware randomness
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import SVC
    import xgboost as xgb

    models = {
        'RandomForest': RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=-1),
        'XGBoost': xgb.XGBClassifier(n_estimators=200, random_state=seed, use_label_encoder=False, eval_metric='logloss'),
        'GradientBoosting': GradientBoostingClassifier(n_estimators=200, random_state=seed),
        'LogisticRegression': LogisticRegression(max_iter=1000, random_state=seed),
        'SVM': SVC(kernel='rbf', probability=True, random_state=seed)
    }

    results = {}
    for name, model in models.items():
        # Fit
        try:
            if name in ('LogisticRegression', 'SVM'):
                model.fit(X_train_scaled, y_train)
                y_pred = model.predict(X_test_scaled)
            else:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)

            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            results[name] = {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1}
        except Exception as e:
            results[name] = {'error': str(e)}

    return results


def run_experiments(seeds=(0,1,2,3,4), n_samples=10000):
    all_results = { 'seeds': seeds, 'per_seed': {} }
    for seed in seeds:
        print(f"Running seed={seed} ...")
        res = run_once(seed, n_samples=n_samples)
        all_results['per_seed'][seed] = res

    # Summarize per-model
    import statistics
    summary = {}
    model_names = list(next(iter(all_results['per_seed'].values())).keys())
    for model in model_names:
        vals = []
        for seed in seeds:
            r = all_results['per_seed'][seed].get(model, {})
            if 'accuracy' in r:
                vals.append(r['accuracy'])
        if vals:
            summary[model] = {'mean_accuracy': statistics.mean(vals), 'stdev_accuracy': statistics.stdev(vals) if len(vals)>1 else 0.0}
        else:
            summary[model] = {'mean_accuracy': None, 'stdev_accuracy': None}

    print('\nExperiment Summary:')
    for model, s in summary.items():
        print(f"{model}: mean_acc={s['mean_accuracy']}, stdev_acc={s['stdev_accuracy']}")

    return all_results, summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run training experiments with multiple seeds')
    parser.add_argument('--seeds', type=str, default='0,1,2,3,4', help='Comma separated seeds')
    parser.add_argument('--samples', type=int, default=10000, help='Number of synthetic samples')
    args = parser.parse_args()
    seeds = [int(x) for x in args.seeds.split(',') if x.strip()!='']
    run_experiments(seeds=seeds, n_samples=args.samples)
