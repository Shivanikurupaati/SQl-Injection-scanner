"""
ML package for SQL Injection Detection.
"""

# Lazy imports to avoid circular import issues
__all__ = ['SQLFeatureExtractor', 'SQLInjectionPredictor']

def __getattr__(name):
    if name == 'SQLFeatureExtractor':
        from .feature_extractor import SQLFeatureExtractor
        return SQLFeatureExtractor
    elif name == 'SQLInjectionPredictor':
        from .predict import SQLInjectionPredictor
        return SQLInjectionPredictor
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

