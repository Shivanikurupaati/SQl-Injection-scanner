"""
Setup script for SQL Injection Detector.
"""

from setuptools import setup, find_packages

setup(
    name="sql-injection-detector",
    version="1.0.0",
    description="Machine Learning-based SQL Injection Detection System",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "scikit-learn>=1.3.0",
        "xgboost>=2.0.0",
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "pydantic>=2.0.0",
        "kaggle>=1.5.0",
        "python-dotenv>=1.0.0",
    ],
    python_requires=">=3.8",
)

