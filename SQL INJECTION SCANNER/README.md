# SQL Injection Detector Using Machine Learning

A comprehensive machine learning-based system for detecting SQL injection attacks. This project includes a robust ML model trained on complex SQL injection payloads, a FastAPI backend, and a database for logging and analytics.

## Quick Start Guide

Follow these steps to get the project running from scratch.

### 1. Prerequisites
- Python 3.8 or higher
- Git (optional, for cloning)

### 2. Installation

1.  **Clone the repository** (or download and extract the zip):
    ```bash
    git clone <repository-url>
    cd sql
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

### 3. Database Setup

Initialize the database to create the necessary tables for users and logs.
```bash
python database/init_db.py
```
*This creates `database/sql_injection_detector.db`.*

### 4. Model Training (Recommended)

For the best accuracy, train the model using a Kaggle dataset.

**Option A: Using Kaggle (Best Results)**
1.  Set your Kaggle credentials (if not already set):
    ```powershell
    # Windows PowerShell
    $env:KAGGLE_USERNAME="your_username"
    $env:KAGGLE_KEY="your_key"
    ```
2.  Run the training script:
    ```bash
    python ml/train_model.py --kaggle syedazareth/sql-injection-dataset
    ```

**Option B: Quick Start (Synthetic Data)**
If you don't have Kaggle credentials, just run:
```bash
python ml/train_model.py
```

### 5. Run the Application

1.  **Start the Backend Server**:
    ```bash
    python backend/main.py
    ```
    *The server will start at `http://localhost:8000`.*

2.  **Open the Frontend**:
    - Navigate to the `frontend` folder.
    - Open `index.html` (or `home.html`) in your web browser.

### 6. Using the App

1.  **Sign Up/Login**: Create an account to access the dashboard.
2.  **Scan URLs**: Enter a URL to check if it's safe or vulnerable to SQL injection.
    - **Safe Example**: `https://www.google.com`
    - **Vulnerable Example**: `http://test.com/login.php?user=admin' OR '1'='1`
3.  **View Results**: Check the "Results" page for detailed analysis.

---

## Project Structure

```
sql/
├── ml/                    # Machine Learning components
│   ├── feature_extractor.py    # Feature extraction for SQL queries
│   ├── train_model.py          # Model training script
│   └── predict.py              # Prediction module
├── backend/               # FastAPI backend
│   └── main.py                # API endpoints
├── database/              # Database components
│   ├── schema.sql             # Database schema
│   ├── init_db.py             # Database initialization
│   └── db_manager.py          # Database operations
├── frontend/              # Web Interface
│   ├── index.html             # Landing page
│   ├── home.html              # Dashboard
│   ├── login.html             # Authentication
│   └── ...                    # Styles and scripts
└── requirements.txt       # Python dependencies
```

##  API Documentation

Once the server is running, you can explore the API docs at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

##  Running Tests

To verify everything is working correctly:
```bash
python test_api.py
```

##  Features

- **Advanced ML Model**: Detects complex SQL injection payloads (Classic, Union-based, Blind, etc.)
- **Real-time Detection**: Fast prediction with confidence scores.
- **User Management**: Secure signup and login.
- **History & Analytics**: Track scanned URLs and detection statistics.

