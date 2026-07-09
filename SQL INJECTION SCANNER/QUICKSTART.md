# Quick Start Guide

Get your SQL Injection Detector up and running in minutes!

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 2: Initialize Database

```bash
python database/init_db.py
```

This creates a SQLite database at `database/sql_injection_detector.db`

## Step 3: Train the Model

### Option A: Use Synthetic Dataset (Quick Start)
```bash
python ml/train_model.py
```

This will:
- Generate 10,000 synthetic samples
- Train multiple ML models
- Select the best model
- Save to `models/` directory

### Option B: Use Kaggle Dataset
```bash
# First, set up Kaggle API (see KAGGLE_DATASETS.md)
python ml/train_model.py --kaggle username/dataset-name
```

### Option C: Use Local Dataset
```bash
python ml/train_model.py --dataset path/to/your/dataset.csv
```

**Training takes 2-5 minutes** depending on your system.

## Step 4: Start the Backend Server

```bash
python backend/main.py
```

Or:
```bash
uvicorn backend.main:app --reload
```

The API will be available at `http://localhost:8000`

## Step 5: Test the API

### Using the Test Script
```bash
python test_api.py
```

### Using curl
```bash
# Detect SQL injection
curl -X POST "http://localhost:8000/api/v1/detect" \
  -H "Content-Type: application/json" \
  -d '{"query": "admin'\'' OR '\''1'\''='\''1"}'

# Get statistics
curl "http://localhost:8000/api/v1/statistics"
```

### Using Python
```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/detect",
    json={"query": "admin' OR '1'='1"}
)
print(response.json())
```

## Step 6: View API Documentation

Open your browser and visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Troubleshooting

### "Model not found" Error
- Make sure you've trained the model first (Step 3)
- Check that `models/sql_injection_model.pkl` exists

### Database Errors
- Run `python database/init_db.py` again
- Check file permissions on the database file

### Import Errors
- Make sure all dependencies are installed: `pip install -r requirements.txt`
- Check Python version (requires Python 3.8+)

### Port Already in Use
- Change the port: `export PORT=8001`
- Or kill the process using port 8000

## Next Steps

1. **Integrate with your application**: Use the API endpoints in your web application
2. **Monitor performance**: Check statistics endpoint regularly
3. **Improve model**: Submit feedback on false positives/negatives
4. **Retrain**: Periodically retrain with new data

## Example Integration

```python
import requests

def check_sql_injection(query):
    """Check if a query is SQL injection."""
    response = requests.post(
        "http://localhost:8000/api/v1/detect",
        json={"query": query, "log_to_db": True}
    )
    result = response.json()
    
    if result['is_sql_injection']:
        print(f"⚠️ SQL Injection detected! Confidence: {result['confidence']:.2%}")
        return True
    return False

# Usage
check_sql_injection("admin' OR '1'='1")
```

## Production Deployment

For production:
1. Use PostgreSQL or MySQL instead of SQLite
2. Configure CORS properly in `backend/main.py`
3. Add authentication/authorization
4. Use environment variables for sensitive config
5. Set up logging and monitoring
6. Use a production ASGI server (Gunicorn with Uvicorn workers)

