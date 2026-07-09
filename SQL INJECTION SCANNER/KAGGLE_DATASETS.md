# Kaggle Datasets for SQL Injection Detection

This guide helps you find and use Kaggle datasets for training the SQL injection detector.

## Popular SQL Injection Datasets on Kaggle

### 1. SQL Injection Dataset
- **Search for**: "sql injection dataset" or "sqli dataset"
- **Common datasets**:
  - `datasets/sql-injection-dataset` (if available)
  - `datasets/sqli-attack-dataset`
  - `datasets/web-security-sql-injection`

### 2. How to Use a Kaggle Dataset

#### Step 1: Install Kaggle API
```bash
pip install kaggle
```

#### Step 2: Set up Kaggle Credentials
1. Go to https://www.kaggle.com/account
2. Scroll down to "API" section
3. Click "Create New API Token"
4. This downloads `kaggle.json`

#### Step 3: Place kaggle.json
- **Windows**: `C:\Users\<username>\.kaggle\kaggle.json`
- **Linux/Mac**: `~/.kaggle/kaggle.json`

#### Step 4: Set Permissions (Linux/Mac)
```bash
chmod 600 ~/.kaggle/kaggle.json
```

#### Step 5: Download and Train
```bash
# Find a dataset on Kaggle, then use:
python ml/train_model.py --kaggle username/dataset-name

# Example:
python ml/train_model.py --kaggle johnsmith/sql-injection-dataset
```

## Creating Your Own Dataset

If you can't find a suitable Kaggle dataset, the training script will automatically generate a synthetic dataset with:
- 10,000+ samples
- Mix of safe SQL queries
- Complex SQL injection payloads
- Various injection techniques

## Dataset Format

Your dataset CSV should have:
- **Query column**: Named `query`, `Query`, `sql`, `SQL`, `payload`, or `text`
- **Label column**: Named `label`, `Label`, `is_sql_injection`, `is_sqli`, or `target`
- **Label values**: 
  - `0` or `False` or `'safe'` for safe queries
  - `1` or `True` or `'sql_injection'` for malicious queries

Example CSV:
```csv
query,label
"SELECT * FROM users",0
"admin' OR '1'='1",1
"INSERT INTO products VALUES (...)",0
"' UNION SELECT NULL --",1
```

## Alternative Data Sources

1. **OWASP**: Open Web Application Security Project has SQL injection examples
2. **GitHub**: Search for "sql injection dataset" repositories
3. **Security Research Papers**: Many papers include datasets
4. **Web Application Firewall Logs**: Real-world attack logs

## Tips

- Look for datasets with at least 1,000+ samples
- Prefer datasets with balanced classes (50/50 safe vs injection)
- Datasets with diverse injection techniques work best
- Consider combining multiple datasets for better coverage

