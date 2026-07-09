"""
Database initialization script.
Supports SQLite, PostgreSQL, and MySQL.
"""

import os
import sqlite3
from pathlib import Path
from typing import Optional


def init_sqlite_db(db_path: str = 'database/sql_injection_detector.db'):
    """Initialize SQLite database."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Read and execute schema
    schema_path = Path(__file__).parent / 'schema.sql'
    with open(schema_path, 'r') as f:
        schema = f.read()
    
    # SQLite doesn't support SERIAL, use INTEGER PRIMARY KEY AUTOINCREMENT
    schema = schema.replace('SERIAL PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT')
    schema = schema.replace('SERIAL', 'INTEGER')
    schema = schema.replace('DECIMAL(5, 4)', 'REAL')
    schema = schema.replace('TIMESTAMP DEFAULT CURRENT_TIMESTAMP', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    schema = schema.replace('DATE', 'TEXT')
    # Handle UNIQUE constraint properly
    schema = schema.replace('NOT NULL UNIQUE', 'NOT NULL')
    schema = schema.replace('UNIQUE', '')
    schema = schema.replace('BOOLEAN', 'INTEGER')  # SQLite uses INTEGER for booleans
    schema = schema.replace('VARCHAR(45)', 'TEXT')
    schema = schema.replace('VARCHAR(100)', 'TEXT')
    schema = schema.replace('VARCHAR(255)', 'TEXT')
    schema = schema.replace('VARCHAR(20)', 'TEXT')
    schema = schema.replace('VARCHAR(50)', 'TEXT')
    
    # Remove inline INDEX definitions (SQLite doesn't support them in CREATE TABLE)
    import re
    # Remove INDEX lines that are inside CREATE TABLE statements
    schema = re.sub(r',\s*INDEX\s+\w+\s*\([^)]+\)', '', schema, flags=re.IGNORECASE | re.MULTILINE)
    
    # Remove CHECK constraints (SQLite has limited support)
    schema = re.sub(r',\s*CHECK\s*\([^)]+\)', '', schema, flags=re.IGNORECASE | re.MULTILINE)
    
    # Remove FOREIGN KEY constraints (SQLite needs them defined differently)
    # We'll create the table without FK first, then add it if needed
    schema = re.sub(r',\s*FOREIGN\s+KEY\s+\([^)]+\)\s+REFERENCES\s+[^,)]+[^)]*\)', '', schema, flags=re.IGNORECASE | re.MULTILINE)
    
    # Execute statements - process each CREATE TABLE separately
    statements = []
    current_statement = []
    
    for line in schema.split('\n'):
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith('--'):
            continue
        
        # Add line to current statement
        current_statement.append(line)
        
        # If line ends with semicolon, we have a complete statement
        if line.endswith(';'):
            statement = ' '.join(current_statement)
            statement = statement.rstrip(';').strip()
            if statement.upper().startswith('CREATE TABLE'):
                statements.append(statement)
            current_statement = []
    
    # Execute CREATE TABLE statements
    for statement in statements:
        try:
            cursor.execute(statement)
        except sqlite3.OperationalError as e:
            if 'already exists' not in str(e).lower():
                print(f"Warning creating table: {e}")
    
    # Manually create feedback_logs table (has complex constraints)
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feedback_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_log_id INTEGER,
                actual_label INTEGER NOT NULL,
                predicted_label INTEGER NOT NULL,
                feedback_type TEXT,
                user_feedback TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    except sqlite3.OperationalError as e:
        if 'already exists' not in str(e).lower():
            print(f"Warning creating feedback_logs: {e}")
    
    # Create indexes separately for SQLite
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_is_sql_injection ON query_logs(is_sql_injection)",
        "CREATE INDEX IF NOT EXISTS idx_created_at ON query_logs(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_ip_address ON query_logs(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_model_name ON model_metrics(model_name)",
        "CREATE INDEX IF NOT EXISTS idx_training_date ON model_metrics(training_date)",
        "CREATE INDEX IF NOT EXISTS idx_feedback_type ON feedback_logs(feedback_type)",
        "CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback_logs(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_requests(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_blocked_at ON blocked_requests(blocked_at)",
        "CREATE INDEX IF NOT EXISTS idx_date ON daily_statistics(date)",
        "CREATE INDEX IF NOT EXISTS idx_username ON users(username)",
    ]
    
    for index_sql in indexes:
        try:
            cursor.execute(index_sql)
        except sqlite3.OperationalError as e:
            if 'no such table' not in str(e).lower():
                print(f"Warning creating index: {e}")
    
    conn.commit()
    conn.close()
    print(f"SQLite database initialized at {db_path}")


def init_postgresql_db(connection_string: str):
    """Initialize PostgreSQL database."""
    try:
        import psycopg2
        from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
        
        conn = psycopg2.connect(connection_string)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        schema_path = Path(__file__).parent / 'schema.sql'
        with open(schema_path, 'r') as f:
            schema = f.read()
        
        # Execute statements
        statements = [s.strip() for s in schema.split(';') if s.strip()]
        
        for statement in statements:
            try:
                cursor.execute(statement)
            except Exception as e:
                if 'already exists' not in str(e).lower():
                    print(f"Warning: {e}")
        
        conn.close()
        print("PostgreSQL database initialized successfully")
    except ImportError:
        print("psycopg2 not installed. Install with: pip install psycopg2-binary")
    except Exception as e:
        print(f"Error initializing PostgreSQL: {e}")


def init_mysql_db(connection_string: str):
    """Initialize MySQL database."""
    try:
        import pymysql
        
        conn = pymysql.connect(connection_string)
        cursor = conn.cursor()
        
        schema_path = Path(__file__).parent / 'schema.sql'
        with open(schema_path, 'r') as f:
            schema = f.read()
        
        # MySQL adjustments
        schema = schema.replace('SERIAL PRIMARY KEY', 'INT AUTO_INCREMENT PRIMARY KEY')
        schema = schema.replace('SERIAL', 'INT AUTO_INCREMENT')
        
        statements = [s.strip() for s in schema.split(';') if s.strip()]
        
        for statement in statements:
            try:
                cursor.execute(statement)
            except Exception as e:
                if 'already exists' not in str(e).lower():
                    print(f"Warning: {e}")
        
        conn.commit()
        conn.close()
        print("MySQL database initialized successfully")
    except ImportError:
        print("pymysql not installed. Install with: pip install pymysql")
    except Exception as e:
        print(f"Error initializing MySQL: {e}")


def main():
    """Main initialization function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Initialize Database')
    parser.add_argument('--type', type=str, choices=['sqlite', 'postgresql', 'mysql'], 
                       default='sqlite', help='Database type')
    parser.add_argument('--path', type=str, default='database/sql_injection_detector.db',
                       help='SQLite database path')
    parser.add_argument('--connection', type=str, help='PostgreSQL/MySQL connection string')
    
    args = parser.parse_args()
    
    if args.type == 'sqlite':
        init_sqlite_db(args.path)
    elif args.type == 'postgresql':
        if not args.connection:
            print("PostgreSQL requires --connection argument")
            return
        init_postgresql_db(args.connection)
    elif args.type == 'mysql':
        if not args.connection:
            print("MySQL requires --connection argument")
            return
        init_mysql_db(args.connection)


if __name__ == '__main__':
    main()

