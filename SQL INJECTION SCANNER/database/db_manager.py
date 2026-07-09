"""
Database manager for SQL injection detector.
Handles database operations.
"""

import sqlite3
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime, date
from contextlib import contextmanager


class DatabaseManager:
    """Manages database operations for the SQL injection detector."""
    
    def __init__(self, db_path: str = 'database/sql_injection_detector.db', db_type: str = 'sqlite'):
        self.db_path = db_path
        self.db_type = db_type
        self.connection_string = None
        
        if db_type == 'sqlite':
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager."""
        if self.db_type == 'sqlite':
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        else:
            # For PostgreSQL/MySQL, would use appropriate libraries
            raise NotImplementedError(f"Database type {self.db_type} not fully implemented")
    
    def log_query(self, query: str, prediction_result: Dict[str, Any], 
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                  endpoint: Optional[str] = None) -> int:
        """Log a query and its prediction result."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO query_logs 
                (query, is_sql_injection, confidence, probability_safe, probability_injection,
                 ip_address, user_agent, endpoint, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                query,
                prediction_result['is_sql_injection'],
                prediction_result['confidence'],
                prediction_result['probability_safe'],
                prediction_result['probability_injection'],
                ip_address,
                user_agent,
                endpoint,
                datetime.now()
            ))
            return cursor.lastrowid
    
    def add_feedback(self, query_log_id: int, actual_label: bool, 
                    predicted_label: bool, feedback_type: str, 
                    user_feedback: Optional[str] = None) -> int:
        """Add feedback for a prediction (false positive/negative)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO feedback_logs 
                (query_log_id, actual_label, predicted_label, feedback_type, user_feedback, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                query_log_id,
                actual_label,
                predicted_label,
                feedback_type,
                user_feedback,
                datetime.now()
            ))
            return cursor.lastrowid
    
    def block_request(self, query: str, ip_address: Optional[str] = None,
                     user_agent: Optional[str] = None, endpoint: Optional[str] = None,
                     reason: Optional[str] = None) -> int:
        """Log a blocked request."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO blocked_requests 
                (query, ip_address, user_agent, endpoint, blocked_at, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                query,
                ip_address,
                user_agent,
                endpoint,
                datetime.now(),
                reason
            ))
            return cursor.lastrowid
    
    def get_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get statistics for the last N days."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Total queries
            cursor.execute("""
                SELECT COUNT(*) as total, 
                       SUM(CASE WHEN is_sql_injection = 1 THEN 1 ELSE 0 END) as injections
                FROM query_logs
                WHERE created_at >= datetime('now', '-' || ? || ' days')
            """, (days,))
            stats = cursor.fetchone()
            
            # False positives/negatives
            cursor.execute("""
                SELECT 
                    SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as false_positives,
                    SUM(CASE WHEN feedback_type = 'false_negative' THEN 1 ELSE 0 END) as false_negatives
                FROM feedback_logs
                WHERE created_at >= datetime('now', '-' || ? || ' days')
            """, (days,))
            feedback_stats = cursor.fetchone()
            
            return {
                'total_queries': stats['total'] or 0,
                'sql_injections_detected': stats['injections'] or 0,
                'false_positives': feedback_stats['false_positives'] or 0,
                'false_negatives': feedback_stats['false_negatives'] or 0,
                'days': days
            }
    
    def get_recent_logs(self, limit: int = 100, is_injection: Optional[bool] = None) -> List[Dict]:
        """Get recent query logs."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if is_injection is not None:
                cursor.execute("""
                    SELECT * FROM query_logs
                    WHERE is_sql_injection = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (is_injection, limit))
            else:
                cursor.execute("""
                    SELECT * FROM query_logs
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (limit,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def save_model_metrics(self, model_name: str, accuracy: float, precision: float,
                          recall: float, f1_score: float, model_version: Optional[str] = None):
        """Save model performance metrics."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO model_metrics 
                (model_name, accuracy, precision, recall, f1_score, training_date, model_version)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                model_name,
                accuracy,
                precision,
                recall,
                f1_score,
                datetime.now(),
                model_version
            ))

    def create_user(self, username: str, password_hash: str) -> int:
        """Create a new user."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (username, password_hash, created_at)
                    VALUES (?, ?, ?)
                """, (username, password_hash, datetime.now()))
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                raise ValueError(f"Username '{username}' already exists")

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

