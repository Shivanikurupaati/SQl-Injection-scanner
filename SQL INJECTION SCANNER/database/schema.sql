-- SQL Injection Detector Database Schema
-- Supports PostgreSQL, MySQL, and SQLite

-- Table for storing users
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for storing query logs and predictions
CREATE TABLE IF NOT EXISTS query_logs (
    id SERIAL PRIMARY KEY,
    query TEXT NOT NULL,
    is_sql_injection BOOLEAN NOT NULL,
    confidence DECIMAL(5, 4) NOT NULL,
    probability_safe DECIMAL(5, 4) NOT NULL,
    probability_injection DECIMAL(5, 4) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    endpoint VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_is_sql_injection (is_sql_injection),
    INDEX idx_created_at (created_at),
    INDEX idx_ip_address (ip_address)
);

-- Table for storing model performance metrics
CREATE TABLE IF NOT EXISTS model_metrics (
    id SERIAL PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    accuracy DECIMAL(5, 4),
    precision DECIMAL(5, 4),
    recall DECIMAL(5, 4),
    f1_score DECIMAL(5, 4),
    training_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50),
    INDEX idx_model_name (model_name),
    INDEX idx_training_date (training_date)
);

-- Table for storing false positives/negatives for model improvement
CREATE TABLE IF NOT EXISTS feedback_logs (
    id SERIAL PRIMARY KEY,
    query_log_id INTEGER,
    actual_label BOOLEAN NOT NULL,
    predicted_label BOOLEAN NOT NULL,
    feedback_type VARCHAR(20) CHECK (feedback_type IN ('false_positive', 'false_negative', 'correct')),
    user_feedback TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (query_log_id) REFERENCES query_logs(id) ON DELETE CASCADE,
    INDEX idx_feedback_type (feedback_type),
    INDEX idx_created_at (created_at)
);

-- Table for storing blocked requests (if implementing blocking)
CREATE TABLE IF NOT EXISTS blocked_requests (
    id SERIAL PRIMARY KEY,
    query TEXT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    endpoint VARCHAR(255),
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,
    INDEX idx_ip_address (ip_address),
    INDEX idx_blocked_at (blocked_at)
);

-- Table for storing statistics
CREATE TABLE IF NOT EXISTS daily_statistics (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    total_queries INTEGER DEFAULT 0,
    sql_injections_detected INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_date (date)
);

