"""
FastAPI backend for SQL Injection Detector.
Provides REST API endpoints for detection and monitoring.
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import hashlib
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from ml.predict import SQLInjectionPredictor
from database.db_manager import DatabaseManager
import os

app = FastAPI(
    title="SQL Injection Detector API",
    description="Machine Learning-based SQL Injection Detection System",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
predictor = None
db_manager = None


def get_predictor():
    """Get or initialize predictor."""
    global predictor
    if predictor is None:
        model_dir = os.getenv('MODEL_DIR', 'models')
        try:
            predictor = SQLInjectionPredictor(model_dir=model_dir)
        except FileNotFoundError as e:
            raise HTTPException(
                status_code=503,
                detail=f"Model not found. Please train the model first. Error: {str(e)}"
            )
    return predictor


def get_db_manager():
    """Get or initialize database manager."""
    global db_manager
    if db_manager is None:
        db_path = os.getenv('DB_PATH', 'database/sql_injection_detector.db')
        db_type = os.getenv('DB_TYPE', 'sqlite')
        db_manager = DatabaseManager(db_path=db_path, db_type=db_type)
    return db_manager


# Request/Response Models
class QueryRequest(BaseModel):
    query: str = Field(..., description="SQL query to check for injection")
    log_to_db: bool = Field(True, description="Whether to log this query to database")


class QueryResponse(BaseModel):
    is_sql_injection: bool
    confidence: float
    probability_safe: float
    probability_injection: float
    query: str
    log_id: Optional[int] = None
    vulnerable_parameter: Optional[str] = None
    suspicious_value: Optional[str] = None


class BatchQueryRequest(BaseModel):
    queries: List[str] = Field(..., description="List of SQL queries to check")
    log_to_db: bool = Field(True, description="Whether to log queries to database")


class BatchQueryResponse(BaseModel):
    results: List[QueryResponse]
    total_queries: int
    injections_detected: int


class FeedbackRequest(BaseModel):
    query_log_id: int = Field(..., description="ID of the logged query")
    actual_label: bool = Field(..., description="Actual label (True if injection, False if safe)")
    feedback_type: str = Field(..., description="Type: 'false_positive', 'false_negative', or 'correct'")
    user_feedback: Optional[str] = Field(None, description="Additional feedback text")


class StatisticsResponse(BaseModel):
    total_queries: int
    sql_injections_detected: int
    false_positives: int
    false_negatives: int
    days: int


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    token: str
    username: str
    message: str


# API Endpoints
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "SQL Injection Detector API",
        "version": "1.0.0",
        "endpoints": {
            "detect": "/api/v1/detect",
            "batch_detect": "/api/v1/batch-detect",
            "statistics": "/api/v1/statistics",
            "logs": "/api/v1/logs",
            "feedback": "/api/v1/feedback",
            "health": "/api/v1/health",
            "auth": {
                "signup": "/api/v1/auth/signup",
                "login": "/api/v1/auth/login"
            }
        }
    }


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    try:
        predictor = get_predictor()
        db_manager = get_db_manager()
        
        # Test prediction
        test_result = predictor.predict("SELECT * FROM users")
        
        return {
            "status": "healthy",
            "model_loaded": True,
            "database_connected": True,
            "model_type": predictor.model_name or "Unknown"
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )


@app.post("/api/v1/detect", response_model=QueryResponse)
async def detect_sql_injection(
    request: QueryRequest,
    http_request: Request = None
):
    """
    Detect SQL injection in a single query.
    """
    try:
        predictor = get_predictor()
        db_manager = get_db_manager()
        
        # Predict
        result = predictor.predict(request.query)
        
        # Log to database if requested
        log_id = None
        if request.log_to_db:
            ip_address = http_request.client.host if http_request else None
            user_agent = http_request.headers.get('user-agent') if http_request else None
            endpoint = str(http_request.url.path) if http_request else None
            
            log_id = db_manager.log_query(
                query=request.query,
                prediction_result=result,
                ip_address=ip_address,
                user_agent=user_agent,
                endpoint=endpoint
            )
        
        return QueryResponse(
            is_sql_injection=result['is_sql_injection'],
            confidence=result['confidence'],
            probability_safe=result['probability_safe'],
            probability_injection=result['probability_injection'],
            query=result['query'],
            log_id=log_id,
            vulnerable_parameter=result.get('vulnerable_parameter'),
            suspicious_value=result.get('suspicious_value')
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")


@app.post("/api/v1/batch-detect", response_model=BatchQueryResponse)
async def batch_detect_sql_injection(
    request: BatchQueryRequest,
    http_request: Request = None
):
    """
    Detect SQL injection in multiple queries.
    """
    try:
        predictor = get_predictor()
        db_manager = get_db_manager()
        
        results = []
        injections_detected = 0
        
        for query in request.queries:
            result = predictor.predict(query)
            
            if result['is_sql_injection']:
                injections_detected += 1
            
            log_id = None
            if request.log_to_db:
                ip_address = http_request.client.host if http_request else None
                user_agent = http_request.headers.get('user-agent') if http_request else None
                endpoint = str(http_request.url.path) if http_request else None
                
                log_id = db_manager.log_query(
                    query=query,
                    prediction_result=result,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    endpoint=endpoint
                )
            
            results.append(QueryResponse(
                is_sql_injection=result['is_sql_injection'],
                confidence=result['confidence'],
                probability_safe=result['probability_safe'],
                probability_injection=result['probability_injection'],
                query=result['query'],
                log_id=log_id,
                vulnerable_parameter=result.get('vulnerable_parameter'),
                suspicious_value=result.get('suspicious_value')
            ))
        
        return BatchQueryResponse(
            results=results,
            total_queries=len(request.queries),
            injections_detected=injections_detected
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing batch: {str(e)}")


@app.get("/api/v1/statistics", response_model=StatisticsResponse)
async def get_statistics(days: int = 7):
    """
    Get statistics for the last N days.
    """
    try:
        db_manager = get_db_manager()
        stats = db_manager.get_statistics(days=days)
        return StatisticsResponse(**stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching statistics: {str(e)}")


@app.get("/api/v1/logs")
async def get_logs(limit: int = 100, is_injection: Optional[bool] = None):
    """
    Get recent query logs.
    """
    try:
        db_manager = get_db_manager()
        logs = db_manager.get_recent_logs(limit=limit, is_injection=is_injection)
        return {
            "logs": logs,
            "count": len(logs)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching logs: {str(e)}")


@app.post("/api/v1/feedback")
async def submit_feedback(request: FeedbackRequest):
    """
    Submit feedback for a prediction (false positive/negative).
    """
    try:
        db_manager = get_db_manager()
        
        # Determine predicted label from log
        logs = db_manager.get_recent_logs(limit=1000)
        log_entry = next((log for log in logs if log['id'] == request.query_log_id), None)
        
        if not log_entry:
            raise HTTPException(status_code=404, detail="Query log not found")
        
        predicted_label = log_entry['is_sql_injection']
        
        feedback_id = db_manager.add_feedback(
            query_log_id=request.query_log_id,
            actual_label=request.actual_label,
            predicted_label=predicted_label,
            feedback_type=request.feedback_type,
            user_feedback=request.user_feedback
        )
        
        return {
            "message": "Feedback submitted successfully",
            "feedback_id": feedback_id
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error submitting feedback: {str(e)}")


@app.post("/api/v1/block")
async def block_request(
    query: str,
    reason: Optional[str] = None,
    http_request: Request = None
):
    """
    Log a blocked request (for use with blocking middleware).
    """
    try:
        db_manager = get_db_manager()
        
        ip_address = http_request.client.host if http_request else None
        user_agent = http_request.headers.get('user-agent') if http_request else None
        endpoint = str(http_request.url.path) if http_request else None
        
        block_id = db_manager.block_request(
            query=query,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            reason=reason or "SQL injection detected"
        )
        
        return {
            "message": "Request blocked and logged",
            "block_id": block_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error blocking request: {str(e)}")


@app.post("/api/v1/auth/signup", response_model=AuthResponse)
async def signup(user: UserCreate):
    """Register a new user."""
    try:
        db_manager = get_db_manager()
        
        # Hash password
        password_hash = hashlib.sha256(user.password.encode()).hexdigest()
        
        try:
            user_id = db_manager.create_user(user.username, password_hash)
            return {
                "token": f"user_{user_id}_{hashlib.md5(user.username.encode()).hexdigest()}", # Simple token for demo
                "username": user.username,
                "message": "User registered successfully"
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error registering user: {str(e)}")


@app.post("/api/v1/auth/login", response_model=AuthResponse)
async def login(user: UserLogin):
    """Login user."""
    try:
        db_manager = get_db_manager()
        
        # Hash password
        password_hash = hashlib.sha256(user.password.encode()).hexdigest()
        
        stored_user = db_manager.get_user(user.username)
        
        if not stored_user or stored_user['password_hash'] != password_hash:
            raise HTTPException(status_code=401, detail="Invalid username or password")
            
        return {
            "token": f"user_{stored_user['id']}_{hashlib.md5(user.username.encode()).hexdigest()}",
            "username": user.username,
            "message": "Login successful"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error logging in: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv('PORT', 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

