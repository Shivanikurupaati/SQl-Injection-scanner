"""
Quick test script for the SQL Injection Detector API.
Run this after starting the backend server.
"""

import requests
import json

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint."""
    print("Testing health endpoint...")
    response = requests.get(f"{BASE_URL}/api/v1/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print()

def test_detect():
    """Test detection endpoint."""
    print("Testing detection endpoint...")
    
    test_queries = [
        "SELECT * FROM users WHERE id = 1",  # Safe
        "admin' OR '1'='1",  # Injection
        "'; DROP TABLE users --",  # Injection
        "SELECT name, email FROM customers",  # Safe
        "' UNION SELECT NULL, NULL, NULL --",  # Injection
    ]
    
    for query in test_queries:
        payload = {"query": query, "log_to_db": True}
        response = requests.post(f"{BASE_URL}/api/v1/detect", json=payload)
        
        if response.status_code == 200:
            result = response.json()
            status = "🚨 INJECTION" if result['is_sql_injection'] else "✅ SAFE"
            print(f"{status}: {query[:50]}...")
            print(f"  Confidence: {result['confidence']:.4f}")
        else:
            print(f"Error: {response.status_code} - {response.text}")
        print()

def test_batch_detect():
    """Test batch detection endpoint."""
    print("Testing batch detection endpoint...")
    
    queries = [
        "SELECT * FROM users",
        "admin' OR '1'='1",
        "INSERT INTO products VALUES ('test', 10)",
        "' UNION SELECT password FROM users --",
    ]
    
    payload = {"queries": queries, "log_to_db": True}
    response = requests.post(f"{BASE_URL}/api/v1/batch-detect", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        print(f"Total queries: {result['total_queries']}")
        print(f"Injections detected: {result['injections_detected']}")
        print("\nResults:")
        for r in result['results']:
            status = "🚨 INJECTION" if r['is_sql_injection'] else "✅ SAFE"
            print(f"  {status}: {r['query'][:50]}...")
    else:
        print(f"Error: {response.status_code} - {response.text}")
    print()

def test_statistics():
    """Test statistics endpoint."""
    print("Testing statistics endpoint...")
    response = requests.get(f"{BASE_URL}/api/v1/statistics?days=7")
    
    if response.status_code == 200:
        stats = response.json()
        print(f"Statistics (last {stats['days']} days):")
        print(f"  Total queries: {stats['total_queries']}")
        print(f"  Injections detected: {stats['sql_injections_detected']}")
        print(f"  False positives: {stats['false_positives']}")
        print(f"  False negatives: {stats['false_negatives']}")
    else:
        print(f"Error: {response.status_code} - {response.text}")
    print()

def main():
    """Run all tests."""
    print("=" * 60)
    print("SQL Injection Detector API Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_health()
        test_detect()
        test_batch_detect()
        test_statistics()
        
        print("=" * 60)
        print("All tests completed!")
        print("=" * 60)
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the API.")
        print("Make sure the backend server is running:")
        print("  python backend/main.py")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

