import requests
import json
import time

BASE_URL = "http://localhost:8000/api/v1"

def test_flow():
    print("Starting verification...")
    
    # 1. Register User
    username = f"testuser_{int(time.time())}"
    password = "password123"
    
    print(f"\n1. Registering user: {username}")
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json={
            "username": username,
            "password": password
        })
        if resp.status_code == 200:
            print("   SUCCESS: User registered")
        else:
            print(f"   FAILED: {resp.text}")
            return
    except Exception as e:
        print(f"   FAILED: {e}")
        return

    # 2. Login
    print("\n2. Logging in")
    try:
        resp = requests.post(f"{BASE_URL}/auth/login", json={
            "username": username,
            "password": password
        })
        if resp.status_code == 200:
            print("   SUCCESS: Login successful")
            token = resp.json()['token']
        else:
            print(f"   FAILED: {resp.text}")
            return
    except Exception as e:
        print(f"   FAILED: {e}")
        return

    # 3. Scan Safe URL
    safe_url = "https://google.com/search?q=test"
    print(f"\n3. Scanning Safe URL: {safe_url}", flush=True)
    try:
        resp = requests.post(f"{BASE_URL}/detect", json={
            "query": safe_url,
            "log_to_db": True
        })
        data = resp.json()
        if not data['is_sql_injection']:
            print(f"   SUCCESS: Correctly identified as SAFE (Confidence: {data['confidence']:.2f})", flush=True)
        else:
            print(f"   FAILED: False Positive! Identified as INJECTION", flush=True)
            print(f"   Response: {json.dumps(data)}", flush=True)
    except Exception as e:
        print(f"   FAILED: {e}", flush=True)

    # 4. Scan Vulnerable URL
    vuln_url = "http://example.com/page?id=1' OR '1'='1"
    print(f"\n4. Scanning Vulnerable URL: {vuln_url}", flush=True)
    try:
        resp = requests.post(f"{BASE_URL}/detect", json={
            "query": vuln_url,
            "log_to_db": True
        })
        data = resp.json()
        if data['is_sql_injection']:
            print(f"   SUCCESS: Correctly identified as INJECTION (Confidence: {data['confidence']:.2f})", flush=True)
            print(f"   Vulnerable Parameter: {data.get('vulnerable_parameter')}", flush=True)
        else:
            print(f"   FAILED: False Negative! Identified as SAFE", flush=True)
            print(f"   Response: {json.dumps(data)}", flush=True)
    except Exception as e:
        print(f"   FAILED: {e}", flush=True)

if __name__ == "__main__":
    test_flow()
