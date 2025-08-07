#!/usr/bin/env python3
import requests
import time

def test_rate_limit():
    base_url = "http://localhost:12345"
    session = requests.Session()
    
    print("Testing rate limiting...")
    
    # Get login page
    response = session.get(f"{base_url}/login")
    print(f"Login page status: {response.status_code}")
    
    # Check initial rate limit
    response = session.get(f"{base_url}/ajax/check-rate-limit")
    result = response.json()
    print(f"Initial rate limit: {result}")
    
    # Make failed attempts
    for i in range(6):
        print(f"Attempt {i+1}/6")
        
        # Submit wrong password
        data = {'password': f'wrong{i}'}
        response = session.post(f"{base_url}/login", data=data)
        
        if response.status_code == 200:
            if "Too many failed attempts" in response.text:
                print("✅ Rate limit triggered!")
                break
            else:
                print("Incorrect password (expected)")
        else:
            print(f"Error: {response.status_code}")
        
        time.sleep(0.5)
    
    # Check final rate limit status
    response = session.get(f"{base_url}/ajax/check-rate-limit")
    result = response.json()
    print(f"Final rate limit: {result}")

if __name__ == "__main__":
    test_rate_limit() 