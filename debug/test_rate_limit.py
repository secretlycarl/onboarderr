#!/usr/bin/env python3
import requests
import time

def test_rate_limiting():
    base_url = "http://localhost:12345"
    
    # Get initial CSRF token
    session = requests.Session()
    response = session.get(f"{base_url}/login")
    
    # Extract CSRF token from the response
    import re
    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    if not csrf_match:
        print("Could not find CSRF token")
        return
    
    csrf_token = csrf_match.group(1)
    print(f"CSRF Token: {csrf_token}")
    
    # Make 6 failed login attempts (more than the 5 limit)
    for i in range(6):
        print(f"Attempt {i+1}: Making failed login attempt...")
        
        data = {
            'password': f'wrongpassword{i}',
            'csrf_token': csrf_token
        }
        
        response = session.post(f"{base_url}/login", data=data)
        
        if "Incorrect password" in response.text:
            print(f"  ✓ Failed attempt {i+1} recorded")
        else:
            print(f"  ✗ Unexpected response for attempt {i+1}")
            print(f"    Response: {response.text[:200]}...")
    
    # Now check the rate limit status
    print("\nChecking rate limit status...")
    response = session.get(f"{base_url}/ajax/check-rate-limit")
    
    if response.status_code == 200:
        result = response.json()
        print(f"Rate limit check result: {result}")
        
        if result.get('rate_limited'):
            print("✓ Rate limiting is working!")
            print(f"  Time remaining: {result.get('time_remaining', 'unknown')} seconds")
        else:
            print("✗ Rate limiting is NOT working - should be rate limited after 5 attempts")
    else:
        print(f"✗ Failed to check rate limit: {response.status_code}")
        print(f"  Response: {response.text}")

if __name__ == "__main__":
    test_rate_limiting() 