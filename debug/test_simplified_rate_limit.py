#!/usr/bin/env python3
"""
Simple test for the simplified rate limiting logic
Tests the core functionality: 5+ failed attempts in 15 minutes triggers 1-hour lockout
"""

import requests
import time
import json

def test_simplified_rate_limit():
    base_url = "http://localhost:12345"
    session = requests.Session()
    
    print("Testing simplified rate limiting...")
    
    # Get login page
    response = session.get(f"{base_url}/login")
    print(f"Login page status: {response.status_code}")
    
    # Check initial rate limit status
    response = session.get(f"{base_url}/ajax/check-rate-limit")
    result = response.json()
    print(f"Initial rate limit: {result}")
    
    # Make failed attempts to trigger rate limiting
    print("\nMaking failed login attempts...")
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
    
    # Check rate limit status after attempts
    response = session.get(f"{base_url}/ajax/check-rate-limit")
    result = response.json()
    print(f"\nRate limit status after attempts: {result}")
    
    if result.get('rate_limited'):
        print(f"✅ IP is rate limited for {result.get('time_remaining', 0)} seconds")
    else:
        print("❌ IP should be rate limited but isn't")
    
    # Test form submission rate limiting
    print("\nTesting form submission rate limiting...")
    response = session.post(f"{base_url}/ajax/rate-limit-settings", 
                          json={"enabled": "yes", "max_login_attempts": 5, "max_form_submissions": 1})
    result = response.json()
    print(f"Form submission 1: {result}")
    
    # Try another form submission (should be rate limited)
    response = session.post(f"{base_url}/ajax/rate-limit-settings", 
                          json={"enabled": "yes", "max_login_attempts": 5, "max_form_submissions": 1})
    result = response.json()
    print(f"Form submission 2: {result}")
    
    print("\n✅ Simplified rate limiting test completed!")

if __name__ == "__main__":
    test_simplified_rate_limit() 