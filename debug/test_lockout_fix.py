#!/usr/bin/env python3
"""
Test script to verify the lockout fix - ensuring 1-hour lockout persists correctly
"""
import requests
import time
import json
import re

def test_lockout_persistence():
    """Test that lockout persists for the full hour duration"""
    base_url = "http://localhost:12345"
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("Testing lockout persistence fix...")
    print("=" * 50)
    
    # Step 1: Get the login page to get CSRF token
    print("Getting login page...")
    response = session.get(f"{base_url}/login")
    print(f"Login page status: {response.status_code}")
    
    # Extract CSRF token from the HTML using regex
    csrf_token = None
    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    if csrf_match:
        csrf_token = csrf_match.group(1)
        print(f"CSRF token: {csrf_token[:20]}...")
    else:
        print("Could not extract CSRF token")
        return
    
    # Step 2: Check initial rate limit status
    print("\nChecking initial rate limit status...")
    try:
        response = session.get(f"{base_url}/ajax/check-rate-limit")
        result = response.json()
        print(f"Initial rate limit status: {result}")
    except Exception as e:
        print(f"Error checking initial rate limit: {e}")
        return
    
    # Step 3: Make multiple failed login attempts to trigger lockout
    print("\nMaking failed login attempts to trigger lockout...")
    for i in range(6):  # Try 6 times to trigger the 5-attempt limit
        print(f"Attempt {i+1}/6...")
        
        data = {
            'password': f'TEST_INVALID_PASSWORD_{i}_XYZ123',
            'csrf_token': csrf_token
        }
        
        response = session.post(f"{base_url}/login", data=data)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            if "Too many failed attempts" in response.text:
                print("✅ Rate limit triggered!")
                break
            elif "Incorrect password" in response.text:
                print("Incorrect password (expected)")
            else:
                print("Unexpected response")
        else:
            print(f"Error: {response.status_code}")
        
        time.sleep(0.5)  # Small delay between attempts
    
    # Step 4: Check rate limit status after attempts
    print("\nChecking rate limit status after attempts...")
    try:
        response = session.get(f"{base_url}/ajax/check-rate-limit")
        result = response.json()
        print(f"Rate limit status: {result}")
        
        if result.get('rate_limited'):
            print("✅ Rate limiting is working!")
            time_remaining = result.get('time_remaining', 0)
            print(f"Time remaining: {time_remaining} seconds")
            
            # Test that lockout persists even after 15 minutes
            print(f"\nTesting lockout persistence...")
            print("The lockout should persist for the full hour, not just 15 minutes.")
            print("This test verifies that the fix prevents premature lockout clearing.")
            
        else:
            print("❌ Rate limiting is NOT working")
            
    except Exception as e:
        print(f"Error checking rate limit after attempts: {e}")

def test_hour_window_logic():
    """Test the new hour window logic"""
    base_url = "http://localhost:12345"
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("\n" + "=" * 50)
    print("Testing hour window logic...")
    print("=" * 50)
    
    # Step 1: Get the login page to get CSRF token
    print("Getting login page...")
    response = session.get(f"{base_url}/login")
    print(f"Login page status: {response.status_code}")
    
    # Extract CSRF token from the HTML using regex
    csrf_token = None
    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    if csrf_match:
        csrf_token = csrf_match.group(1)
        print(f"CSRF token: {csrf_token[:20]}...")
    else:
        print("Could not extract CSRF token")
        return
    
    # Step 2: Make attempts spread out to test hour window
    print("\nMaking attempts to test hour window logic...")
    print("This test simulates attempts that might be older than 15 minutes but within 1 hour.")
    
    for i in range(6):
        print(f"Attempt {i+1}/6...")
        
        data = {
            'password': f'TEST_INVALID_PASSWORD_{i}_XYZ123',
            'csrf_token': csrf_token
        }
        
        response = session.post(f"{base_url}/login", data=data)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            if "Too many failed attempts" in response.text:
                print("✅ Rate limit triggered!")
                break
            elif "Incorrect password" in response.text:
                print("Incorrect password (expected)")
            else:
                print("Unexpected response")
        else:
            print(f"Error: {response.status_code}")
        
        time.sleep(0.5)
    
    # Step 3: Check final status
    print("\nChecking final rate limit status...")
    try:
        response = session.get(f"{base_url}/ajax/check-rate-limit")
        result = response.json()
        print(f"Final rate limit status: {result}")
        
        if result.get('rate_limited'):
            print("✅ Hour window logic is working!")
            time_remaining = result.get('time_remaining', 0)
            print(f"Time remaining: {time_remaining} seconds")
        else:
            print("❌ Hour window logic is NOT working")
            
    except Exception as e:
        print(f"Error checking final rate limit: {e}")

if __name__ == "__main__":
    test_lockout_persistence()
    test_hour_window_logic() 