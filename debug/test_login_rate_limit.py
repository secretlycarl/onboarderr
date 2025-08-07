#!/usr/bin/env python3
"""
Test script to verify login rate limiting functionality
"""
import requests
import time
import json
import re

def clear_rate_limit_data():
    """Clear rate limit data by making a request to reset it"""
    base_url = "http://localhost:12345"
    
    # This is a simple way to potentially clear rate limit data
    # In a real application, you might have an admin endpoint for this
    print("Clearing rate limit data...")
    
    # Make a few requests to potentially trigger cleanup
    session = requests.Session()
    for i in range(3):
        try:
            session.get(f"{base_url}/login")
            time.sleep(0.1)
        except:
            pass

def test_login_rate_limit():
    """Test login rate limiting by making multiple failed attempts"""
    base_url = "http://localhost:12345"  # Updated to correct port
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("Testing login rate limiting...")
    print("=" * 40)
    
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
    
    # Step 3: Make multiple failed login attempts
    print("\nMaking failed login attempts...")
    for i in range(6):  # Try 6 times to trigger the 5-attempt limit
        print(f"Attempt {i+1}/6...")
        
        data = {
            'password': f'TEST_INVALID_PASSWORD_{i}_XYZ123',  # Use completely different passwords
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
            if response.status_code == 400:
                print("CSRF token issue - trying to get new token...")
                # Get a new CSRF token
                response = session.get(f"{base_url}/login")
                csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                    print(f"New CSRF token: {csrf_token[:20]}...")
        
        time.sleep(0.5)  # Small delay between attempts
    
    # Step 4: Check rate limit status after attempts
    print("\nChecking rate limit status after attempts...")
    try:
        response = session.get(f"{base_url}/ajax/check-rate-limit")
        result = response.json()
        print(f"Final rate limit status: {result}")
        
        if result.get('rate_limited'):
            print("✅ Rate limiting is working!")
            print(f"Time remaining: {result.get('time_remaining', 'unknown')} seconds")
        else:
            print("❌ Rate limiting is NOT working")
            
    except Exception as e:
        print(f"Error checking rate limit after attempts: {e}")

def test_rate_limit_with_ajax():
    """Test rate limiting using AJAX requests to simulate the actual login form behavior"""
    base_url = "http://localhost:12345"
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("\n" + "=" * 40)
    print("Testing rate limiting with AJAX requests...")
    print("=" * 40)
    
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
    
    # Step 3: Make multiple failed login attempts via AJAX
    print("\nMaking failed login attempts via AJAX...")
    for i in range(6):  # Try 6 times to trigger the 5-attempt limit
        print(f"AJAX Attempt {i+1}/6...")
        
        data = {
            'password': f'TEST_INVALID_PASSWORD_{i}_XYZ123',  # Use completely different passwords
            'csrf_token': csrf_token
        }
        
        headers = {
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        response = session.post(f"{base_url}/login", data=data, headers=headers)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 401:
            result = response.json()
            print(f"  Response: {result}")
        elif response.status_code == 200:
            print("  Login successful (unexpected)")
        else:
            print(f"  Unexpected status: {response.status_code}")
        
        time.sleep(0.5)  # Small delay between attempts
    
    # Step 4: Check rate limit status after AJAX attempts
    print("\nChecking rate limit status after AJAX attempts...")
    try:
        response = session.get(f"{base_url}/ajax/check-rate-limit")
        result = response.json()
        print(f"Final rate limit status: {result}")
        
        if result.get('rate_limited'):
            print("✅ Rate limiting is working with AJAX!")
            print(f"Time remaining: {result.get('time_remaining', 'unknown')} seconds")
        else:
            print("❌ Rate limiting is NOT working with AJAX")
            
    except Exception as e:
        print(f"Error checking rate limit after AJAX attempts: {e}")

def test_clean_rate_limit():
    """Test rate limiting with a clean state"""
    base_url = "http://localhost:12345"
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("\n" + "=" * 40)
    print("Testing rate limiting with clean state...")
    print("=" * 40)
    
    # Clear rate limit data first
    clear_rate_limit_data()
    
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
    
    # Step 3: Make exactly 5 failed login attempts via AJAX
    print("\nMaking exactly 5 failed login attempts via AJAX...")
    for i in range(5):  # Exactly 5 attempts to trigger the limit
        print(f"AJAX Attempt {i+1}/5...")
        
        data = {
            'password': f'TEST_INVALID_PASSWORD_{i}_XYZ123',  # Use completely different passwords
            'csrf_token': csrf_token
        }
        
        headers = {
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        response = session.post(f"{base_url}/login", data=data, headers=headers)
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 401:
            result = response.json()
            print(f"  Response: {result}")
        elif response.status_code == 200:
            print("  Login successful (unexpected)")
        else:
            print(f"  Unexpected status: {response.status_code}")
        
        time.sleep(0.5)  # Small delay between attempts
    
    # Step 4: Check rate limit status after exactly 5 attempts
    print("\nChecking rate limit status after exactly 5 attempts...")
    try:
        response = session.get(f"{base_url}/ajax/check-rate-limit")
        result = response.json()
        print(f"Final rate limit status: {result}")
        
        if result.get('rate_limited'):
            print("✅ Rate limiting is working correctly!")
            print(f"Time remaining: {result.get('time_remaining', 'unknown')} seconds")
        else:
            print("❌ Rate limiting is NOT working correctly")
            
    except Exception as e:
        print(f"Error checking rate limit after attempts: {e}")

if __name__ == "__main__":
    print("Login Rate Limit Test")
    print("=" * 20)
    
    # Test 1: Regular form submission
    test_login_rate_limit()
    
    # Test 2: AJAX submission (like the actual login form)
    test_rate_limit_with_ajax()
    
    # Test 3: Clean state test
    test_clean_rate_limit()
    
    print("\nTest complete.") 