#!/usr/bin/env python3
"""
Test script to verify MOBILE_SCROLL_MODE environment variable functionality
"""

import os
from dotenv import load_dotenv

def test_mobile_scroll_mode():
    """Test the MOBILE_SCROLL_MODE environment variable"""
    
    # Load environment variables
    load_dotenv()
    
    # Test default value
    default_mode = os.getenv("MOBILE_SCROLL_MODE", "auto")
    print(f"✓ Default MOBILE_SCROLL_MODE: {default_mode}")
    
    # Test valid values
    valid_modes = ["auto", "manual"]
    if default_mode in valid_modes:
        print(f"✓ MOBILE_SCROLL_MODE '{default_mode}' is valid")
    else:
        print(f"✗ MOBILE_SCROLL_MODE '{default_mode}' is not valid (should be 'auto' or 'manual')")
    
    # Test template variable injection
    print("\nTesting template variable injection...")
    print("This would be available in templates as: {{ MOBILE_SCROLL_MODE }}")
    
    # Simulate different values
    test_values = ["auto", "manual", "invalid"]
    for value in test_values:
        os.environ["MOBILE_SCROLL_MODE"] = value
        current_mode = os.getenv("MOBILE_SCROLL_MODE", "auto")
        print(f"  - Setting to '{value}' -> Template gets: {current_mode}")
    
    print("\n✓ Mobile scroll mode test completed!")

if __name__ == "__main__":
    test_mobile_scroll_mode() 