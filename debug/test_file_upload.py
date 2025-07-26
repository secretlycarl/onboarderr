#!/usr/bin/env python3
"""
Test script to verify file upload functionality
"""

import os
import tempfile
from PIL import Image
import io

def test_image_processing():
    """Test the image processing functions"""
    
    # Create a test image
    test_img = Image.new('RGB', (300, 300), color='red')
    
    # Save to bytes
    img_bytes = io.BytesIO()
    test_img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    # Create a mock file object
    class MockFile:
        def __init__(self, data, filename):
            self.stream = data
            self.filename = filename
    
    mock_file = MockFile(img_bytes, 'test_logo.png')
    
    # Test the processing functions
    try:
        from app import process_uploaded_logo, process_uploaded_wordmark
        
        # Test logo processing
        result = process_uploaded_logo(mock_file)
        print(f"Logo processing result: {result}")
        
        # Test wordmark processing
        result = process_uploaded_wordmark(mock_file)
        print(f"Wordmark processing result: {result}")
        
        # Check if files were created
        if os.path.exists('static/clearlogo.webp'):
            print("✓ clearlogo.webp created successfully")
        else:
            print("✗ clearlogo.webp not created")
            
        if os.path.exists('static/favicon.webp'):
            print("✓ favicon.webp created successfully")
        else:
            print("✗ favicon.webp not created")
            
        if os.path.exists('static/wordmark.webp'):
            print("✓ wordmark.webp created successfully")
        else:
            print("✗ wordmark.webp not created")
            
    except ImportError as e:
        print(f"Import error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_image_processing() 