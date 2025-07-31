#!/usr/bin/env python3
"""
Test script to verify APP_PORT is being read correctly
"""

import os
from dotenv import load_dotenv

print("Before load_dotenv():")
print(f"APP_PORT from environment: {os.getenv('APP_PORT', 'NOT_SET')}")

load_dotenv()

print("\nAfter load_dotenv():")
print(f"APP_PORT from environment: {os.getenv('APP_PORT', 'NOT_SET')}")

# Test the same logic as in app.py
APP_PORT = int(os.getenv("APP_PORT", "10000"))
print(f"APP_PORT variable: {APP_PORT}") 