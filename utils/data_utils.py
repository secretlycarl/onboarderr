"""
Data utilities for Onboarderr

This module provides utilities for loading and saving JSON files,
with improved error handling and recovery.
"""

import os
import json
from typing import Any, Optional
from pathlib import Path

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

def safe_operation(operation, error_message, operation_type, default_value):
    """
    Safely execute an operation with error handling and logging.
    
    Args:
        operation: Function to execute
        error_message: Error message to log
        operation_type: Type of operation for logging
        default_value: Default value to return on error
        
    Returns:
        Result of operation or default value
    """
    try:
        return operation()
    except Exception as e:
        debug_log(f"[ERROR] {error_message}: {e}")
        return default_value

def load_json_file(filename: str, default: Any = None) -> Any:
    """
    Load JSON file with improved error handling and recovery.
    
    Args:
        filename: Name of the JSON file to load
        default: Default value if file not found or invalid
        
    Returns:
        Loaded data or default value
    """
    if default is None:
        default = []
    
    def load_operation():
        with open(os.path.join(os.getcwd(), filename), "r", encoding="utf-8") as f:
            return json.load(f)
    
    try:
        data = safe_operation(
            load_operation,
            f"Failed to load JSON file: {filename}",
            "file_operation",
            default
        )
        
        debug_log(f"Loaded {len(data) if isinstance(data, (list, dict)) else 'data'} from {filename}")
        return data
        
    except FileNotFoundError:
        debug_log(f"No {filename} file found, using default")
        return default
    except json.JSONDecodeError as e:
        debug_log(f"JSON decode error in {filename}: {e}")
        return default
    except Exception as e:
        debug_log(f"Unexpected error loading {filename}: {e}")
        return default

def save_json_file(filename: str, data: Any) -> bool:
    """
    Save JSON file with improved error handling and recovery.
    
    Args:
        filename: Name of the JSON file to save
        data: Data to save
        
    Returns:
        True if successful, False otherwise
    """
    def save_operation():
        file_path = os.path.join(os.getcwd(), filename)
        # Create directory if it doesn't exist (only if there's a directory component)
        dir_path = os.path.dirname(file_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True  # Explicitly return True on success
    
    try:
        success = safe_operation(
            save_operation,
            f"Failed to save JSON file: {filename}",
            "file_operation",
            False
        )
        
        debug_log(f"{'Successfully saved' if success else 'Failed to save'} data to {filename}")
        return success
        
    except Exception as e:
        debug_log(f"Unexpected error saving {filename}: {e}")
        return False 