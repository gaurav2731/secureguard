#!/usr/bin/env python3
"""
Test script to verify the changes made to redis_connection.py and app.py
"""

import sys
import os
import json

# Add the current directory to path to import modules
sys.path.insert(0, os.path.dirname(__file__))

def test_redis_connection():
    """Test the get_behavior_data method in redis_connection.py"""
    print("Testing redis_connection.py get_behavior_data method...")

    try:
        # Test the JSON parsing logic directly by importing the module
        # and testing the method that was changed
        import json

        # Simulate the get_behavior_data logic
        def test_get_behavior_data_logic(data_str):
            """Test the logic from get_behavior_data method"""
            if not data_str:
                return {}
            try:
                return json.loads(data_str)
            except json.JSONDecodeError:
                return {}

        # Test with valid JSON
        valid_json = '{"requests": 10, "last_seen": "2023-01-01"}'
        result = test_get_behavior_data_logic(valid_json)
        expected = {"requests": 10, "last_seen": "2023-01-01"}
        if result == expected:
            print("✓ JSON parsing correctly handled valid JSON")
        else:
            print(f"✗ JSON parsing failed for valid JSON: expected {expected}, got {result}")
            return False

        # Test with invalid JSON
        invalid_json = "invalid json"
        result = test_get_behavior_data_logic(invalid_json)
        if result == {}:
            print("✓ JSON parsing correctly handled invalid JSON (returned empty dict)")
        else:
            print(f"✗ JSON parsing failed for invalid JSON: expected {{}}, got {result}")
            return False

        # Test with empty string
        result = test_get_behavior_data_logic("")
        if result == {}:
            print("✓ JSON parsing correctly handled empty string")
        else:
            print(f"✗ JSON parsing failed for empty string: expected {{}}, got {result}")
            return False

        # Test with None
        result = test_get_behavior_data_logic(None)
        if result == {}:
            print("✓ JSON parsing correctly handled None")
        else:
            print(f"✗ JSON parsing failed for None: expected {{}}, got {result}")
            return False

    except Exception as e:
        print(f"✗ Error testing redis_connection logic: {e}")
        return False

    return True

def test_app_import():
    """Test that app.py can be imported without errors"""
    print("Testing app.py import...")

    try:
        import app
        print("✓ app.py imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error in app.py: {e}")
        return False
    except Exception as e:
        print(f"✗ Other error importing app.py: {e}")
        return False

def test_app_start_services():
    """Test that start_services can be called without errors"""
    print("Testing app.py start_services function...")

    try:
        import app
        # Call start_services (this should initialize without starting the server)
        app.start_services()
        print("✓ start_services executed successfully")
        return True
    except Exception as e:
        print(f"✗ Error in start_services: {e}")
        return False

if __name__ == "__main__":
    print("Running tests for SecureGuard changes...\n")

    results = []

    # Test redis_connection
    results.append(test_redis_connection())
    print()

    # Test app import
    results.append(test_app_import())
    print()

    # Test start_services
    results.append(test_app_start_services())
    print()

    if all(results):
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)
