#!/usr/bin/env python3
"""
Test script for the proxy functionality in SecureGuard
"""

import requests
import json
import time
from config_enhanced import PROTECTED_WEBSITES

def test_proxy_functionality():
    """Test the proxy functionality"""

    print("Testing SecureGuard Proxy Functionality")
    print("=" * 50)

    # Test configuration
    test_config = {
        'host': 'localhost',
        'port': 5000,
        'timeout': 10
    }

    # Test 1: Health check (should bypass proxy)
    print("\n1. Testing health check endpoint...")
    try:
        response = requests.get(f"http://{test_config['host']}:{test_config['port']}/health",
                              timeout=test_config['timeout'])
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {data}")
            print("   ✓ Health check passed")
        else:
            print(f"   ✗ Health check failed: {response.text}")
    except Exception as e:
        print(f"   ✗ Health check error: {e}")

    # Test 2: Dashboard (should be handled by proxy or dashboard route)
    print("\n2. Testing dashboard endpoint...")
    try:
        response = requests.get(f"http://{test_config['host']}:{test_config['port']}/",
                              timeout=test_config['timeout'])
        print(f"   Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('content-type', 'N/A')}")
        if 'text/html' in response.headers.get('content-type', ''):
            print("   ✓ Dashboard returned HTML (proxy or direct route)")
        else:
            print(f"   Response preview: {response.text[:200]}...")
    except Exception as e:
        print(f"   ✗ Dashboard error: {e}")

    # Test 3: API stats (should bypass proxy)
    print("\n3. Testing API stats endpoint...")
    try:
        response = requests.get(f"http://{test_config['host']}:{test_config['port']}/api/stats",
                              timeout=test_config['timeout'])
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✓ API stats: {len(str(data))} bytes of data")
        else:
            print(f"   ✗ API stats failed: {response.text}")
    except Exception as e:
        print(f"   ✗ API stats error: {e}")

    # Test 4: Check backend configuration
    print("\n4. Checking backend configuration...")
    print(f"   Configured backends: {list(PROTECTED_WEBSITES.keys())}")
    for name, config in PROTECTED_WEBSITES.items():
        print(f"   - {name}: {config.get('ip', 'N/A')}:{config.get('port', 'N/A')} (SSL: {config.get('use_ssl', False)})")

    # Test 5: Test with a backend that might not exist (should return error)
    print("\n5. Testing proxy with non-existent backend...")
    try:
        # Try to access a path that should be proxied
        response = requests.get(f"http://{test_config['host']}:{test_config['port']}/test-proxy",
                              timeout=test_config['timeout'])
        print(f"   Status: {response.status_code}")
        if response.status_code in [502, 504, 500]:
            print("   ✓ Proxy correctly handled backend error")
        else:
            print(f"   Response: {response.text[:200]}...")
    except Exception as e:
        print(f"   ✗ Proxy test error: {e}")

    print("\n" + "=" * 50)
    print("Proxy functionality test completed!")

if __name__ == "__main__":
    test_proxy_functionality()
