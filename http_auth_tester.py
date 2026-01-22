#!/usr/bin/env python3
"""
HTTP Authentication Response Tester
Tests various HTTP auth responses to trigger different client behaviors
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import argparse
import base64

class AuthTesterHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[*] {self.address_string()} - {format % args}")

    def do_GET(self):
        self.handle_request()

    def do_PROPFIND(self):
        self.handle_request()

    def do_OPTIONS(self):
        self.handle_request()

    def handle_request(self):
        auth_header = self.headers.get('Authorization', '')

        print(f"\n[+] Request from {self.client_address[0]}")
        print(f"    Method: {self.command}")
        print(f"    Path: {self.path}")
        print(f"    Authorization: {auth_header[:50]}..." if auth_header else "    No Authorization header")

        # Parse NTLM message type if present
        if auth_header.startswith('NTLM ') or auth_header.startswith('Negotiate '):
            try:
                token = base64.b64decode(auth_header.split(' ')[1])
                if len(token) >= 12:
                    msg_type = int.from_bytes(token[8:12], 'little')
                    print(f"    NTLM Message Type: {msg_type}")

                    if msg_type == 3:
                        # Parse flags from Type 3
                        if len(token) >= 64:
                            flags = int.from_bytes(token[60:64], 'little')
                            print(f"    NTLM Flags: {flags:#010x}")
                            print(f"    SIGN: {bool(flags & 0x10)}")
                            print(f"    SEAL: {bool(flags & 0x20)}")
                            print(f"    ALWAYS_SIGN: {bool(flags & 0x8000)}")
            except Exception as e:
                print(f"    Error parsing NTLM: {e}")

        # Respond based on mode
        mode = self.server.mode

        if mode == 'ntlm':
            self.send_ntlm_challenge()
        elif mode == 'proxy':
            self.send_proxy_auth()
        elif mode == 'basic':
            self.send_basic_auth()
        elif mode == 'redirect_local':
            self.send_redirect('http://127.0.0.1/')
        elif mode == 'redirect_localhost':
            self.send_redirect('http://localhost/')
        elif mode == 'negotiate':
            self.send_negotiate_auth()
        elif mode == 'multi':
            self.send_multiple_auth()
        else:
            self.send_ntlm_challenge()

    def send_ntlm_challenge(self):
        """Standard 401 with NTLM/Negotiate"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'NTLM')
        self.send_header('WWW-Authenticate', 'Negotiate')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 401 with NTLM/Negotiate")

    def send_proxy_auth(self):
        """407 Proxy Authentication Required"""
        self.send_response(407)
        self.send_header('Proxy-Authenticate', 'NTLM')
        self.send_header('Proxy-Authenticate', 'Negotiate')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 407 Proxy Authentication Required")

    def send_basic_auth(self):
        """401 with Basic auth"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Test"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 401 with Basic auth")

    def send_negotiate_auth(self):
        """401 with only Negotiate (no NTLM)"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Negotiate')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 401 with Negotiate only")

    def send_multiple_auth(self):
        """401 with multiple auth schemes"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Negotiate')
        self.send_header('WWW-Authenticate', 'NTLM')
        self.send_header('WWW-Authenticate', 'Basic realm="Test"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        print("    Response: 401 with multiple schemes")

    def send_redirect(self, location):
        """302 redirect"""
        self.send_response(302)
        self.send_header('Location', location + self.path)
        self.send_header('Content-Length', '0')
        self.end_headers()
        print(f"    Response: 302 redirect to {location}")

def main():
    parser = argparse.ArgumentParser(description='HTTP Authentication Response Tester')
    parser.add_argument('-p', '--port', type=int, default=80, help='Port to listen on (default: 80)')
    parser.add_argument('-i', '--interface', default='0.0.0.0', help='Interface to bind to (default: 0.0.0.0)')
    parser.add_argument('-m', '--mode',
                       choices=['ntlm', 'proxy', 'basic', 'redirect_local', 'redirect_localhost', 'negotiate', 'multi'],
                       default='ntlm',
                       help='Response mode to test')

    args = parser.parse_args()

    print(f"""
[*] HTTP Authentication Tester
[*] Listening on {args.interface}:{args.port}
[*] Mode: {args.mode}
[*]
[*] Modes:
    - ntlm: Standard 401 with NTLM/Negotiate
    - proxy: 407 Proxy Authentication Required
    - basic: 401 with Basic auth
    - redirect_local: 302 redirect to http://127.0.0.1/
    - redirect_localhost: 302 redirect to http://localhost/
    - negotiate: 401 with only Negotiate (no NTLM)
    - multi: 401 with multiple auth schemes
[*]
[*] Waiting for connections...
    """)

    server = HTTPServer((args.interface, args.port), AuthTesterHandler)
    server.mode = args.mode

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.shutdown()

if __name__ == '__main__':
    main()
