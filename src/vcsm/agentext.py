#
# Copyright 2023 The University of Queensland
# Author: Alex Wilson <alex@uq.edu.au>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

"""
Agent extension and key wrapper class
"""

import paramiko.agent
from paramiko import Message

from ecdsa.keys import VerifyingKey, BadSignatureError
from ecdsa.ellipticcurve import Point
from ecdsa.der import UnexpectedDER
from ecdsa.util import sigencode_der, sigdecode_der
from ecdsa.ellipticcurve import AbstractPoint, Point

from tlslite.utils.ecdsakey import ECDSAKey
from tlslite.utils.ecc import getCurveByName
from tlslite.utils.cryptomath import secureHash
from tlslite.utils.compat import compatHMAC

from tlslite import X509

SSH_AGENT_SUCCESS = 6
SSH_AGENTC_EXTENSION = bytes([27])

class Agent(paramiko.agent.Agent):
    def query_extensions(self):
        msg = Message()
        msg.add_byte(SSH_AGENTC_EXTENSION)
        msg.add_string("query")
        ptype, result = self._send_message(msg)
        if ptype != SSH_AGENT_SUCCESS:
            return []
        n = result.get_int()
        r = []
        for x in range(0, n):
            r.append(result.get_text())
        return r

    def has_extension(self, ext):
        exts = self.query_extensions()
        if ext in exts:
            return True
        return False

class AgentKeyExt(paramiko.agent.AgentKey):
    def sign_prehash_data(self, data):
        msg = Message()
        msg.add_byte(SSH_AGENTC_EXTENSION)
        msg.add_string('sign-prehash@arekinath.github.io')
        msg.add_string(self.blob)
        msg.add_string(data)
        msg.add_int(0)
        ptype, result = self.agent._send_message(msg)
        if ptype != SSH_AGENT_SUCCESS:
            raise Exception('ssh-agent failed to sign prehashed data')
        return result.get_binary()

    def get_x509_cert(self):
        msg = Message()
        msg.add_byte(SSH_AGENTC_EXTENSION)
        msg.add_string('x509-certs@joyent.com')
        msg.add_string(self.blob)
        msg.add_int(0)
        ptype, result = self.agent._send_message(msg)
        if ptype != SSH_AGENT_SUCCESS:
            raise Exception('ssh-agent failed to return x509 certs')
        return result.get_binary()
paramiko.agent.AgentKey = AgentKeyExt

class SSHAgentECDSAKey(ECDSAKey):
    def __init__(self, fp):
        self._agent = Agent()
        ks = [x for x in self._agent.get_keys() if x.get_fingerprint() == fp]
        if len(ks) < 1:
            raise Exception('Key fingerprint not found in agent')
        if not self._agent.has_extension('sign-prehash@arekinath.github.io'):
            raise Exception('Agent lacks the prehash sign extension')
        self._key = ks[0]
        tname = None
        if self._key.get_name() == 'ecdsa-sha2-nistp256':
            tname = 'secp256r1'
        elif self._key.get_name() == 'ecdsa-sha2-nistp384':
            tname = 'secp384r1'
        elif self._key.get_name() == 'ecdsa-sha2-nistp521':
            tname = 'secp521r1'
        else:
            raise Exception('Unsupported EC alg')
        self._curve = getCurveByName(tname)
        msg = Message(self._key.asbytes())
        msg.get_text()  # alg
        msg.get_text()  # curve
        self.public_key = VerifyingKey.from_string(msg.get_binary(),
            curve = self._curve)
        self.private_key = self.public_key

    def key_type(self):
        return 'ecdsa'

    def __len__(self):
        if self._key.get_name() == 'ecdsa-sha2-nistp256':
            return 256
        elif self._key.get_name() == 'ecdsa-sha2-nistp384':
            return 384
        elif self._key.get_name() == 'ecdsa-sha2-nistp521':
            return 521

    def hasPrivateKey(self):
        return True

    def get_cert(self):
        der = self._key.get_x509_cert()
        x = X509()
        x.parseBinary(der)
        return x

    @staticmethod
    def generate(bits):
        raise NotImplementedError()

    def acceptsPassword(self):
        return False

    def _sign(self, bytes, rsaScheme=None, hAlg='sha256', sLen=None):
        return self._key.sign_prehash_data(bytes)

    def _verify(self, signature, hash_bytes):
        try:
            return self.public_key.verify_digest(compatHMAC(signature),
                                                 compatHMAC(hash_bytes),
                                                 sigdecode_der)
        # https://github.com/warner/python-ecdsa/issues/114
        except (BadSignatureError, UnexpectedDER, IndexError, AssertionError):
            return False
