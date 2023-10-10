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
Implementation of getServiceInstance
"""

from .agentext import SSHAgentECDSAKey, Agent
from tlslite import TLSConnection, HTTPTLSConnection, X509, X509CertChain, parsePEMKey
from tlslite.errors import TLSAuthenticationTypeError, TLSNoAuthenticationError
from xml.etree import ElementTree

from http.client import HTTPSConnection
from urllib.parse import urlencode, urlparse, parse_qs

from http.cookies import SimpleCookie

from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError
from asn1crypto.x509 import Certificate

from pyVmomi import vim
from pyVim.connect import SmartStubAdapter

import json
import logging

class CertChecker:
    def __init__(self, host: str):
        self._host = host

    def __call__(self, conn):
        chain = conn.session.serverCertChain
        if isinstance(chain, X509CertChain):
            certs = [Certificate.load(bytes(x509.bytes)) for x509 in chain.x509List]
            eecert = certs[0]
            icerts = certs[1:]
            vctx = ValidationContext(
                allow_fetching = True,
                revocation_mode = 'hard-fail')
            val = CertificateValidator(eecert, icerts,
                validation_context = vctx)
            val.validate_tls(self._host)
        elif chain:
            raise TLSAuthenticationTypeError()
        else:
            raise TLSNoAuthenticationError()


def getServiceInstance(host: str, upn: str):
    log = logging.getLogger('vcsm')

    vctx = ValidationContext(
        allow_fetching = True,
        revocation_mode = 'hard-fail')

    agent = Agent()
    key = None
    log.debug('searching for key')
    for k in agent.get_keys():
        log.debug(f"looking at key {k.get_fingerprint().hex()}")
        try:
            der = k.get_x509_cert()
            cert = Certificate.load(der)
            val = CertificateValidator(cert, validation_context = vctx)
            val.validate_usage(set(['digital_signature']))
            if not cert.subject_alt_name_value:
                continue
            for san in cert.subject_alt_name_value:
                if san.name != 'other_name':
                    continue
                try:
                    oid = san.native['type_id']
                    v = san.native['value']
                except:
                    continue
                if oid == '1.3.6.1.4.1.311.20.2.3':
                    log.debug(f"key {k.get_fingerprint().hex()} has upn {v}")
                    if v == upn:
                        key = k
                        break
            if key is not None:
                break
        except Exception as e:
            log.debug(f"failed to check upn: {e}")
            continue
    if key is None:
        raise Exception(f"Failed to find any agent key with UPN {upn}")
    fp = key.get_fingerprint()
    log.debug(f"using key {fp.hex()}")

    log.debug('getting SAMLRequest from /ui/login')
    conn = HTTPSConnection(host = host, port = 443)
    conn.request('GET', '/ui/login')
    r = conn.getresponse()
    if r.status != 302:
        raise Exception(f"Expected 302 from /ui/login, got a {r.status}")
    uri = urlparse(r.getheader('Location'))
    r.read()

    log.debug('starting smartcard auth')
    pkey = SSHAgentECDSAKey(fp)

    x509 = pkey.get_cert()
    chain = X509CertChain([x509])

    smconn = HTTPTLSConnection(
        host = host,
        port = 3128,
        certChain = chain,
        privateKey = pkey,
        checker = CertChecker(host))
    smconn.request('POST', '/websso/SAML2/SSOCAC/vsphere.local?' + uri.query,
        body = urlencode({'CastleAuthorization': 'TLSClient Og=='}),
        headers = {'content-type': 'application/x-www-form-urlencoded'})
    r = smconn.getresponse()
    if r.status != 200:
        raise Exception(f"Expected 200 from ssocac, got a {r.status}")
    body = r.read()

    root = ElementTree.fromstring(body.decode('utf-8'))
    body = root.find('body')
    form = body.find('form')
    inputs = form.findall('input')
    post = {}
    for inp in inputs:
        if inp.get('name') is not None:
            post[inp.get('name')] = inp.get('value')

    log.debug("converting back to /ui cookies...")
    conn.request('POST', '/ui/saml/websso/sso',
        body = urlencode(post),
        headers = {'content-type': 'application/x-www-form-urlencoded'})
    r = conn.getresponse()
    r.read()
    if r.status != 302:
        raise Exception(f"Expected 302 from /ui/saml/websso/sso, got a {r.status}")

    jar = SimpleCookie()
    for k,v in r.getheaders():
        if k == 'set-cookie':
            jar.load(v)
    cookies = jar.output(attrs=[], header='', sep=';')

    log.debug("getting session info...")
    conn.request('GET', '/ui/usersession/serverInfo',
        headers = {'cookie': cookies})
    r = conn.getresponse()
    data = json.loads(r.read())

    sinfos = data['serversInfo']
    my_sinfos = [x for x in sinfos if x['name'] == host]
    soap_cookie = json.loads(my_sinfos[0]['sessionCookie'])

    log.debug('creating service instance...')

    soap = SmartStubAdapter(host = host)
    soap.cookie = 'vmware_soap_session=' + soap_cookie

    si = vim.ServiceInstance('ServiceInstance', soap)
    return si
