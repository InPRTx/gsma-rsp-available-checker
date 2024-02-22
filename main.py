from __future__ import annotations
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import argparse
import base64
import json
import os
import re
import ssl
import urllib.request

context = ssl._create_unverified_context()


def gen_tlv(tag: bytes, data: bytes) -> bytes:
    length = len(data)
    tlv = tag + bytes([length]) + data
    return tlv


def gen_svn(svn_str: str) -> bytes:
    tag = b'\x82'
    svn = [int(i) for i in svn_str.split('.')]
    return gen_tlv(tag, bytes(svn))


def gen_pki(cert: bytes) -> bytes:
    tag = b'\x04'
    return gen_tlv(tag, cert)


def gen_pki_list(cert_str: str) -> bytes:
    certs = cert_str.split(',')
    pki_list = b''
    for cert in certs:
        if re.match(r'^[0-9a-fA-F]{40}$', cert):
            cert = bytes.fromhex(cert)
            pki_list += gen_pki(cert)
        else:
            print(json.dumps({"status": "warning", "reason": "skip invalid cert string:" + cert}))
    if not pki_list:
        raise ValueError('无有效证书,证书应为40位0-f或0-F,多条证书以逗号隔开')
    return gen_tlv(b'\xA9', pki_list) + gen_tlv(b'\xAA', pki_list)


def gen_euicc_info(cert_str: str) -> str:
    tag = b'\xBF\x20'
    euiccinfo = gen_tlv(tag, gen_svn('2.2.2') + gen_pki_list(cert_str))
    return base64.encodebytes(euiccinfo).decode().strip()


def gen_random_challenge() -> str:
    return base64.b64encode(os.urandom(16)).decode().strip()


def request_cert(host: str, cert_str: str, file_name: str | None):
    body = {"smdpAddress": host, "euiccChallenge": gen_random_challenge(),
            "euiccInfo1": gen_euicc_info(cert_str)}
    header = {'Content-Type': 'application/json',
              'User-Agent': 'gsma-rsp-lpad',
              'X-Admin-Protocol': 'gsma/rsp/v2.2.0'}

    try:
        req = urllib.request.Request(f'https://{host}/gsma/rsp2/es9plus/initiateAuthentication',
                                     data=json.dumps(body).encode('utf-8'),
                                     headers=header)
        resp = urllib.request.urlopen(req, context=context)
    except:
        print(json.dumps({"status": "error"}))
    else:
        if resp.status // 200 != 1:
            print(json.dumps({"status": "error", "statuscode": resp.status}))
        if data := resp.read().decode('utf-8'):
            if cert := json.loads(data.replace(r'\n', '')).get('serverCertificate'):
                certificate = x509.load_der_x509_certificate(base64.b64decode(cert), default_backend())
                keyid = certificate.extensions.get_extension_for_oid(
                    x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier.hex()
                if keyid in cert_str:
                    print(json.dumps({"status": "success", "keyID": keyid, "cert": cert}))
                    if file_name:
                        open(file_name, 'wb').write(base64.b64decode(cert))
                else:
                    print(json.dumps({"status": "fail", "reason": "KeyIDMismatch", "keyID": keyid, "cert": cert}))
            else:
                print(json.dumps(
                    {"status": "fail", "reason": "CertNotFound", "response": json.loads(data).get('header')}))
        else:
            print(json.dumps({"status": "fail", "reason": "none"}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', required=True, help='服务器URL地址')
    parser.add_argument('-c', required=True, help='证书KI')
    parser.add_argument('-w', help='保存文件名')
    args = parser.parse_args()
    request_cert(args.s, args.c.lower(), args.w)
