from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import urllib.request

context = ssl._create_unverified_context()


def get_euicc_info(cert_str: str) -> str:
    a = b'\xBF\x20\x35\x82\x03\x02\x02\x00\xA9\x16\x04\x14' + bytes.fromhex(
        cert_str) + b'\xaa\x16\x04\x14' + bytes.fromhex(cert_str)
    return base64.encodebytes(a).decode().strip()


def gen_random_challenge() -> str:
    return base64.b64encode(os.urandom(16)).decode().strip()


def get_url_data(host: str, cert_str: str, file_name: str | None):
    data = {"smdpAddress": host, "euiccChallenge": gen_random_challenge(),
            "euiccInfo1": get_euicc_info(cert_str)}
    headers = {'Content-Type': 'application/json',
               'User-Agent': 'gsma-rsp-lpad',
               'X-Admin-Protocol': 'gsma/rsp/v2.2.0'}

    try:
        req = urllib.request.Request(f'https://{host}/gsma/rsp2/es9plus/initiateAuthentication',
                                     data=json.dumps(data).encode('utf-8'),
                                     headers=headers)
        r = urllib.request.urlopen(req, context=context)
    except:
        print(json.dumps({"status": "error"}))
    else:
        if r.status // 200 != 1:
            print(json.dumps({"status": "error"}))
        if output_str := json.loads(r.read().decode('utf-8')).get('serverCertificate'):
            print(json.dumps({"status": "success", "cert": output_str}))
            if file_name:
                open(file_name, 'wb').write(base64.b64decode(output_str))
        else:
            print(json.dumps({"status": "fail"}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', help='服务器URL地址')
    parser.add_argument('-c', help='证书KI')
    parser.add_argument('-w', help='保存文件名')
    args = parser.parse_args()
    if not re.match(r'^[0-9a-fA-F]{40}$', args.c):
        raise ValueError('证书应为40位0-f或0-F')
    get_url_data(args.s, args.c.lower(), args.w)
