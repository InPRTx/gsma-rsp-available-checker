import argparse
import base64
import json
import os
import re

import urllib3

http = urllib3.PoolManager(cert_reqs='CERT_NONE')
urllib3.disable_warnings()


def get_euicc_info(cert_str: str) -> str:
    a = b'\xBF\x20\x35\x82\x03\x02\x02\x00\xA9\x16\x04\x14' + bytes.fromhex(
        cert_str) + b'\xaa\x16\x04\x14' + bytes.fromhex(cert_str)
    return base64.encodebytes(a).decode().strip()


def gen_random_challenge() -> str:
    return base64.b64encode(os.urandom(16)).decode().strip()


def get_url_data(host: str, cert_str: str, file_name: str | None):
    data = {"smdpAddress": host, "euiccChallenge": gen_random_challenge(),
            "euiccInfo1": get_euicc_info(cert_str)}
    headers = {'User-Agent': 'curl/7.88.1',
               'Content-Type': 'application/json'}
    try:
        r = http.request('POST', f'https://{host}/gsma/rsp2/es9plus/initiateAuthentication', body=json.dumps(data),
                         headers=headers)
    except:
        print({'status': 'error'})
    else:
        if r.status // 200 != 1:
            print({'status': 'error'})
        if output_str := r.json().get('serverCertificate'):
            print({'status': 'success', 'cert': output_str})
            if file_name:
                open(file_name, 'wb').write(base64.b64decode(output_str))
        else:
            print(json.dumps({"status": "fail"}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', help='服务器URL地址')
    parser.add_argument('-c', help='证书名')
    parser.add_argument('-w', help='保存文件名')
    args = parser.parse_args()
    if not re.match(r'^[0-9a-f]{40}$', args.c):
        raise ValueError('证书大概应为40位0-f')
    get_url_data(args.s, args.c, args.w)
