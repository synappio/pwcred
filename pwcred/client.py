import json
from urlparse import urljoin, urlparse

import requests

from . import security

class PWCredClient(object):

    def __init__(self, url, client_id, private_key):
        if not url.endswith('/'):
            url += '/'
        self._url = url
        self._client_id = client_id
        self._key = private_key
        
    def get(self, key):
        url = urljoin(self._url, key) + '/'
        pr = urlparse(url)
        params = security.sign_request(
            pr.path, {}, 
            self._client_id, self._key)
        response = requests.get(url, params=params)
        rjson = response.json()
        rjson = dict(
            (k, v.decode('base64'))
            for k,v in rjson.items())
        plaintext = security.decrypt(
            self._key,
            enc_aes_key=rjson['enc_aes_key'],
            aes_iv=rjson['aes_iv'],
            ciphertext=rjson['enc_creds'])
        return json.loads(security.unpad(plaintext))
