import logging

import bson
import pyramid.httpexceptions as exc
from pyramid.url import urlencode
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from . import model as M

log = logging.getLogger(__name__)

def validate_request(request):
    '''Either returns (client, params) or raises a 403'''
    params = dict(request.params)
    try:
        signature_str = params.pop('signature')
        client_id = params['client_id']
        client = M.client.m.get(_id=bson.ObjectId(client_id))
        if not client:
            raise exc.HTTPNotFound()
        to_sign = request.path + '?' + urlencode(sorted(params.items()))
        if not _signature_is_valid(to_sign, signature_str, client.public_key):
            raise exc.HTTPForbidden()
        if request.remote_addr not in client.ip_addrs:
            raise exc.HTTPForbidden()
        return client
    except exc.HTTPError:
        raise
    except KeyError, ke:
        raise exc.HTTPBadRequest, repr(ke)
    except:
        log.exception('Error validating request: %r', params)
        raise exc.HTTPForbidden()

def sign_request(path, params, client_id, private_key_str):
    '''Returns signature field as a hex string'''
    if isinstance(params, dict):
        params = params.items()
    params.append( ('client_id', client_id) )
    params.sort()
    to_sign = path + '?' + urlencode(params)
    hash = SHA256.new(to_sign).digest()
    key = RSA.importKey(private_key_str)
    signature = key.sign(hash, '')
    signature_str = '%x' % signature[0]
    return params + [ ('signature', signature_str) ]
    
def _signature_is_valid(plaintext, signature_str, public_key_str):
    hash = SHA256.new(plaintext).digest()
    sig_long = long(signature_str, 16)
    key = RSA.importKey(public_key_str)
    signature = sig_long, ''
    return key.verify(hash, signature)
