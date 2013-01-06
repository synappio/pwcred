import struct
import logging

import pyramid.httpexceptions as exc
from pyramid.url import urlencode

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import PKCS1_PSS

log = logging.getLogger(__name__)

def sign_request(path, params, client_id, private_key_str):
    '''Returns signature field as a hex string'''
    if isinstance(params, dict):
        params = params.items()
    params.append( ('client_id', client_id) )
    params.sort()
    to_sign = path + '?' + urlencode(params)
    print 'Signing', to_sign
    hash = SHA256.new(to_sign)
    key = RSA.importKey(private_key_str)
    signer = PKCS1_PSS.new(key)
    signature = signer.sign(hash).encode('base64').strip()
    return params + [ ('signature', signature) ]
    
def validate_request(request):
    '''Either returns (client, params) or raises a 403'''
    from . import model as M

    params = dict(request.params)
    try:
        signature_str = params.pop('signature')
        client_id = params['client_id']
        client = M.client.m.get(_id=client_id)
        if not client:
            raise exc.HTTPNotFound()
        to_sign = request.path + '?' + urlencode(sorted(params.items()))
        print 'Validate', to_sign
        if not signature_is_valid(to_sign, signature_str, client.public_key):
            raise exc.HTTPForbidden()
        if client.ip_addrs and request.remote_addr not in client.ip_addrs:
            raise exc.HTTPForbidden()
        return client
    except exc.HTTPError:
        raise
    except KeyError, ke:
        raise exc.HTTPBadRequest, repr(ke)
    except:
        log.exception('Error validating request: %r', params)
        raise exc.HTTPForbidden()

def signature_is_valid(plaintext, signature, public_key_str):
    hash = SHA256.new(plaintext)
    key = RSA.importKey(public_key_str)
    signer = PKCS1_PSS.new(key)
    return signer.verify(hash, signature.decode('base64'))

def pad(text, factor=16):
    length = len(text) + 4
    slength = struct.pack('<L', length)
    padding_nbytes = 16 - (length % 16)
    padding = (padding_nbytes % 16) * ' '
    return slength + text + padding

def unpad(text):
    length = struct.unpack('<L', text[:4])[0]
    return text[4:length]

def encrypt(pubkey_text, plaintext):
    # Generate an AES key & IV to use for the encryption
    aes_key = Random.get_random_bytes(32)
    aes_iv = Random.get_random_bytes(16)
    aes = AES.new(aes_key, mode=AES.MODE_CBC, IV=aes_iv)

    # Actually encrypt the plaintext + padding
    padding_nbytes = 16 - (len(plaintext) % 16)
    padding = (padding_nbytes % 16) * ' '
    ciphertext = aes.encrypt(plaintext + padding)

    # Now, encrypt the aes_key with the RSA public key
    rsa_key = RSA.importKey(pubkey_text)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    # Finally, return the enc_aes_key, aes_iv, and encrypted credentials
    return enc_aes_key, aes_iv, ciphertext

def decrypt(prikey_text, enc_aes_key, aes_iv, ciphertext):
    # Decrypt the aes_key with the RSA private key
    rsa_key = RSA.importKey(prikey_text)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    # Decrypt the enc_creds and padding
    aes = AES.new(aes_key, mode=AES.MODE_CBC, IV=aes_iv)
    return aes.decrypt(ciphertext)
