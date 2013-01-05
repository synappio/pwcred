import json

import bson
import ming.mim
from Crypto.PublicKey import RSA

from pwcred import model as M
from pwcred.main import add_routes
from pwcred import security

def configure_app(config):
    configure_ming()
    add_routes(config)

def configure_ming():
    ming.config.configure_from_nested_dict(dict(
            pwcred=dict(uri='mim://')))
    ming.mim.Connection.get().clear_all()
    
def make_client(name, pubkey, **kwargs):
    pubkey_str = pubkey.exportKey()
    client = M.client.make(dict(_id=name, public_key=pubkey_str, **kwargs))
    client.m.save()
    return client

def make_key():
    key = RSA.generate(1024)
    return key, key.publickey()
        
def make_credentials(key, client, **creds):
    plaintext = security.pad(json.dumps(creds))
    enc_aes_key, aes_iv, enc_creds = security.encrypt(client.public_key, plaintext)
    creds = M.credentials.make(dict(
            key=key,
            client_id=client._id,
            aes_iv=bson.Binary(aes_iv),
            enc_aes_key=bson.Binary(enc_aes_key),
            enc_creds=bson.Binary(enc_creds)))
    creds.m.save()
    return creds
