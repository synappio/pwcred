import ming.mim

from Crypto.PublicKey import RSA

from pwcred import model as M
from pwcred.main import add_routes

def configure_app(config):
    configure_ming()
    add_routes(config)

def configure_ming():
    ming.config.configure_from_nested_dict(dict(
            pwcred=dict(uri='mim://')))
    ming.mim.Connection.get().clear_all()
    
def make_client(pubkey, **kwargs):
    pubkey_str = pubkey.exportKey()
    client = M.client.make(dict(public_key=pubkey_str, **kwargs))
    client.m.save()
    return client

def make_key():
    key = RSA.generate(1024)
    return key, key.publickey()
        
def make_credentials(key, context, **creds):
    creds = M.credentials.make(dict(key=key, context=context, creds=creds))
    creds.m.save()
    return creds
