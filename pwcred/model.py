import bson
import json
import logging

from ming import collection, Field, Index, Session
from ming import schema as S

from pwcred import security

doc_session = Session.by_name('pwcred')

log = logging.getLogger(__name__)

client = collection(
    'pwcred.client', doc_session,
    Field('_id', str),
    Field('ip_addrs', [ str ]),
    Field('context', str),
    Field('public_key', str))

credentials = collection(
    'pwcred.credentials', doc_session,
    Field('_id', S.ObjectId()),
    Field('key', str),
    Field('client_id', str),
    Field('enc_aes_key', S.Binary()),
    Field('aes_iv', S.Binary()),
    Field('enc_creds', S.Binary()),
    Index('client_id', 'key', unique=True))

def encrypt_credentials(client, key, **creds):
    plaintext = security.pad(json.dumps(credentials))
    enc_aes_key, aes_iv, enc_creds = security.encrypt(
        client.public_key, plaintext)
    creds = credentials.make(dict(
            key=key,
            client_id=client._id,
            aes_iv=bson.Binary(aes_iv),
            enc_aes_key=bson.Binary(enc_aes_key),
            enc_creds=bson.Binary(enc_creds)))
    return creds

def decrypt_credentials(prikey, client, enc_aes_key, aes_iv, enc_creds):
    plaintext = security.decrypt(
        prikey, enc_aes_key, aes_iv, enc_creds)
    return json.loads(security.unpad(plaintext))
    
