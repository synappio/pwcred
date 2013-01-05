import logging

from ming import collection, Field, Index, Session
from ming import schema as S

doc_session = Session.by_name('pwcred')

log = logging.getLogger(__name__)

client = collection(
    'pwcred.client', doc_session,
    Field('_id', S.ObjectId()),
    Field('ip_addrs', [ str ]),
    Field('context', str),
    Field('public_key', str))

credentials = collection(
    'pwcred.credentials', doc_session,
    Field('_id', S.ObjectId()),
    Field('key', str),
    Field('client_id', S.ObjectId()),
    Field('context', str),
    Field('creds', S.Binary()),
    Index('client_id', 'context', 'context', unique=True))
