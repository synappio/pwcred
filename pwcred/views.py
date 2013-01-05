from pyramid.view import view_config

from . import security
from . import model as M

@view_config(route_name='creds', renderer='json', request_method='GET')
def get_creds(request):
    import pdb; pdb.set_trace()
    client_doc = security.validate_request(request)
    doc = M.credentials.m.get(
        client_id=client_doc._id,
        key=request.matchdict['key'])
    return dict(enc_aes_key=doc.enc_aes_key.encode('base64').strip(),
                aes_iv=doc.aes_iv.encode('base64').strip(),
                enc_creds=doc.enc_creds.encode('base64').strip())
