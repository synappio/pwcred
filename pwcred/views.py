from pyramid.view import view_config

from . import security
from . import model as M

@view_config(route_name='creds', renderer='json', request_method='GET')
def get_creds(request):
    client_doc = security.validate_request(request)
    doc = M.credentials.m.get(
        key=request.matchdict['key'],
        context=client_doc.context)
    return doc.creds
