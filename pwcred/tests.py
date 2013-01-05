import unittest

import bson
from pyramid import testing
import pyramid.httpexceptions as exc

from pwcred import security

from . import test_helpers as H
from . import views
from . import model as M

class ViewTests(unittest.TestCase):

    def setUp(self):
        self.config = testing.setUp()
        H.configure_app(self.config)
        self.key, self.pubkey = H.make_key()
        self.key_str = self.key.exportKey()
        self.prod_cli = H.make_client('prod-cli', self.pubkey, context='prod')
        self.test_cli = H.make_client('test-cli', self.pubkey, context='prod')
        H.make_credentials('pwcred', self.test_cli, a=1)
        H.make_credentials('pwcred', self.prod_cli, a=2)

    def tearDown(self):
        testing.tearDown()

    def test_creds_test(self):
        path = '/pwcred/'
        signed_params = security.sign_request(path, {}, self.test_cli._id, self.key_str)
        req = testing.DummyRequest(
            path='/pwcred/', params=signed_params, remote_addr='1.2.3.4',
            matchdict=dict(key='pwcred'))
        resp = views.get_creds(req)
        decrypted = M.decrypt_credentials(self.key_str, self.test_cli, **resp)
        self.assertEqual(decrypted, dict(a=1))
        
    def test_creds_prod(self):
        path = '/pwcred/'
        signed_params = security.sign_request(path, {}, self.prod_cli._id, self.key_str)
        req = testing.DummyRequest(
            path='/pwcred/', params=signed_params, remote_addr='1.2.3.4',
            matchdict=dict(key='pwcred'))
        resp = views.get_creds(req)
        decrypted = M.decrypt_credentials(self.key_str, self.test_cli, **resp)
        self.assertEqual(decrypted, dict(a=2))
        

class SecurityTests(unittest.TestCase):
    def setUp(self):
        H.configure_ming()
        self.key, self.pubkey = H.make_key()
        self.key_str = self.key.exportKey()
        self.client = H.make_client('cli', self.pubkey, ip_addrs=[ '1.2.3.4'] )

    def test_valid(self):
        path = '/a/b/c'
        params = dict(d=5, e=6)
        signed_params = security.sign_request(path, params, self.client['_id'], self.key_str)
        req = testing.DummyRequest(path=path, params=signed_params, remote_addr='1.2.3.4')
        client_doc = security.validate_request(req)
        self.assertEqual(client_doc['_id'], self.client['_id'])

    def test_bad_sig(self):
        path = '/a/b/c'
        params = dict(d=5, e=6)
        signed_params = security.sign_request(path, params, self.client['_id'], self.key_str)
        signed_params = dict(signed_params)
        signed_params['signature'] = 'badsig'
        req = testing.DummyRequest(path=path, params=signed_params, remote_addr='1.2.3.4')
        with self.assertRaises(exc.HTTPForbidden):
            security.validate_request(req)

    def test_bad_ip(self):
        path = '/a/b/c'
        params = dict(d=5, e=6)
        signed_params = security.sign_request(path, params, self.client['_id'], self.key_str)
        req = testing.DummyRequest(path=path, params=signed_params, remote_addr='1.2.3.5')
        with self.assertRaises(exc.HTTPForbidden):
            security.validate_request(req)
            
    def test_bad_path(self):
        path = '/a/b/c'
        params = dict(d=5, e=6)
        signed_params = security.sign_request(path, params, self.client['_id'], self.key_str)
        req = testing.DummyRequest(path=path + 'd/', params=signed_params, remote_addr='1.2.3.5')
        with self.assertRaises(exc.HTTPForbidden):
            security.validate_request(req)
            
    def test_no_sig(self):
        path = '/a/b/c'
        params = dict(d=5, e=6)
        signed_params = security.sign_request(path, params, self.client['_id'], self.key_str)
        signed_params = dict(signed_params)
        signed_params.pop('signature')
        req = testing.DummyRequest(path=path + 'd/', params=signed_params, remote_addr='1.2.3.5')
        with self.assertRaises(exc.HTTPBadRequest):
            security.validate_request(req)
            
    def test_no_client_id(self):
        path = '/a/b/c'
        params = dict(d=5, e=6)
        signed_params = security.sign_request(path, params, self.client['_id'], self.key_str)
        signed_params = dict(signed_params)
        signed_params.pop('client_id')
        req = testing.DummyRequest(path=path + 'd/', params=signed_params, remote_addr='1.2.3.5')
        with self.assertRaises(exc.HTTPBadRequest):
            security.validate_request(req)
            
    def test_bad_client(self):
        path = '/a/b/c'
        params = dict(d=5, e=6)
        signed_params = security.sign_request(path, params, self.client['_id'], self.key_str)
        signed_params = dict(signed_params)
        signed_params['client_id'] = bson.ObjectId()
        req = testing.DummyRequest(path=path + 'd/', params=signed_params, remote_addr='1.2.3.5')
        with self.assertRaises(exc.HTTPNotFound):
            security.validate_request(req)
            
