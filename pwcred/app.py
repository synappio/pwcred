import json
import subprocess

import yaml
import bson
from path import path

from pwcred import model as M
from pwcred import security

class Application(object):

    def __init__(self, args):
        self.args = args
        self.keyfile = args['--key']
        self.dburi = args['--dburi']
        self.dirname = args['--directory']

    def do_process(self, yamlfiles):
        for fn in yamlfiles:
            print 'Processing %s' % fn
            with open(path(fn).expand()) as fp:
                self._process(**yaml.load(fp))

    def do_add_client(self, client, context):
        # Generate keys if they don't exist
        keyfile = self._keyfile(client)
        if not keyfile.exists():
            subprocess.check_call(
                ['ssh-keygen', '-f', keyfile, '-P', '', '-b', '2048', '-q', '-C', client])
            print 'Created keypair in %s' % keyfile
        pubkeyfile = keyfile + '.pub'
        with pubkeyfile.open('rb') as fp:
            M.client.m.collection.update(
                dict(_id=client),
                {'$set': dict(context=context, public_key=fp.read()) },
                upsert=True)
        print 'Created client %s with context %s' % (client, context)

    def do_list_clients(self):
        fmt = '%20.20s %20.20s'
        print fmt % ('Name', 'Context')
        print fmt % ('-'*20, '-'*20)
        for cli in M.client.m.find():
            print fmt % (cli._id, cli.context)

    def do_client_read(self, client, key):
        creds = M.credentials.m.get(key=key, client_id=client)
        if not creds:
            print 'No such client registered for that key'
            return
        keyfile = self._keyfile(client)
        if keyfile is None:
            print '<Enc %r>' % creds.enc_creds
            return
        with path(keyfile).open() as fp:
            plaintext = security.decrypt(
                fp.read(), creds.enc_aes_key, creds.aes_iv, creds.enc_creds)
            data = json.loads(security.unpad(plaintext))
            for k,v in sorted(data.items()):
                print '%s=%s' % (k,v)

    def do_client_delete(self, client):
        M.client.m.remove({'_id': client})
        M.credentials.m.remove({'client_id': client})

    def _process(self, key, **contexts):
        print '... key: ' + key
        for context, creds in contexts.items():
            print '...... context: ' + context
            plain_cred_data = json.dumps(creds)
            plaintext = security.pad(plain_cred_data)
            for cli in M.client.m.find(dict(context=context)):
                enc_aes_key, aes_iv, ciphertext = security.encrypt(cli.public_key, plaintext)
                M.credentials.m.collection.update(
                    dict(key=key, client_id=cli._id),
                    {'$set': dict(
                            enc_aes_key=bson.Binary(enc_aes_key),
                            aes_iv=bson.Binary(aes_iv),
                            enc_creds=bson.Binary(ciphertext)
                            )
                     },
                    upsert=True)


    def _keyfile(self, client):
        keyfile = self.args['--key']
        if keyfile is None:
            keyfile = (path(self.args['--directory']) / client).expand()
        return keyfile

