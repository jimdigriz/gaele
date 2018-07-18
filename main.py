import webapp2
import logging
import os
import httplib2
import json
import base64
import cloudstorage as gcs
from collections import OrderedDict
from google.appengine.api import memcache, app_identity, urlfetch
from oauth2client.contrib.appengine import AppAssertionCredentials

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Util import number

# https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html

def b64u_en (s):
    return base64.urlsafe_b64encode(s).rstrip('=')

rsa = None
nonce = None
acct = None
def acme (url, payload):
    global nonce

    protected = {
       'alg': 'RS256',
       'nonce': nonce,
       'url': url
    }
    if acct:
        protected['kid'] = acct
    else:
        protected['jwk'] = {
           'e': b64u_en(number.long_to_bytes(rsa.e)),
           'kty': 'RSA',
           'n': b64u_en(number.long_to_bytes(rsa.n))
        }
    protected_b64u = b64u_en(json.dumps(protected))

    payload_b64u = b64u_en(json.dumps(payload))

    hash = SHA256.new(protected_b64u + '.' + payload_b64u)
    signature_b64u = b64u_en(signer.sign(hash))

    payload = json.dumps({
       'protected': protected_b64u,
       'payload': payload_b64u,
       'signature': signature_b64u
    })

    result = urlfetch.fetch(
        method=urlfetch.POST,
        headers={
            'content-type': 'application/jose+json'
        },
        url=url,
        payload=payload
    )

    nonce = result.headers['replay-nonce']

    logging.debug(json.dumps({
        'url': url,
        'payload': payload,
        'result': {
            'code': result.status_code,
            'headers': dict(result.headers),
            'content': result.content
        }
    }))

    return result

request_log_id = os.environ.get('REQUEST_LOG_ID')
keysize = int(os.environ.get('KEYSIZE', '2048'))

bucket = os.environ.get('BUCKET', app_identity.get_default_gcs_bucket_name())

#credentials = AppAssertionCredentials(scope='https://www.googleapis.com/auth/cloud-platform')
#http = credentials.authorize(httplib2.Http(memcache))

domain = os.environ.get('DOMAIN')

discovery_req = urlfetch.fetch(os.environ.get('DISCOVERY'))
discovery = json.loads(discovery_req.content)

nonce_init = urlfetch.fetch(url=discovery['newNonce'], method=urlfetch.HEAD)
nonce = nonce_init.headers['replay-nonce']

rsa_filename = '/' + bucket + '/le.rsa'
try:
    rsa_file = gcs.open(rsa_filename)
    rsa = RSA.importKey(rsa_file.read())
    rsa_file.close()
except gcs.NotFoundError as e:
    rsa = RSA.generate(keysize)
    rsa_file = gcs.open(rsa_filename, 'w')
    rsa_file.write(rsa.exportKey())
    rsa_file.close()
signer = PKCS1_v1_5.new(rsa)

newacct = acme(discovery['newAccount'], { 'termsOfServiceAgreed': True })
acct = newacct.headers['location']

neworder = acme(discovery['newOrder'], {
    'identifiers': [
        {
            'type': 'dns',
            'value': domain
        }
    ]
})
neworder_content = json.loads(neworder.content)

authz = acme(neworder_content['authorizations'][0], {
    'identifier': {
        'type': 'dns',
        'value': domain
    }
})

class LE(webapp2.RequestHandler):
    def get(self):
        self.response.write('request log id: {}\n'.format(request_log_id))

app = webapp2.WSGIApplication([
    (os.environ.get('LE_PATH', '/'), LE),
], debug=True)
