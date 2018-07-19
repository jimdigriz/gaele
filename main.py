import webapp2
import logging
import os
import httplib2
import json
import base64
import cloudstorage as gcs
from collections import OrderedDict
from google.appengine.api import memcache, app_identity, urlfetch
#from oauth2client.contrib.appengine import AppAssertionCredentials

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Util import number

#credentials = AppAssertionCredentials(scope='https://www.googleapis.com/auth/cloud-platform')
#http = credentials.authorize(httplib2.Http(memcache))

bucket = os.environ.get('BUCKET', app_identity.get_default_gcs_bucket_name())
keysize = int(os.environ.get('KEYSIZE', '2048'))
domain = os.environ.get('DOMAIN')

def b64u_en (s):
  return base64.urlsafe_b64encode(s).rstrip('=')

def pubkey (s):
  if not hasattr(pubkey, 'key'):
    rsa_filename = '/' + bucket + '/le.rsa'
    try:
      rsa_file = gcs.open(rsa_filename)
      pubkey.key = RSA.importKey(rsa_file.read())
      rsa_file.close()
    except gcs.NotFoundError as e:
      pubkey.key = RSA.generate(keysize)
      rsa_file = gcs.open(rsa_filename, 'w')
      rsa_file.write(key.exportKey())
      rsa_file.close()
    pubkey.e = pubkey.key.e
    pubkey.n = pubkey.key.n
    pubkey.signer = PKCS1_v1_5.new(pubkey.key)
  return getattr(pubkey, s)

def discovery (s):
  if not hasattr(discovery, 'data'):
    discovery_url = os.environ.get('DISCOVERY')
    if not discovery_url:
      raise RuntimeError('missing DISCOVERY env')
    discovery_req = urlfetch.fetch(discovery_url)
    if discovery_req.status_code != 200:
      raise RuntimeError('HTTP code {} fetching DISCOVERY URL'.format(str(discovery_req.status_code)))
    try:
      discovery.data = json.loads(discovery_req.content)
    except ValueError as e:
      raise RuntimeError('Invalid JSON from DISCOVERY URL')
  return discovery.data[s]

nonce = None
acct = None
def acme (url, payload):
  global nonce
  if not nonce:
    nonce_req = urlfetch.fetch(url=discovery('newNonce'), method=urlfetch.HEAD)
    nonce = nonce_req.headers['replay-nonce']

  protected = {
     'alg': 'RS256',
     'nonce': nonce,
     'url': url
  }
  if acct:
    protected['kid'] = acct
  else:
    protected['jwk'] = {
       'e': b64u_en(number.long_to_bytes(pubkey('e'))),
       'kty': 'RSA',
       'n': b64u_en(number.long_to_bytes(pubkey('n')))
    }
  protected_b64u = b64u_en(json.dumps(protected))

  payload_b64u = b64u_en(json.dumps(payload))

  hash = SHA256.new(protected_b64u + '.' + payload_b64u)
  signature_b64u = b64u_en(pubkey('signer').sign(hash))

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

class BaseHandler(webapp2.RequestHandler):
  def get(self):
    self.response.headers['x-request-log-id'] = os.environ.get('REQUEST_LOG_ID')

  def handle_exception(self, exception, debug):
    # Log the error.
    logging.exception(exception)

    # If the exception is a HTTPException, use its error code.
    # Otherwise use a generic 500 error code.
    if isinstance(exception, webapp2.HTTPException):
        self.response.set_status(exception.code)
    else:
        self.response.set_status(500)

class LE_noop(BaseHandler):
  def get(self):
    super(LE_noop, self).get()
    self.response.set_status(204)

class LE_cron(BaseHandler):
  def get(self):
    super(LE_cron, self).get()

    if not 'x-appengine-cron' in self.request.headers:
      self.response.set_status(403)
      return

    self.response.write('le cron')

class LE(BaseHandler):
  def get(self):
    super(LE, self).get()
   
    newacct = acme(discovery('newAccount'), { 'termsOfServiceAgreed': True })
    acct = newacct.headers['location']
    
    neworder = acme(discovery('newOrder'), {
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

    self.response.write('le')

app = webapp2.WSGIApplication([
  (r'^/_ah/.*$', LE_noop),
  (r'^/cron$', LE_cron),
  (r'^/.*$', LE),
], debug=True)
