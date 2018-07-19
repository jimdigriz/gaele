import webapp2
import logging
import os
import httplib2
import json
import base64
from collections import OrderedDict
import cloudstorage as gcs
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

rsa = None
signer = None

def b64u_en(s):
  return base64.urlsafe_b64encode(s).rstrip('=')

acct = None
class ACME():
  def __init__(self):
    logging.info('ACME init')

    # https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.1.1
    directory_url = os.environ.get('DIRECTORY')
    if not directory_url:
      raise RuntimeError('missing DIRECTORY env')
    directory_req = urlfetch.fetch(directory_url)
    logging.debug('{} returned HTTP code {}: {}'.format(directory_url, directory_req.status_code, directory_req.content))
    if directory_req.status_code != 200:
      raise RuntimeError('DIRECTORY URL served HTTP code {}'.format(str(directory_req.status_code)))
    try:
      self.directory = json.loads(directory_req.content)
    except ValueError as e:
      raise RuntimeError('DIRECTORY URL served invalid JSON')
    for key in ('newNonce', 'newAccount', 'newOrder'):
      if not key in self.directory: raise RuntimeError('DIRECTORY JSON missing key {}'.format(key))

    # https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-6.4
    nonce_req = urlfetch.fetch(url=self.directory['newNonce'], method=urlfetch.HEAD)
    self.nonce = nonce_req.headers['replay-nonce']
    logging.debug('Nonce initialised: {}'.format(self.nonce))

    acct_req = self.request('newAccount', { 'termsOfServiceAgreed': True })
    if acct_req.status_code >= 400:
      raise RuntimeError('newAccount returned HTTP code {}'.format(str(acct_req.status_code)))
    self.acct = acct_req.headers['location']

    logging.debug('newAccount returned: {}'.format(self.acct))

  def request(self, key, payload):
    logging.info('ACME request({}, {})'.format(key, payload))

    if not key in self.directory:
      raise AssertionError

    return self.fetch(self.directory[key], payload)

  def fetch(self, url, payload):
    logging.info('ACME fetch({}, {})'.format(url, payload))

    # https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-6.2
    protected = {
       'alg': 'RS256',
       'nonce': self.nonce,
       'url': url
    }
    if hasattr(self, 'acct'):
      protected['kid'] = self.acct
    else:
      # https://tools.ietf.org/html/rfc7638#section-3.2
      protected['jwk'] = OrderedDict([
         ('e', b64u_en(number.long_to_bytes(rsa.e))),
         ('kty', 'RSA'),
         ('n', b64u_en(number.long_to_bytes(rsa.n)))
      ])
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

    self.nonce = result.headers['replay-nonce']

    logging.debug('ACME fetch({}, {}): {}'.format(url, payload, json.dumps(OrderedDict([
      ('code', result.status_code),
      ('headers', dict(result.headers)),
      ('content', result.content)
    ]))))

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

class LE_start(BaseHandler):
  def get(self):
    global rsa, signer

    super(LE_start, self).get()

    rsa_filename = '/' + bucket + '/gaele.rsa'
    try:
      rsa_file = gcs.open(rsa_filename)
      rsa = RSA.importKey(rsa_file.read())
      rsa_file.close()

      logging.info('RSA loaded')
    except gcs.NotFoundError as e:
      rsa = RSA.generate(keysize)
      rsa_file = gcs.open(rsa_filename, 'w')
      rsa_file.write(rsa.exportKey())
      rsa_file.close()

      logging.info('RSA generated')

    signer = PKCS1_v1_5.new(rsa)

    self.response.set_status(204)

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

    acme = ACME()
    neworder_req = acme.request('newOrder', {
      'identifiers': [
        {
          'type': 'dns',
          'value': domain
        }
      ]
    })
    if neworder_req.status_code != 201:
      raise RuntimeError('newOrder returned HTTP code {}'.format(str(neworder_req.status_code)))
    neworder = json.loads(neworder_req.content)
    if not 'authorizations' in neworder:
      raise RuntimeError('newOrder returned no authorizations')

    authz_req = acme.fetch(neworder['authorizations'][0], {
      'identifier': {
        'type': 'dns',
        'value': domain
      }
    })

    self.response.write('le')

app = webapp2.WSGIApplication([
  (r'^/_ah/start$', LE_start),
  (r'^/_ah/.*$', LE_noop),
  (r'^/cron$', LE_cron),
  (r'^/\.well-known/acme-challenge/.*$', LE),
], debug=True)
