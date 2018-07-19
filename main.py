import webapp2
import logging
import os
import httplib2
import json
import base64
from collections import OrderedDict
from google.appengine.ext import ndb
from google.appengine.api import app_identity, urlfetch

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Util import number

DIRECTORY_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'

ALG2KEYTYPE = {
  'RS256': 'RSA'
}

def b64u_en(s):
  return base64.urlsafe_b64encode(s).rstrip('=')

class Configuration(ndb.Model):
  created = ndb.DateTimeProperty(auto_now_add=True)
  modified = ndb.DateTimeProperty(auto_now=True)
  directory = ndb.TextProperty(default=DIRECTORY_STAGING, choices=[DIRECTORY_STAGING, DIRECTORY])
  keysize = ndb.IntegerProperty(default=2048, choices=[2048])
  key = ndb.BlobProperty()
  alg = ndb.TextProperty(default='RS256', choices=['RS256'])
  account = ndb.TextProperty()
  domains = ndb.TextProperty(repeated=True)
configuration_key = ndb.Key('Configuration', 'configuration')

class ACME():
  def __init__(self, configuration):
    logging.info('ACME init')

    self.alg = configuration.alg
    self.key = RSA.importKey(configuration.key)
    self.signer = PKCS1_v1_5.new(self.key)

    # https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.1.1
    directory_req = urlfetch.fetch(configuration.directory)
    logging.debug('{} returned HTTP code {}: {}'.format(configuration.directory, directory_req.status_code, directory_req.content))
    if directory_req.status_code != 200:
      raise RuntimeError('DIRECTORY URL served HTTP code {}'.format(str(directory_req.status_code)))
    try:
      self.directory = json.loads(directory_req.content)
    except ValueError as e:
      raise RuntimeError('DIRECTORY URL served invalid JSON')
    for key in ('newNonce', 'newAccount', 'newOrder'):
      if not key in self.directory:
        raise RuntimeError('DIRECTORY JSON missing key {}'.format(key))

    # https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-6.4
    nonce_req = urlfetch.fetch(url=self.directory['newNonce'], method=urlfetch.HEAD)
    self.nonce = nonce_req.headers['replay-nonce']
    logging.debug('Nonce initialised: {}'.format(self.nonce))

    if not configuration.account:
      account_req = self.request('newAccount', { 'termsOfServiceAgreed': True })
      if account_req.status_code >= 400:
        raise RuntimeError('newAccount returned HTTP code {}'.format(str(account_req.status_code)))
      configuration.account = account_req.headers['location']
      configuration.put()
    self.account = configuration.account

    logging.debug('ACME account: {}'.format(self.account))

  def request(self, key, payload):
    logging.info('ACME request({}, {})'.format(key, payload))

    if not key in self.directory:
      raise AssertionError

    return self.fetch(self.directory[key], payload)

  def fetch(self, url, payload):
    logging.info('ACME fetch({}, {})'.format(url, payload))

    # https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-6.2
    protected = {
       'alg': self.alg,
       'nonce': self.nonce,
       'url': url
    }
    if hasattr(self, 'account'):
      protected['kid'] = self.account
    else:
      # https://tools.ietf.org/html/rfc7638#section-3.2
      protected['jwk'] = OrderedDict([
         ('e', b64u_en(number.long_to_bytes(self.key.e))),
         ('kty', ALG2KEYTYPE[self.alg]),
         ('n', b64u_en(number.long_to_bytes(self.key.n)))
      ])
    protected_b64u = b64u_en(json.dumps(protected))

    payload_b64u = b64u_en(json.dumps(payload))

    hash = SHA256.new(protected_b64u + '.' + payload_b64u)
    signature_b64u = b64u_en(self.signer.sign(hash))

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

class GAELE_BaseHandler(webapp2.RequestHandler):
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

class GAELE_StartHandler(GAELE_BaseHandler):
  def get(self):
    super(GAELE_StartHandler, self).get()

    configuration = configuration_key.get()
    if not configuration:
      logging.info('Configuration init')
      configuration = Configuration(id=configuration_key.id(), domains=['example.com'])
      configuration.put()

    if not configuration.key:
      if configuration.alg != 'RS256':
        raise RuntimeError('unsupported alg: {}'.format(configuration.alg))

      key = RSA.generate(configuration.keysize)
      configuration.key = key.exportKey()
      configuration.put()

    self.response.set_status(204)

class GAELE_NOPHandler(GAELE_BaseHandler):
  def get(self):
    super(GAELE_NOPHandler, self).get()

    self.response.set_status(204)

class GAELE_CronHandler(GAELE_BaseHandler):
  def get(self):
    super(GAELE_CronHandler, self).get()

    if not 'x-appengine-cron' in self.request.headers:
      self.response.set_status(403)
      return

    self.response.write('le cron')

class GAELE_ChallengeHandler(GAELE_BaseHandler):
  def get(self):
    super(GAELE_ChallengeHandler, self).get()

    configuration = configuration_key.get()

    acme = ACME(configuration)
    neworder_req = acme.request('newOrder', {
      'identifiers': [{
        'type': 'dns',
        'value': domain
      } for domain in configuration.domains]
    })
    if neworder_req.status_code != 201:
      raise RuntimeError('newOrder returned HTTP code {}'.format(str(neworder_req.status_code)))
    neworder = json.loads(neworder_req.content)
    if not 'authorizations' in neworder:
      raise RuntimeError('newOrder returned no authorizations')

#    authz_req = acme.fetch(neworder['authorizations'][0], {
#      'identifier': {
#        'type': 'dns',
#        'value': domain
#      }
#    })

    self.response.write('le')

app = webapp2.WSGIApplication([
  (r'^/_ah/start$', GAELE_StartHandler),
  (r'^/_ah/.*$', GAELE_NOPHandler),
  (r'^/cron$', GAELE_CronHandler),
  (r'^/\.well-known/acme-challenge/.*$', GAELE_ChallengeHandler),
], debug=True)
