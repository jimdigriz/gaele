import webapp2
import logging
import os
import json
import base64
import binascii
import uuid
from functools import partial
from datetime import datetime, timedelta
from collections import OrderedDict
from google.appengine.ext import ndb
from google.appengine.api import urlfetch, namespace_manager, app_identity
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Util import number
from pyasn1.type import univ, char
from pyasn1_modules import pem, rfc2314, rfc2459, rfc2986
from pyasn1.codec.native.decoder import decode as native_decoder
from pyasn1.codec.native.encoder import encode as native_encoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.codec.der.decoder import decode as der_decoder

DIRECTORY_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'

KEYSIZE = 2048
ALG = 'RS256'
KEYTYPE = 'RSA'

def b64u_en(s):
  return base64.urlsafe_b64encode(s).rstrip('=')

class Configuration(ndb.Model):
  _default_indexed = False
  token = ndb.StringProperty(default=str(uuid.uuid4()), required=True, indexed=False)
  directory = ndb.TextProperty(default=DIRECTORY_STAGING, required=True)
  key = ndb.TextProperty()
  project = ndb.StringProperty(default=app_identity.get_application_id(), required=True, indexed=False)
  # we have to use 'default' otherwise the dev appserver refuses to let you update
  loadbalancer = ndb.StringProperty(default='', indexed=False)
  domains = ndb.TextProperty(default='', required=True)

  def domains_to_list(self):
    return map(unicode.strip, self.domains.split('\n'))
  domains_list = property(domains_to_list)
#namespace_manager.set_namespace('gaele')
configuration_key = ndb.Key('Configuration', 'configuration')

class ACME():
  def __init__(self, configuration):
    logging.info('ACME init')

    self.key = RSA.importKey(configuration.key)
    self.signer = PKCS1_v1_5.new(self.key)

    # https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.1.1
    directory_req = urlfetch.fetch(configuration.directory)
    logging.debug('ACME {} returned HTTP code {}: {}'.format(configuration.directory, directory_req.status_code, directory_req.content))
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
    logging.debug('ACME nonce initialised: {}'.format(self.nonce))

    # done here and not in StartHandler as it would make changing `directory`/`key` difficult
    account_req = self.request('newAccount', { 'termsOfServiceAgreed': True })
    if account_req.status_code >= 400:
      raise RuntimeError('newAccount returned HTTP code {}'.format(str(account_req.status_code)))
    configuration.account = account_req.headers['location']
    configuration.put()
    logging.info('ACME newAccount: {}'.format(configuration.account))
    self.account = configuration.account

  def request(self, key, payload):
    logging.info("ACME request('{}', '{}')".format(key, payload))

    if not key in self.directory:
      raise AssertionError

    return self.fetch(self.directory[key], payload)

  def fetch(self, url, payload):
    logging.info("ACME fetch('{}', '{}')".format(url, payload))

    # https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-6.2
    protected = {
       'alg': 'RS256',
       'nonce': self.nonce,
       'url': url
    }
    if hasattr(self, 'account'):
      protected['kid'] = self.account
    else:
      # https://tools.ietf.org/html/rfc7638#section-3.2
      protected['jwk'] = OrderedDict([
         ('e', b64u_en(number.long_to_bytes(self.key.e))),
         ('kty', KEYTYPE),
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

    logging.debug('ACME fetch: {}'.format(json.dumps(OrderedDict([
      ('code', result.status_code),
      ('headers', dict(result.headers)),
      ('content', result.content)
    ]))))

    return result

# https://github.com/jandd/python-pkiutils
def csr(configuration):
  id_at_pkcs9_extension_request = univ.ObjectIdentifier('1.2.840.113549.1.9.14')
  sha256WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.11')

  key = RSA.importKey(configuration.key)
  signer = PKCS1_v1_5.new(key)

  py_csr = {
    'certificationRequestInfo': {
      'version': 0,
      'subject': {
        'rdnSequence': [
          [
            {
              'type': rfc2459.id_at_commonName,
              'value': der_encoder(char.UTF8String(configuration.domains_list[0]))
            }
          ]
        ]
      },
      'subjectPKInfo': native_encoder(der_decoder(key.publickey().exportKey('DER'), rfc2314.SubjectPublicKeyInfo())[0]),
      'attributes': [
        {
          'type': id_at_pkcs9_extension_request,
          'values': [
            der_encoder(native_decoder([
              {
                'extnID': rfc2459.id_ce_subjectAltName,
                'extnValue': der_encoder(native_decoder(map(lambda x: { 'dNSName': x }, configuration.domains_list), asn1Spec=rfc2314.SubjectAltName()))
              }
            ], asn1Spec=rfc2314.Extensions()))
          ]
        }
      ]
    }
  }
  py_csr['signatureAlgorithm'] = {
    'algorithm': sha256WithRSAEncryption
  }
  hashvalue = SHA256.new(der_encoder(native_decoder(py_csr['certificationRequestInfo'], rfc2986.CertificationRequestInfo())))
  py_csr['signature'] = bin(int(binascii.hexlify(signer.sign(hashvalue)), 16))

  csr = native_decoder(py_csr, asn1Spec=rfc2986.CertificationRequest())

  csr_der = der_encoder(csr)
  csr_der_b64 = base64.b64encode(csr_der)

  csr_pem = '-----BEGIN CERTIFICATE REQUEST-----\n'
  csr_pem += '\n'.join([ csr_der_b64[i: i + 64] for i in range(0, len(csr_der_b64), 64) ]) + '\n'
  csr_pem += '-----END CERTIFICATE REQUEST-----\n'

  return csr_pem

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

    code = 204

    configuration = configuration_key.get(use_cache=False, use_memcache=False)
    if not configuration:
      logging.info('configuration init')
      configuration = Configuration(id=configuration_key.id())
      configuration.put()
      code = 201

    if not configuration.key:
      key = RSA.generate(KEYSIZE)
      configuration.key = key.exportKey('PEM')
      configuration.put()
      if code == 204:
        code = 200

    self.response.set_status(code)

class GAELE_NOPHandler(GAELE_BaseHandler):
  def get(self):
    super(GAELE_NOPHandler, self).get()

    self.response.set_status(204)

class GAELE_CronHandler(GAELE_BaseHandler):
  def get(self):
    super(GAELE_CronHandler, self).get()

    configuration = configuration_key.get(use_cache=False, use_memcache=False)

    if not 'x-gaele-token' in self.request.headers or self.request.headers['x-gaele-token'] != configuration.token:
      if not 'x-appengine-cron' in self.request.headers:
        logging.error('missing x-appengine-cron header')
        self.response.set_status(403)
        return

    if len(configuration.domains_list) == 0:
      logging.info('domains list is empty')
      self.response.set_status(204)
      return

    application_id = app_identity.get_application_id()
    account_name = app_identity.get_service_account_name()
    auth_token, _ = app_identity.get_access_token('https://www.googleapis.com/auth/cloud-platform')

    logging.info(application_id)
    logging.info(account_name)
    logging.info(auth_token)
    logging.info(configuration.project)

    lb_type, lb = configuration.loadbalancer.split(':', 1)
    lb_type = lb_type.capitalize()

    response = urlfetch.fetch('https://www.googleapis.com/compute/v1/projects/{0}/global/target{1}Proxies/{2}'.format(configuration.project, lb_type, lb), headers={ 'Authorization': 'Bearer {}'.format(auth_token) })
    logging.info(response.content)

    return

    acme = ACME(configuration)
    neworder_payload = {
      'identifiers': [
        {
          'type': 'dns',
          'value': domain
        } for domain in configuration.domains_list
      ]
    }
    neworder_req = acme.request('newOrder', neworder_payload)
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

class GAELE_ChallengeHandler(GAELE_BaseHandler):
  def get(self):
    super(GAELE_ChallengeHandler, self).get()

    configuration = configuration_key.get(use_cache=False, use_memcache=False)

    if len(configuration.domains_list) == 0:
      raise RuntimeError('domains list is empty')

app = webapp2.WSGIApplication([
  (r'^/_ah/start$', GAELE_StartHandler),
  (r'^/_ah/.*$', GAELE_NOPHandler),
  (r'^/cron$', GAELE_CronHandler),
  (r'^/\.well-known/acme-challenge/.*$', GAELE_ChallengeHandler),
])
