# ============LICENSE_START====================================================
# org.onap.ccsdk
# =============================================================================
# Copyright (c) 2018 AT&T Intellectual Property. All rights reserved.
# =============================================================================
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END======================================================

import pytest
import requests
import dnsdesig.dns_plugin
from cloudify.mocks import MockCloudifyContext
from cloudify.state import current_ctx
from cloudify.exceptions import NonRecoverableError
from cloudify.exceptions import RecoverableError
from cloudify import ctx

class _resp(object):
  def __init__(self, code, body = None, rhdrs = None):
    self.status_code = code
    if rhdrs is not None:
      self.headers = rhdrs
    if body is not None:
      self._json = body

  def json(self):
    return self._json

  def rhdrs(self):
    return self.headers

def _same(a, b):
  t1 = type(a)
  t2 = type(b)
  if t1 != t2:
    return False
  if t1 == dict:
    if len(a) != len(b):
      return False
    for k, v in a.items():
      if k not in b or not _same(v, b[k]):
        return False
    return True
  if t1 == list:
    if len(a) != len(b):
      return False
    for i in range(len(a)):
      if not _same(a[i], b[i]):
        return False
    return True
  return a == b

class _req(object):
  def __init__(self, op, url, headers, resp, json = None):
    self.resp = resp
    self.op = op
    self.url = url
    self.headers = headers
    self.json = json

  def check(self, op, url, headers, json):
    if op != self.op or url != self.url:
      return None
    if self.headers is not None and not _same(self.headers, headers):
      return None
    if self.json is not None and not _same(self.json, json):
      return None
    return self.resp

_nf = _resp(404)
_ar = _resp(401)
_np = _resp(403)
_svcunavail = _resp(503)
_ok = _resp(200, { 'something': 'or-other' })

_tok = 'at'

_hdrs = { 'X-Auth-Token': _tok }

_goodos = {
  'auth_url': 'https://example.com/identity/v3',
  'password': 'pw',
  'region': 'r',
  'tenant_name': 'tn',
  'username': 'un'
}

_bados = {
  'auth_url': 'https://example.com/identity/v3',
  'password': 'xx',
  'region': 'r',
  'tenant_name': 'tn',
  'username': 'un'
}

_goodosv2 = {
  'auth_url': 'https://example.com/identity/v2.0',
  'password': 'pw',
  'region': 'r',
  'tenant_name': 'tn',
  'username': 'un'
}

_badosv2 = {
  'auth_url': 'https://example.com/identity/v2.0',
  'password': 'xx',
  'region': 'r',
  'tenant_name': 'tn',
  'username': 'un'
}


_answers = [
  # Authenticate v3
  _req('POST', 'https://example.com/identity/v3/auth/tokens', headers=None, resp=_resp(200, {
    'token': {
      'catalog': [
        {
          'type': 'dns',
          'endpoints': [
            {
              'interface': 'public',
              'region': 'r2',
              'url': 'https://example.com/invalid2'
            },
            {
              'interface': 'public',
              'region': 'r3',
              'url': 'https://example.com/invalid3'
            },
            {
              'interface': 'public',
              'url': 'https://example.com/dns'
            }
          ]
        }
      ]
    }
  }, rhdrs = {
    'X-Subject-Token': _tok
  }), json={
    'auth': {
      'identity': {
        'methods': [
          'password'
        ],
        'password': {
          'user': {
            'name': 'un',
            'domain': {
              'id': 'default'
            },
            'password': 'pw'
          }
        }
      },
      'scope': {
        'project': {
          'name': 'tn',
          'domain': {
            'id': 'default'
          }
        }
      }
    }
  }),
  # Invalid authentication v3
  _req('POST', 'https://example.com/identity/v3/auth/tokens', headers=None, resp=_np),
  # Authenticate v2.0
  _req('POST', 'https://example.com/identity/v2.0/tokens', headers=None, resp=_resp(200, {
    'access': {
      'token': {
        'id': _tok
      }, 'serviceCatalog': [
        {
          'type': 'dns',
          'endpoints': [
            {
              'publicURL': 'https://example.com/dns',
              'region': 'r'
            },
	    {
	      'publicURL': 'https://example.com/otherregions'
	    }
          ]
        }
      ]
    }
  }), json={
    'auth': {
      'tenantName': 'tn',
      'passwordCredentials': {
        'username': 'un',
        'password': 'pw'
      }
    }
  }),
  # Invalid authentication v2.0
  _req('POST', 'https://example.com/identity/v2.0/tokens', headers=None, resp=_np),
  # Get zones
  _req('GET', 'https://example.com/dns/v2/zones', headers=_hdrs, resp=_resp(200, {
    'zones': [
      {
        'name': 'x.example.com.',
        'id': 'z1'
      }
    ]
  })),
  # Get recordsets
  _req('GET', 'https://example.com/dns/v2/zones/z1/recordsets?limit=1000', headers=_hdrs, resp=_resp(200, {
    'recordsets': [
      {
        'id': 'ar1',
        'type': 'A',
        'name': 'a.x.example.com.',
        'ttl': 300,
        'records': [
          '87.65.43.21',
          '98.76,54.32'
        ]
      }, {
        'id': 'cname1',
        'type': 'CNAME',
        'name': 'c.x.example.com.',
        'ttl': 300,
        'records': [
          'a.x.example.com.'
        ]
      }, {
        'id': 'noservice',
        'type': 'CNAME',
        'name': 'noservice.x.example.com.',
        'ttl': 300,
        'records': [
          'a.x.example.com.'
        ]
      }
    ]
  })),
  # Bad auth
  _req('GET', 'https://example.com/dns/v2/zones/z1/recordsets?limit=1000', headers=None, resp=_ar),
  # Create A recordset
  _req('POST', 'https://example.com/dns/v2/zones/z1/recordsets', headers=_hdrs, resp=_ok, json={
    'type': 'A',
    'name': 'b.x.example.com.',
    'ttl': 300,
    'records': [
      '34.56.78.12'
    ]
  }),
  # Create CNAME recordset
  _req('POST', 'https://example.com/dns/v2/zones/z1/recordsets', headers=_hdrs, resp=_ok, json={
    'type': 'CNAME',
    'name': 'd.x.example.com.',
    'ttl': 300,
    'records': [
      'b.x.example.com.'
    ]
  }),
  # Update A recordset
  _req('PUT', 'https://example.com/dns/v2/zones/z1/recordsets/ar1', headers=_hdrs, resp=_ok, json={

    'ttl': 300,
    'records': [
      '34.56.78.12'
    ]
  }),
  # Update CNAME recordset
  _req('PUT', 'https://example.com/dns/v2/zones/z1/recordsets/cname1', headers=_hdrs, resp=_ok, json={
    'ttl': 300,
    'records': [
      'b.x.example.com.'
    ]
  }),
  # Delete A recordset
  _req('DELETE', 'https://example.com/dns/v2/zones/z1/recordsets/ar1', headers=_hdrs, resp=_ok),
  # Delete CNAME recordset
  _req('DELETE', 'https://example.com/dns/v2/zones/z1/recordsets/cname1', headers=_hdrs, resp=_ok),
  # service unavailable
  _req('DELETE', 'https://example.com/dns/v2/zones/z1/recordsets/noservice', headers=_hdrs, resp=_svcunavail)
]

def _match(op, url, headers, json = None):
  for choice in _answers:
    ret = choice.check(op, url, headers, json)
    if ret is not None:
      return ret
  return _nf

def _delete(url, headers):
  return _match('DELETE', url, headers)

def _get(url, headers):
  return _match('GET', url, headers)

def _post(url, json, headers = None):
  return _match('POST', url, headers, json)

def _put(url, json, headers = None):
  return _match('PUT', url, headers, json)

def _setup(os, fqdn, ttl=None):
  def fcnbuilder(fcn):
    def newfcn(monkeypatch):
      monkeypatch.setattr(requests, 'delete', _delete)
      monkeypatch.setattr(requests, 'get', _get)
      monkeypatch.setattr(requests, 'post', _post)
      monkeypatch.setattr(requests, 'put', _put)
      properties = { 'fqdn': fqdn, 'openstack': os }
      if ttl is not None:
        properties['ttl'] = ttl
      mock_ctx = MockCloudifyContext(node_id='test_node_id', node_name='test_node_name', properties=properties)
      try:
        current_ctx.set(mock_ctx)
        fcn()
      finally:
        current_ctx.clear()
    return newfcn
  return fcnbuilder

@_setup(_badosv2, 'a.x.example.com')
def test_dns_badauthv2():
  with pytest.raises(NonRecoverableError):
    dnsdesig.dns_plugin.anotneeded()

@_setup(_goodosv2, 'a.x.example.com')
def test_dns_goodauthv2():
  dnsdesig.dns_plugin.anotneeded()

@_setup(_bados, 'a.x.example.com')
def test_dns_badauth():
  with pytest.raises(NonRecoverableError):
    dnsdesig.dns_plugin.anotneeded()

@_setup(_goodos, 'a.bad.example.com')
def test_dns_badzone():
  with pytest.raises(NonRecoverableError):
    dnsdesig.dns_plugin.anotneeded()

@_setup(_goodos, 'b.x.example.com', 300)
def test_dns_addarecord():
  dnsdesig.dns_plugin.aneeded(args={'ip_addresses': [ '34.56.78.12' ]})

@_setup(_goodos, 'a.x.example.com', 300)
def test_dns_modarecord():
  dnsdesig.dns_plugin.aneeded(args={'ip_addresses': [ '34.56.78.12' ]})

@_setup(_goodos, 'a.x.example.com')
def test_dns_delarecord():
  dnsdesig.dns_plugin.anotneeded()

@_setup(_goodos, 'd.x.example.com', 300)
def test_dns_addcnamerecord():
  dnsdesig.dns_plugin.cnameneeded(args={'cname': 'b.x.example.com' })

@_setup(_goodos, 'c.x.example.com', 300)
def test_dns_modcnamerecord():
  dnsdesig.dns_plugin.cnameneeded(args={'cname': 'b.x.example.com' })

@_setup(_goodos, 'c.x.example.com')
def test_dns_delcname():
  dnsdesig.dns_plugin.cnamenotneeded()

@_setup(_goodos, 'noservice.x.example.com')
def test_dns_delbadcname():
  with pytest.raises(RecoverableError):
    dnsdesig.dns_plugin.cnamenotneeded()

def test_module_logger():
  dnsdesig.get_module_logger('dnsdesig')
