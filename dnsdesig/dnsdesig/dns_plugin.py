# ============LICENSE_START====================================================
# org.onap.ccsdk
# =============================================================================
# Copyright (c) 2018-2020 AT&T Intellectual Property. All rights reserved.
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

import requests
from cloudify import ctx
from cloudify.decorators import operation
from cloudify.exceptions import NonRecoverableError, RecoverableError
import sys
USING_PYTHON2 = sys.version_info[0] < 3
if USING_PYTHON2:
  from urlparse import urlparse
else:
  from urllib.parse import urlparse

def _check_status(resp, msg):
  if resp.status_code >= 300:
    if resp.status_code >= 500:
      raise RecoverableError(msg)
    else:
      raise NonRecoverableError(msg)

def _get_auth_info(openstack):
  if openstack['auth_url'].endswith('/v2.0'):
    (tok, gbls, urls) = _get_auth_info_v2(openstack)
  else:
    (tok, gbls, urls) = _get_auth_info_v3(openstack)
  if len(list(urls.keys())) == 1:
    reg = list(urls.keys())[0]
  else:
    reg = openstack['region']
  if reg in urls and 'dns' in urls[reg]:
    url = urls[reg]['dns']
  elif 'dns' in gbls:
    url = gbls['dns']
  else:
    raise NonRecoverableError('DNS service not found')
  return { 'osauth': { 'X-Auth-Token': tok }, 'dns': url }

def _get_auth_info_v3(openstack):
  domain = openstack['domain'] if 'domain' in openstack else 'default'
  resp = requests.post('{0}/auth/tokens'.format(openstack['auth_url']), json={
    'auth': {
      'identity': {
        'methods': [
          'password'
        ],
        'password': {
          'user': {
            'name': openstack['username'],
            'domain': {
              'id': domain
            },
            'password': openstack['password']
          }
        }
      },
      'scope': {
        'project': {
          'name': openstack['tenant_name'],
          'domain': {
            'id': domain
          }
        }
      }
    }
  })
  _check_status(resp, 'Failed to get authorization token from OpenStack identity service v3')
  gbls = {}
  urls = {}
  for sc in resp.json()['token']['catalog']:
    type = sc['type']
    for ep in sc['endpoints']:
      if 'region' in ep and ep['region'] not in urls:
        urls[ep['region']] = {}
      if ep['interface'] == 'public' and ep['url'] != '':
        if 'region' not in ep:
          gbls[type] = ep['url']
        else:
          urls[ep['region']][type] = ep['url']
  return (resp.headers['X-Subject-Token'], gbls, urls)

def _get_auth_info_v2(openstack):
  resp = requests.post('{0}/tokens'.format(openstack['auth_url']), json={'auth':{'tenantName':openstack['tenant_name'],'passwordCredentials':{'username':openstack['username'], 'password':openstack['password']}}})
  _check_status(resp, 'Failed to get authorization token from OpenStack identity service v2')
  respj = resp.json()['access']
  gbls = {}
  urls = {}
  for se in respj['serviceCatalog']:
    type = se['type']
    for ep in se['endpoints']:
      if 'region' in ep and ep['region'] not in urls:
        urls[ep['region']] = {}
      if 'publicURL' in ep and ep['publicURL'] != '':
        if 'region' not in ep:
          gbls[type] = ep['publicURL']
        else:
          urls[ep['region']][type] = ep['publicURL']
  return (respj['token']['id'], gbls, urls)

def _dot(fqdn):
  """
  Append a dot to a fully qualified domain name.

  DNS and Designate expect FQDNs to end with a dot, but human's conventionally don't do that.
  """
  return '{0}.'.format(fqdn)

def _get_domain(fqdn):
  return fqdn[(fqdn.find('.') + 1):]

def _get_zone_id(fqdn, access):
  zn = _dot(_get_domain(fqdn))
  resp = requests.get('{0}/v2/zones'.format(access['dns']), headers=access['osauth'])
  _check_status(resp, 'Failed to list DNS zones')
  respj = resp.json()['zones']
  for ae in respj:
    if ae['name'] == zn:
      return ae['id']
  raise NonRecoverableError('DNS zone {0} not available for this tenant'.format(zn))

def _find_recordset(fqdn, type, zid, access):
  fqdnd = _dot(fqdn)
  resp = requests.get('{0}/v2/zones/{1}/recordsets?limit=1000'.format(access['dns'], zid), headers=access['osauth'])
  _check_status(resp, 'Failed to list DNS record sets')
  respj = resp.json()['recordsets']
  for rs in respj:
    if rs['type'] == type and rs['name'] == fqdnd:
      return rs
  return None

@operation
def aneeded(**kwargs):
  """
  Create DNS A record, if not already present.  Expect args: ip_addresses: [ ... ]
  """
  try:
    _doneed('A', kwargs['args']['ip_addresses'])
  except (NonRecoverableError, RecoverableError) as nre:
    raise nre
  except Exception as e:
    raise NonRecoverableError(e)

@operation
def anotneeded(**kwargs):
  """
  Remove DNS A record, if present
  """
  _noneed('A')

@operation
def cnameneeded(**kwargs):
  """
  Create DNS CNAME record, if not already present.  Expect args: cname: '...'
  """
  try:
    _doneed('CNAME', [ _dot(kwargs['args']['cname']) ] )
  except (NonRecoverableError, RecoverableError) as nre:
    raise nre
  except Exception as e:
    raise NonRecoverableError(e)

@operation
def cnamenotneeded(**kwargs):
  """
  Remove DNS CNAME record, if present
  """
  _noneed('CNAME')

def _doneed(type, records):
  """
  Create DNS entries, if not already present
  """
  access = _get_auth_info(ctx.node.properties['openstack'])
  fqdn = ctx.node.properties['fqdn']
  zid = _get_zone_id(fqdn, access)
  rs = _find_recordset(fqdn, type, zid, access)
  if not rs:
    resp = requests.post('{0}/v2/zones/{1}/recordsets'.format(access['dns'], zid), json={ 'name': _dot(fqdn), 'type': type, 'records': records, 'ttl': ctx.node.properties['ttl'] }, headers=access['osauth'])
    _check_status(resp, 'Failed to create DNS record set for {0}'.format(fqdn))
  else:
    resp = requests.put('{0}/v2/zones/{1}/recordsets/{2}'.format(access['dns'], zid, rs['id']), json={ 'records': records, 'ttl': ctx.node.properties['ttl'] }, headers=access['osauth'])
    _check_status(resp, 'Failed to update DNS record set for {0}'.format(fqdn))


def _noneed(type):
  """
  Remove DNS entries, if present
  """
  try:
    fqdn = ctx.node.properties['fqdn']
    access = _get_auth_info(ctx.node.properties['openstack'])
    zid = _get_zone_id(fqdn, access)
    rs = _find_recordset(fqdn, type, zid, access)
    if rs:
      resp = requests.delete('{0}/v2/zones/{1}/recordsets/{2}'.format(access['dns'], zid, rs['id']), headers=access['osauth'])
      _check_status(resp, 'Failed to delete DNS record set for {0}'.format(fqdn))
  except (NonRecoverableError, RecoverableError) as nre:
    raise nre
  except Exception as e:
    raise NonRecoverableError(e)
