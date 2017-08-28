from cloudify import ctx
from cloudify.decorators import operation
from cloudify.exceptions import NonRecoverableError
from cloudify.exceptions import RecoverableError

import os
import re
import json
import hashlib
import socket
import sys
import traceback
import base64

opath = sys.path
sys.path = list(opath)
sys.path.append('/usr/lib64/python2.7/site-packages')
import psycopg2
sys.path = opath

def waithp(host, port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    sock.connect((host, port))
  except:
    a, b, c = sys.exc_info()
    traceback.print_exception(a, b, c)
    sock.close()
    raise RecoverableError('Server at {0}:{1} is not ready'.format(host, port))
  sock.close()

def doconn(desc):
  ret = psycopg2.connect(**desc)
  ret.autocommit = True
  return ret

def rootdesc(data, dbname):
  return {
    'database': dbname,
    'host': data['rw'],
    'user': 'postgres',
    'password': getpass(data, 'postgres')
  }

def rootconn(data, dbname='postgres'):
  return doconn(rootdesc(data, dbname))

def onedesc(data, dbname, role, access):
  user = '{0}_{1}'.format(dbname, role)
  return {
    'database': dbname,
    'host': data[access],
    'user': user,
    'password': getpass(data, user)
  }

def dbdescs(data, dbname):
  return {
    'admin': onedesc(data, dbname, 'admin', 'rw'),
    'user': onedesc(data, dbname, 'user', 'rw'),
    'viewer': onedesc(data, dbname, 'viewer', 'ro')
  }

def getpass(data, ident):
  m = hashlib.md5()
  m.update(ident)
  m.update(base64.b64decode(data['data']))
  return m.hexdigest()

def find_related_nodes(reltype, inst = None):
  if inst is None:
    inst = ctx.instance
  ret = []
  for rel in inst.relationships:
    if reltype in rel.type_hierarchy:
      ret.append(rel.target)
  return ret

def chkfqdn(fqdn):
  return re.match('^[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$', fqdn) is not None

def chkdbname(dbname):
  return re.match('[a-zA-Z][a-zA-Z0-9]{0,43}', dbname) is not None and dbname != 'postgres'

def getclusterinfo(wfqdn, reuse, rfqdn, related):
  if not chkfqdn(wfqdn):
    raise NonRecoverableError('Invalid FQDN specified for admin/read-write access')
  if reuse:
    if rfqdn != '':
      raise NonRecoverableError('Read-only FQDN must not be specified when using an existing cluster')
    if len(related) != 0:
      raise NonRecoverableError('Cluster SSH keypair must not be specified when using an existing cluster')
    try:
      with open('/opt/manager/resources/pgaas/{0}'.format(wfqdn).lower(), 'r') as f:
        data = json.load(f)
        data['rw'] = wfqdn
        return data
    except:
      raise NonRecoverableError('Cluster must be deployed when using an existing cluster')
  if rfqdn == '':
    rfqdn = wfqdn
  elif not chkfqdn(rfqdn):
    raise NonRecoverableError('Invalid FQDN specified for read-only access')
  if len(related) != 1:
    raise NonRecoverableError('Cluster SSH keypair must be specified using a dcae.relationships.pgaas_cluster_uses_sshkeypair relationship to a dcae.nodes.sshkeypair node')
  data = { 'ro': rfqdn, 'pubkey': related[0].instance.runtime_properties['public'], 'data': related[0].instance.runtime_properties['base64private'] }
  try:
    os.makedirs('/opt/manager/resources/pgaas')
  except:
    pass
  os.umask(077)
  with open('/opt/manager/resources/pgaas/{0}'.format(wfqdn).lower(), 'w') as f:
    f.write(json.dumps(data))
  data['rw'] = wfqdn
  return(data)
  

@operation
def add_pgaas_cluster(**kwargs):
  """
  Record key generation data for cluster
  """
  data = getclusterinfo(ctx.node.properties['writerfqdn'], ctx.node.properties['use_existing'], ctx.node.properties['readerfqdn'], find_related_nodes('dcae.relationships.pgaas_cluster_uses_sshkeypair'))
  ctx.instance.runtime_properties['public'] = data['pubkey']
  ctx.instance.runtime_properties['base64private'] = data['data']


@operation
def rm_pgaas_cluster(**kwargs):
  """
  Remove key generation data for cluster
  """
  wfqdn = ctx.node.properties['writerfqdn']
  if chkfqdn(wfqdn) and not ctx.node.properties['use_existing']:
    os.remove('/opt/manager/resources/pgaas/{0}'.format(wfqdn))

def dbgetinfo(refctx):
  wfqdn = refctx.node.properties['writerfqdn']
  related = find_related_nodes('dcae.relationships.database_runson_pgaas_cluster', refctx.instance)
  if wfqdn == '':
    if len(related) != 1:
      raise NonRecoverableError('Database Cluster must be specified using exactly one dcae.relationships.database_runson_pgaas_cluster relationship to a dcae.nodes.pgaas.cluster node when writerfqdn is not specified')
    wfqdn = related[0].node.properties['writerfqdn']
  if not chkfqdn(wfqdn):
    raise NonRecoverableError('Invalid FQDN specified for admin/read-write access')
  ret = getclusterinfo(wfqdn, True, '', [])
  waithp(wfqdn, 5432)
  return ret
  
@operation
def create_database(**kwargs):
  """
  Create a database on a cluster
  """
  dbname = ctx.node.properties['name']
  if not chkdbname(dbname):
    raise NonRecoverableError('Unacceptable or missing database name')
  ctx.logger.warn('In create_database')
  info = dbgetinfo(ctx)
  ctx.logger.warn('Got db server info')
  descs = dbdescs(info, dbname)
  ctx.instance.runtime_properties['admin'] = descs['admin']
  ctx.instance.runtime_properties['user'] = descs['user']
  ctx.instance.runtime_properties['viewer'] = descs['viewer']
  with rootconn(info) as conn:
    crx = conn.cursor()
    crx.execute('SELECT datname FROM pg_database WHERE datistemplate = false')
    existingdbs = [ x[0] for x in crx ]
    if ctx.node.properties['use_existing']:
      if dbname not in existingdbs:
        raise NonRecoverableError('use_existing specified but database does not exist')
      return
    crx.execute('SELECT rolname FROM pg_roles')
    existingroles = [ x[0] for x in crx ]
    admu = descs['admin']['user']
    usru = descs['user']['user']
    vwru = descs['viewer']['user']
    cusr = '{0}_common_user_role'.format(dbname)
    cvwr = '{0}_common_viewer_role'.format(dbname)
    schm = '{0}_db_common'.format(dbname)
    if admu not in existingroles:
      crx.execute('CREATE USER {0} WITH PASSWORD %s'.format(admu), (descs['admin']['password'],))
    if usru not in existingroles:
      crx.execute('CREATE USER {0} WITH PASSWORD %s'.format(usru), (descs['user']['password'],))
    if vwru not in existingroles:
      crx.execute('CREATE USER {0} WITH PASSWORD %s'.format(vwru), (descs['viewer']['password'],))
    if cusr not in existingroles:
      crx.execute('CREATE ROLE {0}'.format(cusr))
    if cvwr not in existingroles:
      crx.execute('CREATE ROLE {0}'.format(cvwr))
    if dbname not in existingdbs:
      crx.execute('CREATE DATABASE {0} WITH OWNER {1}'.format(dbname, admu))
    crx.close()
  with rootconn(info, dbname) as dbconn:
    crz = dbconn.cursor()
    for r in [ cusr, cvwr, usru, vwru ]:
      crz.execute('REVOKE ALL ON DATABASE {0} FROM {1}'.format(dbname, r))
    crz.execute('GRANT {0} TO {1}'.format(cvwr, cusr))
    crz.execute('GRANT {0} TO {1}'.format(cusr, admu))
    crz.execute('GRANT CONNECT ON DATABASE {0} TO {1}'.format(dbname, cvwr))
    crz.execute('CREATE SCHEMA IF NOT EXISTS {0} AUTHORIZATION {1}'.format(schm, admu))
    for r in [ admu, cusr, cvwr, usru, vwru ]:
      crz.execute('ALTER ROLE {0} IN DATABASE {1} SET search_path = public, {2}'.format(r, dbname, schm))
    crz.execute('GRANT USAGE ON SCHEMA {0} to {1}'.format(schm, cvwr))
    crz.execute('GRANT CREATE ON SCHEMA {0} to {1}'.format(schm, admu))
    crz.execute('ALTER DEFAULT PRIVILEGES FOR ROLE {0} GRANT SELECT ON TABLES TO {1}'.format(admu, cvwr))
    crz.execute('ALTER DEFAULT PRIVILEGES FOR ROLE {0} GRANT INSERT, UPDATE, DELETE, TRUNCATE ON TABLES TO {1}'.format(admu, cusr))
    crz.execute('ALTER DEFAULT PRIVILEGES FOR ROLE {0} GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {1}'.format(admu, cusr))
    crz.execute('GRANT TEMP ON DATABASE {0} TO {1}'.format(dbname, cusr))
    crz.execute('GRANT {0} to {1}'.format(cusr, usru))
    crz.execute('GRANT {0} to {1}'.format(cvwr, vwru))
    crz.close()
  ctx.logger.warn('All done')

@operation
def delete_database(**kwargs):
  """
  Delete a database from a cluster
  """
  dbname = ctx.node.properties['name']
  if not chkdbname(dbname):
    return
  if ctx.node.properties['use_existing']:
    return
  info = dbgetinfo(ctx)
  ctx.logger.warn('Got db server info')
  with rootconn(info) as conn:
    crx = conn.cursor()
    admu = ctx.instance.runtime_properties['admin']['user']
    usru = ctx.instance.runtime_properties['user']['user']
    vwru = ctx.instance.runtime_properties['viewer']['user']
    cusr = '{0}_common_user_role'.format(dbname)
    cvwr = '{0}_common_viewer_role'.format(dbname)
    crx.execute('DROP DATABASE IF EXISTS {0}'.format(dbname))
    for r in [ usru, vwru, admu, cusr, cvwr ]:
      crx.execute('DROP ROLE IF EXISTS {0}'.format(r))
  ctx.logger.warn('All gone')
