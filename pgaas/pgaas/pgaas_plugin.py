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
import urllib

opath = sys.path
sys.path = list(opath)
sys.path.append('/usr/lib64/python2.7/site-packages')
import psycopg2
sys.path = opath

"""
  To set up a cluster:
  - https://$NEXUS/repository/raw/type_files/sshkeyshare/sshkey_types.yaml
  - https://$NEXUS/repository/raw/type_files/pgaas_types.yaml
  sharedsshkey_pgrs:
    type: dcae.nodes.ssh.keypair
  pgaas_cluster:
    type: dcae.nodes.pgaas.cluster
    properties:
      writerfqdn: { concat: [ { get_input: location_prefix }, '-', { get_input: pgaas_cluster_name }, '-write.', { get_input: location_domain } ] }
      readerfqdn: { concat: [ { get_input: location_prefix }, '-', { get_input: pgaas_cluster_name }, '.', { get_input: location_domain } ] }
    relationships:
      - type: dcae.relationships.pgaas_cluster_uses_sshkeypair
        target: sharedsshkey_pgrs

  To reference an existing cluster:
  - https://$NEXUS/repository/raw/type_files/pgaas_types.yaml
  pgaas_cluster:
    type: dcae.nodes.pgaas.cluster
    properties:
      writerfqdn: { concat: [ { get_input: location_prefix }, '-', { get_input: pgaas_cluster_name }, '-write.', { get_input: location_domain } ] }
      # or: writerfqdn: { get_property: [ dns_pgrs_rw, fqdn ] }
      use_existing: true

  - { get_attribute: [ pgaas_cluster, public ] }
  - { get_attribute: [ pgaas_cluster, base64private ] }


  To set up a database:
  - http://$NEXUS/raw/type_files/pgaas_types.yaml
  pgaasdbtest: 
    type: dcae.nodes.pgaas.database 
    properties: 
      writerfqdn: { concat: [ { get_input: location_prefix }, '-', { get_input: database_cluster_name }, '-write.', { get_input: location_domain } ] } 
      name: { get_input: database_name }

  To reference an existing database:
  - http://$NEXUS/raw/type_files/pgaas_types.yaml
  $CLUSTER_$DBNAME: 
    type: dcae.nodes.pgaas.database 
    properties: 
      writerfqdn: { concat: [ { get_input: location_prefix }, '-', { get_input: database_cluster_name }, '-write.', { get_input: location_domain } ] } 
      name: { get_input: database_name }
      use_existing: true

  $CLUSTER_$DBNAME_admin_host:
    description: Hostname for $CLUSTER $DBNAME database
    value: { get_attribute: [ $CLUSTER_$DBNAME, admin, host ] }
  $CLUSTER_$DBNAME_admin_user:
    description: Admin Username for $CLUSTER $DBNAME database
    value: { get_attribute: [ $CLUSTER_$DBNAME, admin, user ] }
  $CLUSTER_$DBNAME_admin_password:
    description: Admin Password for $CLUSTER $DBNAME database  
    value: { get_attribute: [ $CLUSTER_$DBNAME, admin, password ] }
  $CLUSTER_$DBNAME_user_host:
    description: Hostname for $CLUSTER $DBNAME database
    value: { get_attribute: [ $CLUSTER_$DBNAME, user, host ] }
  $CLUSTER_$DBNAME_user_user:
    description: User Username for $CLUSTER $DBNAME database
    value: { get_attribute: [ $CLUSTER_$DBNAME, user, user ] }
  $CLUSTER_$DBNAME_user_password:
    description: User Password for $CLUSTER $DBNAME database
    value: { get_attribute: [ $CLUSTER_$DBNAME, user, password ] }
  $CLUSTER_$DBNAME_viewer_host:
    description: Hostname for $CLUSTER $DBNAME database
    value: { get_attribute: [ $CLUSTER_$DBNAME, viewer, host ] }
  $CLUSTER_$DBNAME_viewer_user:
    description: Viewer Username for $CLUSTER $DBNAME database
    value: { get_attribute: [ $CLUSTER_$DBNAME, viewer, user ] }
  $CLUSTER_$DBNAME_viewer_password:
    description: Viewer Password for $CLUSTER $DBNAME database
    value: { get_attribute: [ $CLUSTER_$DBNAME, viewer, password ] }

"""


def safestr(s):
  return urllib.quote(str(s), '')

def debug(msg):
  """
  Print a debugging message.
  This is a handy endpoint to add other extended debugging calls.
  """
  ctx.logger.info(msg)

def warn(msg):
  """
  Print a warning message.
  This is a handy endpoint to add other extended warning calls.
  """
  ctx.logger.warn(msg)

def info(msg):
  """
  Print a info message.
  This is a handy endpoint to add other extended info calls.
  """
  ctx.logger.info(msg)
         
def raiseRecoverableError(msg):
  """
  Print a warning message and raise a RecoverableError exception.
  This is a handy endpoint to add other extended debugging calls.
  """
  ctx.logger.warn(msg)
  raise RecoverableError(msg)

def raiseNonRecoverableError(msg):
  """
  Print an error message and raise a NonRecoverableError exception.
  This is a handy endpoint to add other extended debugging calls.
  """
  ctx.logger.error(msg)
  raise NonRecoverableError(msg)


def waithp(host, port):
  """
  do a test connection to a host and port
  """
  debug("waithp({0},{1})".format(safestr(host),safestr(port)))
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    sock.connect((host, port))
  except:
    a, b, c = sys.exc_info()
    traceback.print_exception(a, b, c)
    sock.close()
    raiseRecoverableError('Server at {0}:{1} is not ready'.format(safestr(host), safestr(port)))
  sock.close()

def doconn(desc):
  """
  open an SQL connection to the PG server
  """
  debug("doconn()")
  ret = psycopg2.connect(**desc)
  ret.autocommit = True
  return ret

def rootdesc(data, dbname):
  """
  return the postgres connection information
  """
  debug("rootdesc(..data..,{0})".format(safestr(dbname)))
  return {
    'database': dbname,
    'host': data['rw'],
    'user': 'postgres',
    'password': getpass(data, 'postgres')
  }

def rootconn(data, dbname='postgres'):
  """
  connect to a given server as postgres,
  connecting to the specified database
  """
  debug("rootconn(..data..,{0})".format(safestr(dbname)))
  return doconn(rootdesc(data, dbname))

def onedesc(data, dbname, role, access):
  """
  return the connection information for a given user and dbname on a cluster
  """
  user = '{0}_{1}'.format(dbname, role)
  return {
    'database': dbname,
    'host': data[access],
    'user': user,
    'password': getpass(data, user)
  }

def dbdescs(data, dbname):
  """
  return the entire set of information for a specific server/database
  """
  return {
    'admin': onedesc(data, dbname, 'admin', 'rw'),
    'user': onedesc(data, dbname, 'user', 'rw'),
    'viewer': onedesc(data, dbname, 'viewer', 'ro')
  }

def getpass(data, ident):
  """
  generate the password for a given user on a specific server
  """
  m = hashlib.md5()
  m.update(ident)
  m.update(base64.b64decode(data['data']))
  return m.hexdigest()

def find_related_nodes(reltype, inst = None):
  """
  extract the related_nodes information from the context
  for a specific relationship
  """
  if inst is None:
    inst = ctx.instance
  ret = []
  for rel in inst.relationships:
    if reltype in rel.type_hierarchy:
      ret.append(rel.target)
  return ret

def chkfqdn(fqdn):
  """
  verify that a FQDN is valid
  """
  return re.match('^[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$', fqdn) is not None

def chkdbname(dbname):
  """
  verify that a database name is valid
  """
  ret = re.match('[a-zA-Z][a-zA-Z0-9]{0,43}', dbname) is not None and dbname != 'postgres'
  if not ret: warn("Invalid dbname: {0}".format(safestr(dbname)))
  return ret

def getclusterinfo(wfqdn, reuse, rfqdn, related):
  """
  Retrieve all of the information specific to a cluster.
  if reuse, retrieve it
  else create and store it
  """
  debug("getclusterinfo({0}, {1}, {2},..related..)".format(safestr(wfqdn), safestr(reuse), safestr(rfqdn)))
  if not chkfqdn(wfqdn):
    raiseNonRecoverableError('Invalid FQDN specified for admin/read-write access, fqdn={0}'.format(safestr(wfqdn)))
  if reuse:
    if rfqdn != '':
      raiseNonRecoverableError('Read-only FQDN must not be specified when using an existing cluster, fqdn={0}'.format(safestr(rfqdn)))
    if len(related) != 0:
      raiseNonRecoverableError('Cluster SSH keypair must not be specified when using an existing cluster')
    try:
      with open('/opt/manager/resources/pgaas/{0}'.format(wfqdn).lower(), 'r') as f:
        data = json.load(f)
        data['rw'] = wfqdn
        return data
    except Exception as e:
      warn("Error: {0}".format(e))
      warn("Stack: {0}".format(traceback.format_exc()))
      raiseNonRecoverableError('Cluster must be deployed when using an existing cluster: fqdn={0}, err={1}'.format(safestr(wfqdn),e))
  if rfqdn == '':
    rfqdn = wfqdn
  elif not chkfqdn(rfqdn):
    raiseNonRecoverableError('Invalid FQDN specified for read-only access, fqdn={0}'.format(safestr(rfqdn)))
  if len(related) != 1:
    raiseNonRecoverableError('Cluster SSH keypair must be specified using a dcae.relationships.pgaas_cluster_uses_sshkeypair relationship to a dcae.nodes.sshkeypair node')
  data = { 'ro': rfqdn, 'pubkey': related[0].instance.runtime_properties['public'], 'data': related[0].instance.runtime_properties['base64private'] }
  os.umask(077)
  try:
    os.makedirs('/opt/manager/resources/pgaas')
  except:
    pass
  try:
    with open('/opt/manager/resources/pgaas/{0}'.format(wfqdn).lower(), 'w') as f:
      f.write(json.dumps(data))
  except Exception as e:
    warn("Error: {0}".format(e))
    warn("Stack: {0}".format(traceback.format_exc()))
    raiseNonRecoverableError('Cannot write cluster information to /opt/manager/resources/pgaas: fqdn={0}, err={1}'.format(safestr(wfqdn),e))
  data['rw'] = wfqdn
  return(data)
  

@operation
def add_pgaas_cluster(**kwargs):
  """
  dcae.nodes.pgaas.cluster:
  Record key generation data for cluster
  """
  try:
    warn("add_pgaas_cluster() invoked")
    data = getclusterinfo(ctx.node.properties['writerfqdn'], ctx.node.properties['use_existing'], ctx.node.properties['readerfqdn'], find_related_nodes('dcae.relationships.pgaas_cluster_uses_sshkeypair'))
    ctx.instance.runtime_properties['public'] = data['pubkey']
    ctx.instance.runtime_properties['base64private'] = data['data']
    warn('All done')
  except Exception as e:
    ctx.logger.warn("Error: {0}".format(e))
    ctx.logger.warn("Stack: {0}".format(traceback.format_exc()))
    raise e

@operation
def rm_pgaas_cluster(**kwargs):
  """
  dcae.nodes.pgaas.cluster:
  Remove key generation data for cluster
  """
  try:
    warn("rm_pgaas_cluster()")
    wfqdn = ctx.node.properties['writerfqdn']
    if chkfqdn(wfqdn) and not ctx.node.properties['use_existing']:
      os.remove('/opt/manager/resources/pgaas/{0}'.format(wfqdn))
    warn('All done')
  except Exception as e:
    ctx.logger.warn("Error: {0}".format(e))
    ctx.logger.warn("Stack: {0}".format(traceback.format_exc()))
    raise e

def dbgetinfo(refctx):
  """
  Get the data associated with a database.
  Make sure the connection exists.
  """
  wfqdn = refctx.node.properties['writerfqdn']
  related = find_related_nodes('dcae.relationships.database_runson_pgaas_cluster', refctx.instance)
  if wfqdn == '':
    if len(related) != 1:
      raiseNonRecoverableError('Database Cluster must be specified using exactly one dcae.relationships.database_runson_pgaas_cluster relationship to a dcae.nodes.pgaas.cluster node when writerfqdn is not specified')
    wfqdn = related[0].node.properties['writerfqdn']
  if not chkfqdn(wfqdn):
    raiseNonRecoverableError('Invalid FQDN specified for admin/read-write access, fqdn={0}'.format(safestr(wfqdn)))
  ret = getclusterinfo(wfqdn, True, '', [])
  waithp(wfqdn, 5432)
  return ret
  
@operation
def create_database(**kwargs):
  """
  dcae.nodes.pgaas.database:
  Create a database on a cluster
  """
  try:
    debug("create_database() invoked")
    dbname = ctx.node.properties['name']
    warn("create_database({0})".format(safestr(dbname)))
    if not chkdbname(dbname):
      raiseNonRecoverableError('Unacceptable or missing database name: {0}'.format(safestr(dbname)))
    debug('create_database(): dbname checked out')
    info = dbgetinfo(ctx)
    debug('Got db server info')
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
          raiseNonRecoverableError('use_existing specified but database does not exist, dbname={0}'.format(safestr(dbname)))
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
    warn('All done')
  except Exception as e:
    ctx.logger.warn("Error: {0}".format(e))
    ctx.logger.warn("Stack: {0}".format(traceback.format_exc()))
    raise e

@operation
def delete_database(**kwargs):
  """
  dcae.nodes.pgaas.database:
  Delete a database from a cluster
  """
  try:
    debug("delete_database() invoked")
    dbname = ctx.node.properties['name']
    warn("delete_database({0})".format(safestr(dbname)))
    if not chkdbname(dbname):
      return
    debug('delete_database(): dbname checked out')
    if ctx.node.properties['use_existing']:
      return
    debug('delete_database(): !use_existing')
    info = dbgetinfo(ctx)
    debug('Got db server info')
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
    warn('All gone')
  except Exception as e:
    ctx.logger.warn("Error: {0}".format(e))
    ctx.logger.warn("Stack: {0}".format(traceback.format_exc()))
    raise e
