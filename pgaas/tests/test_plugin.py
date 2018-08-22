# ============LICENSE_START====================================================
# org.onap.ccsdk
# =============================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
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
import socket
import psycopg2
import pgaas.pgaas_plugin
from cloudify.mocks import MockCloudifyContext
from cloudify.mocks import MockNodeContext
from cloudify.mocks import MockNodeInstanceContext
from cloudify.mocks import MockRelationshipSubjectContext
from cloudify.state import current_ctx
from cloudify.exceptions import NonRecoverableError
from cloudify import ctx

import sys, os
sys.path.append(os.path.realpath(os.path.dirname(__file__)))

TMPNAME = "/tmp/pgaas_plugin_tests"

class MockKeyPair(object):
  def __init__(self, type_hierarchy=None, target=None):
    self._type_hierarchy = type_hierarchy
    self._target = target

  @property
  def type_hierarchy(self):
    return self._type_hierarchy

  @property
  def target(self):
    return self._target

class MockInstance(object):
  def __init__(self, instance=None):
    self._instance = instance

  @property
  def instance(self):
    return self._instance

class MockRuntimeProperties(object):
  def __init__(self, runtime_properties=None):
    self._runtime_properties = runtime_properties

  @property
  def runtime_properties(self):
    return self._runtime_properties

class MockSocket(object):
  def __init__(self):
    pass
  def connect(self,host=None,port=None):
    pass
  def close(self):
    pass  


def _connect(h,p):
  return { }
                       
def set_mock_context(msg, monkeypatch):
  print("================ %s ================" % msg)
  os.system("exec >> {0}.out 2>&1; echo Before test".format(TMPNAME)) #### DELETE
  props = {
    'writerfqdn': 'test.bar.example.com',
    'use_existing': False,
    'readerfqdn': 'test-ro.bar.example.com',
    'name': 'testdb',
    'port': '5432',
    'initialpassword': 'test'
    }
    
  sshkeyprops = {
    'public': "testpub",
    'base64private': "testpriv"
    }

  mock_ctx = MockCloudifyContext(node_id='test_node_id', node_name='test_node_name',
                                 properties=props,
                                 relationships = [
                                   MockKeyPair(type_hierarchy =
                                               [ "dcae.relationships.pgaas_cluster_uses_sshkeypair" ],
                                               target= MockInstance(
                                                 MockRuntimeProperties(sshkeyprops)) )
                                   ],
                                 runtime_properties = {
                                   "admin": { "user": "admin_user" },
                                   "user": { "user": "user_user" },
                                   "viewer": { "user": "viewer_user" }
                                   }
                                 )
  current_ctx.set(mock_ctx)
  monkeypatch.setattr(socket.socket, 'connect', _connect)
  # monkeypatch.setattr(psycopg2, 'connect', _connect)
  pgaas.pgaas_plugin.setOptManagerResources(TMPNAME)



@pytest.mark.dependency()
def test_start(monkeypatch):
  os.system("exec > {0}.out 2>&1; echo Before any test; rm -rf {0}; mkdir -p {0}".format(TMPNAME)) #### DELETE

@pytest.mark.dependency(depends=['test_start'])
def test_add_pgaas_cluster(monkeypatch):
  try:
    set_mock_context('test_add_pgaas_cluster', monkeypatch)
    pgaas.pgaas_plugin.add_pgaas_cluster(args={})
  finally:
    current_ctx.clear()
    os.system("exec >> {0}.out 2>&1; echo After add_pgaas_cluster test; ls -lR {0}; head -1000 /dev/null {0}/pgaas/*;echo".format(TMPNAME)) #### DELETE

@pytest.mark.dependency(depends=['test_add_pgaas_cluster'])
def test_add_database(monkeypatch):
  try:
    set_mock_context('test_add_database', monkeypatch)
    pgaas.pgaas_plugin.create_database(args={})
  finally:
    current_ctx.clear()
    os.system("exec >> {0}.out 2>&1; echo After add_database test; ls -lR {0}; head -1000 /dev/null {0}/pgaas/*;echo".format(TMPNAME)) #### DELETE

@pytest.mark.dependency(depends=['test_add_database'])
def test_update_database(monkeypatch):
  try:
    set_mock_context('test_update_database', monkeypatch)
    pgaas.pgaas_plugin.update_database(args={})
  finally:
    current_ctx.clear()
    os.system("exec >> {0}.out 2>&1; echo After update_database test; ls -lR {0}; head -1000 /dev/null {0}/pgaas/*;echo".format(TMPNAME)) #### DELETE

@pytest.mark.dependency(depends=['test_update_database'])
def test_delete_database(monkeypatch):
  try:
    set_mock_context('test_delete_database', monkeypatch)
    pgaas.pgaas_plugin.delete_database(args={})
  finally:
    current_ctx.clear()
    os.system("exec >> {0}.out 2>&1; echo After delete_database test; ls -lR {0}; head -1000 /dev/null {0}/pgaas/*;echo".format(TMPNAME)) #### DELETE

@pytest.mark.dependency(depends=['test_delete_database'])
def test_rm_pgaas_cluster(monkeypatch):
  try:
    set_mock_context('test_rm_pgaas_cluster', monkeypatch)
    pgaas.pgaas_plugin.rm_pgaas_cluster(args={})
  finally:
    current_ctx.clear()
    os.system("exec >> {0}.out 2>&1; echo After delete_database test; ls -lR {0}; head -1000 /dev/null {0}/pgaas/*;echo".format(TMPNAME)) #### DELETE

