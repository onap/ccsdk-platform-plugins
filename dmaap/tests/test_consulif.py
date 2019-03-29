# ============LICENSE_START=======================================================
# org.onap.dcae
# ================================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
# ================================================================================
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
# ============LICENSE_END=========================================================
#
# ECOMP is a trademark and service mark of AT&T Intellectual Property.


import pytest
from consulif.consulif import ConsulHandle
from cloudify.exceptions import NonRecoverableError
import os


#When run unit test, please update the consul interface parameters based on local consul configuration. 
CONSUL_HOST = "consul"                      # Should always be a local consul agent on Cloudify Manager
CONSUL_PORT = '8500'
DBCL_KEY_NAME = "dmaap_dbcl_info"           # Consul key containing DMaaP data bus credentials
DBC_SERVICE_NAME= "dmaap_bus_controller"    # Name under which the DMaaP bus controller is registered

def test_get_config_service():
  try:
    err_msg = "Error getting ConsulHandle when configuring dmaap plugin: {0}"
    _ch = ConsulHandle("http://{0}:{1}".format(CONSUL_HOST, CONSUL_PORT), None, None, None)
    assert None != _ch
    
    err_msg = "Error getting config for '{0}' from ConsulHandle when configuring dmaap plugin: ".format(DBCL_KEY_NAME) + "{0}"
    config = _ch.get_config(DBCL_KEY_NAME)

    print "XL:{0}".format(config)
    err_msg = "Error setting DMAAP_USER while configuring dmaap plugin: {0}"
    DMAAP_USER = config['dmaap']['username']

    err_msg = "Error setting DMAAP_PASS while configuring dmaap plugin: {0}"
    DMAAP_PASS = config['dmaap']['password']

    err_msg = "Error setting DMAAP_OWNER while configuring dmaap plugin: {0}"
    DMAAP_OWNER = config['dmaap']['owner']

    err_msg = "Error setting DMAAP_PROTOCOL while configuring dmaap plugin: {0}"
    if 'protocol' in config['dmaap']:
        DMAAP_PROTOCOL = config['dmaap']['protocol']
    else:
        DMAAP_PROTOCOL = 'https'    # Default to https (service discovery should give us this but doesn't

    err_msg = "Error setting DMAAP_PATH while configuring dmaap plugin: {0}"
    if 'path' in config['dmaap']:
        DMAAP_PATH = config['dmaap']['path']
    else:
        DMAAP_PATH = 'webapi'       # SHould come from service discovery but Consul doesn't support it

    err_msg = "Error getting service_address and service_port for '{0}' from ConsulHandle when configuring dmaap plugin: ".format(DBC_SERVICE_NAME) + "{0}"
    service_address, service_port = _ch.get_service(DBC_SERVICE_NAME)

    err_msg = "Error setting DMAAP_API_URL while configuring dmaap plugin: {0}"
    DMAAP_API_URL = '{0}://{1}:{2}/{3}'.format(DMAAP_PROTOCOL, service_address, service_port, DMAAP_PATH)
    assert DMAAP_API_URL != None
    dmaap_config = {'DMAAP_USER':DMAAP_USER, 'DMAAP_API_URL':DMAAP_API_URL, 'DMAAP_PASS':DMAAP_PASS, 'DMAAP_OWNER':DMAAP_OWNER}
    print "get dmaap config info from consul: {0}".format(dmaap_config)
    return dmaap_config

  except Exception as e:
    raise NonRecoverableError(err_msg.format(e))

def test_add_entry():
  try:
    _ch = ConsulHandle("http://{0}:{1}".format(CONSUL_HOST, CONSUL_PORT), None, None, None)
    assert None != _ch

    key = 'DMAAP_TEST'
    name = 'dmaap_test_name'
    value = 'dmaap_test_value'
    _ch.add_to_entry(key, name, value)

    name = "dmaap_test_name_2"
    value = 'dmaap_test_value_2'
    _ch.add_to_entry(key, name, value)

    _ch.delete_entry(key)

  except Exception as e:
    raise NonRecoverableError("Error in test_add_entry: {0}".format(e))

