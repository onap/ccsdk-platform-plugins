# ============LICENSE_START====================================================
# org.onap.ccsdk
# =============================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
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

## Get parameters for accessing the DMaaP controller
from consulif.consulif import ConsulHandle
from cloudify.exceptions import NonRecoverableError
import os
import pkcrypto

os.environ["REQUESTS_CA_BUNDLE"]="/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt" # This is to handle https request thru plugin

CONSUL_HOST = "127.0.0.1"                   # Should always be a local consul agent on Cloudify Manager
DBCL_KEY_NAME = "dmaap_dbcl_info"           # Consul key containing DMaaP data bus credentials
DBC_SERVICE_NAME= "dmaap_bus_controller"    # Name under which the DMaaP bus controller is registered

try:
    _ch = ConsulHandle("http://{0}:8500".format(CONSUL_HOST), None, None, None)
except Exception as e:
    raise NonRecoverableError("Error getting ConsulHandle when configuring dmaap plugin: {0}".format(e))

try:
    config = _ch.get_config(DBCL_KEY_NAME)
except Exception as e:
    raise NonRecoverableError("Error getting config for '{0}' from ConsulHandle when configuring dmaap plugin: {1}".format(DBCL_KEY_NAME, e))

try:
    DMAAP_USER = config['dmaap']['username']
except Exception as e:
    raise NonRecoverableError("Error setting DMAAP_USER while configuring dmaap plugin: {0}".format(e))

try:
    DMAAP_PASS = pkcrypto.decrypt_obj(config['dmaap']['password'])
except Exception as e:
    raise NonRecoverableError("Error setting DMAAP_PASS while configuring dmaap plugin: {0}".format(e))

try:
    DMAAP_OWNER = config['dmaap']['owner']
except Exception as e:
    raise NonRecoverableError("Error setting DMAAP_OWNER while configuring dmaap plugin: {0}".format(e))

try:
    if 'protocol' in config['dmaap']:
        DMAAP_PROTOCOL = config['dmaap']['protocol']
    else:
        DMAAP_PROTOCOL = 'https'    # Default to https (service discovery should give us this but doesn't
except Exception as e:
    raise NonRecoverableError("Error setting DMAAP_PROTOCOL while configuring dmaap plugin: {0}".format(e))

try:
    if 'path' in config['dmaap']:
        DMAAP_PATH = config['dmaap']['path']
    else:
        DMAAP_PATH = 'webapi'       # SHould come from service discovery but Consul doesn't support it
except Exception as e:
    raise NonRecoverableError("Error setting DMAAP_PATH while configuring dmaap plugin: {0}".format(e))

try:
    service_address, service_port = _ch.get_service(DBC_SERVICE_NAME)
except Exception as e:
    raise NonRecoverableError("Error getting service_address and service_port for '{0}' from ConsulHandle when configuring dmaap plugin: {1}".format(DBC_SERVICE_NAME, e))

try:
    DMAAP_API_URL = '{0}://{1}:{2}/{3}'.format(DMAAP_PROTOCOL, service_address, service_port, DMAAP_PATH)
except Exception as e:
    raise NonRecoverableError("Error setting DMAAP_API_URL while configuring dmaap plugin: {0}".format(e))

