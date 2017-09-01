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

CONSUL_HOST = "127.0.0.1"                   # Should always be a local consul agent on Cloudify Manager
CM_SERVICE_NAME = "cloudify_manager"        # Name under which CM is registered, used as key to get config
DBC_SERVICE_NAME= "dmaap_bus_controller"    # Name under which the DMaaP bus controller is registered

try:
    _ch = ConsulHandle("http://{0}:8500".format(CONSUL_HOST), None, None, None)
    config = _ch.get_config(CM_SERVICE_NAME)
    DMAAP_USER = config['dmaap']['username']
    DMAAP_PASS = config['dmaap']['password']
    DMAAP_OWNER = config['dmaap']['owner']
    if 'protocol' in config['dmaap']:
        DMAAP_PROTOCOL = config['dmaap']['protocol']
    else:
        DMAAP_PROTOCOL = 'https'    # Default to https (service discovery should give us this but doesn't
    if 'path' in config['dmaap']:
        DMAAP_PATH = config['dmaap']['path']
    else:
        DMAAP_PATH = 'webapi'       # SHould come from service discovery but Consul doesn't support it

    service_address, service_port = _ch.get_service(DBC_SERVICE_NAME)
    DMAAP_API_URL = '{0}://{1}:{2}/{3}'.format(DMAAP_PROTOCOL, service_address, service_port, DMAAP_PATH)

except Exception as e:
        raise NonRecoverableError("Error configuring dmaap plugin: {0}".format(e))
