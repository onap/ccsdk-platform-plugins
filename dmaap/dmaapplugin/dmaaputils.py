# ============LICENSE_START====================================================
# org.onap.ccsdk
# =============================================================================
# Copyright (c) 2017-2019 AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2020 Pantheon.tech. All rights reserved.
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

# Utility functions

import os
import string
from random import SystemRandom

from cloudify import ctx
from cloudify.exceptions import NonRecoverableError

from consulif.consulif import ConsulHandle
from dmaapcontrollerif.dmaap_requests import DMaaPControllerHandle


def random_string(n):
    '''
    Create a random alphanumeric string, n characters long.
    '''
    secureRandomGen = SystemRandom()
    choices = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(secureRandomGen.choice(choices) for _ in range(n))


def consul_handle():
    '''
    Get a ConsulHandle from current configuration
    '''
    return consul_config.consul_handle


def controller_handle():
    '''
    Create a DMaaPControllerHandle from global configuration and cloudify context
    '''
    return DMaaPControllerHandle(
        consul_config.dmaap_api_url,
        consul_config.dmaap_user,
        consul_config.dmaap_pass,
        ctx.logger)


class ConsulConfig(object):
    """Lazy loader for DMaaP plugin configuration"""

    # This is to handle https request thru plugin
    CA_BUNDLE_PATH = "/opt/onap/certs/cacert.pem"

    # Should always be a local consul agent on Cloudify Manager
    CONSUL_HOST = "consul"

    # Consul key containing DMaaP data bus credentials
    DBCL_KEY_NAME = "dmaap-plugin"

    # In the ONAP Kubernetes environment, bus controller address is always
    # "dmaap-bc", on port 8080 (http) and 8443 (https)
    ONAP_SERVICE_ADDRESS = "dmaap-bc"

    DEFAULT_PROTOCOL = "https"
    HTTP_PORT = "8080"
    HTTPS_PORT = "8443"

    # Should come from service discovery but Consul doesn't support it
    DEFAULT_PATH = 'webapi'

    _dmaap_config = None

    @property
    def consul_handle(self):
        os.environ["REQUESTS_CA_BUNDLE"] = self.CA_BUNDLE_PATH
        url = "http://{0}:8500".format(self.CONSUL_HOST)
        return ConsulHandle(url, None, None, ctx.logger)

    @property
    def dmaap_config(self):
        if self._dmaap_config is None:
            self._dmaap_config = self._fetch_config()
            self._dmaap_config.setdefault('protocol', self.DEFAULT_PROTOCOL)
            self._dmaap_config.setdefault('path', self.DEFAULT_PATH)
        return self._dmaap_config

    def _fetch_config(self):
        try:
            _ch = self.consul_handle
        except Exception as e:
            raise NonRecoverableError(
                "Error getting ConsulHandle when configuring dmaap plugin: {0}"
                .format(e))

        try:
            return _ch.get_config(self.DBCL_KEY_NAME)['dmaap']
        except Exception as e:
            raise NonRecoverableError(
                "Error getting config for '{0}' from ConsulHandle when "
                "configuring dmaap plugin: {1}"
                .format(self.DBCL_KEY_NAME, e))

    @property
    def dmaap_user(self):
        try:
            return self.dmaap_config['username']
        except KeyError as e:
            raise NonRecoverableError(
                "Missing username in dmaap plugin configuration: {0}".format(e))

    @property
    def dmaap_pass(self):
        try:
            return self.dmaap_config['password']
        except KeyError as e:
            raise NonRecoverableError(
                "Missing password in dmaap plugin configuration: {0}".format(e))

    @property
    def dmaap_owner(self):
        try:
            return self.dmaap_config['owner']
        except KeyError as e:
            raise NonRecoverableError(
                "Missing owner in dmaap plugin configuration: {0}".format(e))

    @property
    def dmaap_protocol(self):
        return self.dmaap_config['protocol']

    @property
    def dmaap_path(self):
        return self.dmaap_config['path']

    @property
    def dmaap_api_url(self):
        protocol = self.dmaap_protocol
        service_port = self.HTTPS_PORT if protocol == 'https' else self.HTTP_PORT
        return '{0}://{1}:{2}/{3}'.format(
            protocol,
            self.ONAP_SERVICE_ADDRESS,
            service_port,
            self.dmaap_path)


consul_config = ConsulConfig()
