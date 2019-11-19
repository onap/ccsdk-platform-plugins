# ============LICENSE_START=======================================================
# org.onap.dcae
# ================================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2020 Pantheon.tech. All rights reserved.
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


def test_random_string():
    from dmaapplugin import dmaaputils
    target_length = 10
    assert len(dmaaputils.random_string(target_length)) == target_length


def test_consul_handle():
    from consulif.consulif import ConsulHandle
    from dmaapplugin import dmaaputils
    assert isinstance(dmaaputils.consul_handle(), ConsulHandle)


def test_controller_handle(mockconsul):
    from dmaapcontrollerif.dmaap_requests import DMaaPControllerHandle
    from dmaapplugin import dmaaputils
    assert isinstance(dmaaputils.controller_handle(), DMaaPControllerHandle)


def test_consul_config_mock(mockconsul):
    from dmaapplugin.dmaaputils import consul_config

    dmaap_config = consul_config.dmaap_config
    assert isinstance(dmaap_config, dict)
    assert dmaap_config

    assert consul_config.dmaap_user
    assert consul_config.dmaap_pass
    assert consul_config.dmaap_owner
    assert consul_config.dmaap_protocol == consul_config.DEFAULT_PROTOCOL
    assert consul_config.dmaap_path == consul_config.DEFAULT_PATH
    assert consul_config.dmaap_api_url


def test_consul_config_nomock():
    from cloudify.exceptions import NonRecoverableError
    from dmaapplugin.dmaaputils import ConsulConfig

    consul_config = ConsulConfig()
    consul_config.CONSUL_HOST = 'noconsul'
    consul_config.HTTP_PORT = '8888'
    consul_config.ONAP_SERVICE_ADDRESS = 'onapaddress'

    with pytest.raises(NonRecoverableError) as err:
        consul_config.dmaap_config
    assert 'noconsul' in str(err.value)

    consul_config._dmaap_config = {
        'protocol': 'http',
        'path': 'altpath',
    }
    with pytest.raises(NonRecoverableError) as err:
        consul_config.dmaap_user
    assert 'username' in str(err.value)
    with pytest.raises(NonRecoverableError) as err:
        consul_config.dmaap_pass
    assert 'password' in str(err.value)
    with pytest.raises(NonRecoverableError) as err:
        consul_config.dmaap_owner
    assert 'owner' in str(err.value)

    assert consul_config.dmaap_api_url == 'http://onapaddress:8888/altpath'
