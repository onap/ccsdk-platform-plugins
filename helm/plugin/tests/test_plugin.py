# ============LICENSE_START==========================================
# ===================================================================
# Copyright (c) 2018 AT&T
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END============================================


from os import path
import unittest
import mock
import plugin.tasks

from cloudify.test_utils import workflow_test
from cloudify.mocks import MockNodeInstanceContext
from cloudify.mocks import MockCloudifyContext
from cloudify.state import current_ctx
from cloudify import ctx


class TestPlugin(unittest.TestCase):

    @workflow_test(path.join('blueprint', 'blueprint.yaml'),
                   resources_to_copy=[(path.join('blueprint', 'plugin',
                                                 'test_plugin.yaml'),
                                       'plugin')])
    @mock.patch('plugin.tasks.execute_command')
    def test_stop(self, cfy_local, mock_execute_command):
        # execute install workflow
        """

        :param cfy_local:
        """
        with mock.patch('plugin.tasks.shutil.rmtree'):
            cfy_local.execute('uninstall', task_retries=0)

        # extract single node instance
        instance = cfy_local.storage.get_node_instances()[0]

        mock_execute_command.assert_called_with('helm delete --purge onap-test_node --host 1.1.1.1:8888 ')

    @workflow_test(path.join('blueprint', 'blueprint.yaml'),
                   resources_to_copy=[(path.join('blueprint', 'plugin',
                                                 'test_plugin.yaml'),
                                       'plugin')])
    @mock.patch('plugin.tasks.execute_command')
    def test_start(self, cfy_local, mock_execute_command):
        # execute install workflow
        """

        :param cfy_local:
        """
        with mock.patch('plugin.tasks.config'):
            with mock.patch('plugin.tasks.get_current_helm_value'):
                with mock.patch('plugin.tasks.get_helm_history'):
                    cfy_local.execute('install', task_retries=0)

        # extract single node instance
        instance = cfy_local.storage.get_node_instances()[0]

        mock_execute_command.assert_called_with('helm install local/test_node-2.0.0.tgz --name onap-test_node --namespace onap --host 1.1.1.1:8888 ')

    @workflow_test(path.join('blueprint', 'blueprint.yaml'),
                   resources_to_copy=[(path.join('blueprint', 'plugin',
                                                 'test_plugin.yaml'),
                                       'plugin')])
    @mock.patch('plugin.tasks.execute_command')
    def test_config(self, cfy_local, mock_execute_command):
        # execute install workflow
        """

        :param cfy_local:
        """
        with mock.patch('plugin.tasks.start'):
            cfy_local.execute('install', task_retries=0)

        # extract single node instance
        instance = cfy_local.storage.get_node_instances()[0]

        mock_execute_command.assert_called_with('helm init --client-only --stable-repo-url http://0.0.0.0/stable')

    @workflow_test(path.join('blueprint', 'blueprint.yaml'),
                   resources_to_copy=[(path.join('blueprint', 'plugin',
                                                 'test_plugin.yaml'),
                                       'plugin')])
    def test_rollback(self, cfy_local):
        # execute install workflow
        """

        :param cfy_local:
        """
        node_instance_id = 'node_instance_id'
        revision = 1
        try:
            cfy_local.execute('rollback', task_retries=0,
                                     parameters={'node_instance_id': node_instance_id, 'revision': revision})
            self.fail('Expected exception due to operation not exist')
        except Exception as e:
            self.assertTrue('operation not available')

    @workflow_test(path.join('blueprint', 'blueprint.yaml'),
                   resources_to_copy=[(path.join('blueprint', 'plugin',
                                                 'test_plugin.yaml'),
                                       'plugin')])
    def test_upgrade(self, cfy_local):
        # execute install workflow
        """

        :param cfy_local:
        """
        node_instance_id = 'node_instance_id'
        config_json = ''
        config_url = ''
        config_format = 'json'
        chartVersion = '2.0.0'
        chartRepo = 'repo'
        try:
            cfy_local.execute('upgrade', task_retries=0,
                                     parameters={'node_instance_id': node_instance_id, 'config_json': config_json,
                                                        'config_url': config_url, 'config_format': config_format,
                                                        'chartVersion': chartVersion, 'chartRepo': chartRepo})
            self.fail('Expected exception due to operation not exist')
        except Exception as e:
            self.assertTrue('operation not available')

    @mock.patch('plugin.tasks.execute_command')
    def test_op_rollback(self, mock_execute_command):
        # test operation rollback
        """

        :rollback operation test:
        """
        props = {
            'component-name': 'test_node',
            'namespace': 'onap',
            'tiller-server-port': '8888',
            'tiller-server-ip': '1.1.1.1',
            'tls-enable': 'false'
        }
        args = {'revision': '1'}
        mock_ctx = MockCloudifyContext(node_id='test_node_id', node_name='test_node_name',
                                         properties=props)
        try:
            current_ctx.set(mock_ctx)
            with mock.patch('plugin.tasks.get_current_helm_value'):
                with mock.patch('plugin.tasks.get_helm_history'):
                    plugin.tasks.rollback(**args)
        finally:
            current_ctx.clear()

    @mock.patch('plugin.tasks.execute_command')
    def test_op_upgrade(self, mock_execute_command):
        # test operation upgrade
        """

        :upgrade operation test:
        """
        props = {
            'component-name': 'test_node',
            'namespace': 'onap',
            'tiller-server-port': '8888',
            'tiller-server-ip': '1.1.1.1',
            'tls-enable': 'false',
            'config-dir': '/tmp'
        }
        args = {'revision': '1', 'config': '', 'chart_repo': 'repo', 'chart_version': '2'}
        mock_ctx = MockCloudifyContext(node_id='test_node_id', node_name='test_node_name',
                                         properties=props)
        try:
            current_ctx.set(mock_ctx)
            with mock.patch('plugin.tasks.get_current_helm_value'):
                with mock.patch('plugin.tasks.get_helm_history'):
                    plugin.tasks.upgrade(**args)
        finally:
            current_ctx.clear()
