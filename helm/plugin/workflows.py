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

from cloudify.decorators import workflow
from cloudify.workflows import ctx
from cloudify.exceptions import NonRecoverableError
import urllib2
import json
import yaml
import base64


@workflow
def upgrade(node_instance_id, config_json, config_url, config_format,
            chartVersion, chartRepo, **kwargs):
    node_instance = ctx.get_node_instance(node_instance_id)

    if not node_instance_id:
        raise NonRecoverableError(
            'No such node_instance_id in deployment: {0}.'.format(
                node_instance_id))

    kwargs = {}
    if config_json == '' and config_url == '':
        kwargs['config'] = config_json
    elif config_json == '' and config_url != '':
        if config_url.find("@") != -1:
            head, end = config_url.rsplit('@', 1)
            head, auth = head.rsplit('//', 1)
            config_url = head + '//' + end
            username, password = auth.rsplit(':', 1)
            request = urllib2.Request(config_url)
            base64string = base64.encodestring(
                '%s:%s' % (username, password)).replace('\n', '')
            request.add_header("Authorization", "Basic %s" % base64string)
            response = urllib2.urlopen(request)
        else:
            response = urllib2.urlopen(config_url)
        if config_format == 'json':
            kwargs['config'] = json.load(response)
        elif config_format == 'yaml':
            kwargs['config'] = yaml.load(response)
        else:
            raise NonRecoverableError("Unable to get config input format")
    elif config_json != '' and config_url == '':
        kwargs['config'] = config_json

    else:
        raise NonRecoverableError("Unable to get Json config input")

    kwargs['chart_version'] = str(chartVersion)
    kwargs['chart_repo'] = str(chartRepo)
    operation_args = {'operation': 'upgrade', }
    operation_args['kwargs'] = kwargs
    node_instance.execute_operation(**operation_args)


@workflow
def rollback(node_instance_id, revision, **kwargs):
    node_instance = ctx.get_node_instance(node_instance_id)

    if not node_instance_id:
        raise NonRecoverableError(
            'No such node_instance_id in deployment: {0}.'.format(
                node_instance_id))

    kwargs = {}
    kwargs['revision'] = str(revision)
    operation_args = {'operation': 'rollback', }
    operation_args['kwargs'] = kwargs
    node_instance.execute_operation(**operation_args)

@workflow
def status(**kwargs):

    for node in ctx.nodes:
        for node_instance in node.instances:
            kwargs = {}
            operation_args = {'operation': 'status', }
            operation_args['kwargs'] = kwargs
            node_instance.execute_operation(**operation_args)
