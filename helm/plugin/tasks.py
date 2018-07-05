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
#============LICENSE_END============================================

from cloudify.decorators import operation
import shutil
import errno
import sys
import pwd
import grp
import os
import re
import getpass
import subprocess
from cloudify import ctx
from cloudify.exceptions import OperationRetry
from cloudify_rest_client.exceptions import CloudifyClientError
import pip
import json
import yaml
import urllib2
from cloudify.decorators import operation
from cloudify import exceptions
from cloudify.exceptions import NonRecoverableError



def execute_command(_command):
    ctx.logger.debug('_command {0}.'.format(_command))

    subprocess_args = {
        'args': _command.split(),
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE
    }

    ctx.logger.debug('subprocess_args {0}.'.format(subprocess_args))

    process = subprocess.Popen(**subprocess_args)
    output, error = process.communicate()

    ctx.logger.debug('command: {0} '.format(_command))
    ctx.logger.debug('output: {0} '.format(output))
    ctx.logger.debug('error: {0} '.format(error))
    ctx.logger.debug('process.returncode: {0} '.format(process.returncode))

    if process.returncode:
        ctx.logger.error('Running `{0}` returns error.'.format(_command))
        return False

    return output


def configure_admin_conf():
    # Add the kubeadmin config to environment
    agent_user = getpass.getuser()
    uid = pwd.getpwnam(agent_user).pw_uid
    gid = grp.getgrnam('docker').gr_gid
    admin_file_dest = os.path.join(os.path.expanduser('~'), 'admin.conf')

    execute_command('sudo cp {0} {1}'.format('/etc/kubernetes/admin.conf', admin_file_dest))
    execute_command('sudo chown {0}:{1} {2}'.format(uid, gid, admin_file_dest))

    with open(os.path.join(os.path.expanduser('~'), '.bashrc'), 'a') as outfile:
        outfile.write('export KUBECONFIG=$HOME/admin.conf')
    os.environ['KUBECONFIG'] = admin_file_dest

def get_current_helm_value(chart_name):
    tiller_host= str(ctx.node.properties['tiller-server-ip'])+':'+str(ctx.node.properties['tiller-server-port'])
    config_dir_root= str(ctx.node.properties['config-dir'])
    config_dir=config_dir_root+str(ctx.deployment.id)+'/'
    if str_to_bool(ctx.node.properties['tls-enable']):
        getValueCommand=subprocess.Popen(["helm", "get","values","-a",chart_name,'--host',tiller_host,'--tls','--tls-ca-cert',config_dir+'ca.cert.pem','--tls-cert',config_dir+'helm.cert.pem','--tls-key',config_dir+'helm.key.pem'], stdout=subprocess.PIPE)
    else:
        getValueCommand=subprocess.Popen(["helm", "get","values","-a",chart_name,'--host',tiller_host], stdout=subprocess.PIPE)
    value=getValueCommand.communicate()[0]
    valueMap= {}
    valueMap = yaml.safe_load(value)
    ctx.instance.runtime_properties['current-helm-value'] = valueMap

def get_helm_history(chart_name):
    tiller_host= str(ctx.node.properties['tiller-server-ip'])+':'+str(ctx.node.properties['tiller-server-port'])
    config_dir_root= str(ctx.node.properties['config-dir'])
    config_dir=config_dir_root+str(ctx.deployment.id)+'/'
    if str_to_bool(ctx.node.properties['tls-enable']):
        getHistoryCommand=subprocess.Popen(["helm", "history",chart_name,'--host',tiller_host,'--tls','--tls-ca-cert',config_dir+'ca.cert.pem','--tls-cert',config_dir+'helm.cert.pem','--tls-key',config_dir+'helm.key.pem'], stdout=subprocess.PIPE)
    else:
        getHistoryCommand=subprocess.Popen(["helm", "history",chart_name,'--host',tiller_host], stdout=subprocess.PIPE)
    history=getHistoryCommand.communicate()[0]
    history_start_output = [line.strip() for line in history.split('\n') if line.strip()]
    for index  in range(len(history_start_output)):
        history_start_output[index]=history_start_output[index].replace('\t',' ')
    ctx.instance.runtime_properties['helm-history'] = history_start_output

def mergedict(dict1, dict2):
    for key in dict2.keys():
        if key not in dict1.keys():
            dict1[key] = dict2[key]
        else:
            if type(dict1[key]) == dict and type(dict2[key]) == dict :
                mergedict(dict1[key], dict2[key])
            else:
                dict1[key] = dict2[key]

def tls():
    if str_to_bool(ctx.node.properties['tls-enable']):
        config_dir_root= str(ctx.node.properties['config-dir'])
        config_dir=config_dir_root+str(ctx.deployment.id)+'/'
        tls_command= ' --tls --tls-ca-cert '+config_dir+'ca.cert.pem --tls-cert '+config_dir+'helm.cert.pem --tls-key '+config_dir+'helm.key.pem '
        ctx.logger.debug(tls_command)
        return tls_command
    else :
        return ''

def tiller_host():
    tiller_host= ' --host '+str(ctx.node.properties['tiller-server-ip'])+':'+str(ctx.node.properties['tiller-server-port'])+' '
    ctx.logger.debug(tiller_host)
    return tiller_host


def str_to_bool(s):
    s=str(s)
    if s == 'True' or s == 'true':
        return True
    elif s == 'False' or s== 'false':
        return False
    else:
        raise False


@operation
def config(**kwargs):
    # create helm value file on K8s master
    #configPath = ctx.node.properties['config-path']
    configJson = str(ctx.node.properties['config'])
    configUrl = str(ctx.node.properties['config-url'])
    configUrlInputFormat = str(ctx.node.properties['config-format'])
    runtime_config = str(ctx.node.properties['runtime-config'])  #json
    componentName = ctx.node.properties['component-name']
    config_dir_root= str(ctx.node.properties['config-dir'])
    stable_repo_url = str(ctx.node.properties['stable-repo-url'])
    ctx.logger.debug("debug "+ configJson + runtime_config )
    #load input config
    config_dir=config_dir_root+str(ctx.deployment.id)
    try:
        os.makedirs(config_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    ctx.logger.debug('tls-enable type '+str(type(str_to_bool(ctx.node.properties['tls-enable']))) )
    #create TLS cert files
    if str_to_bool(ctx.node.properties['tls-enable']):
        ctx.logger.debug('tls enable' )
        ca_value = ctx.node.properties['ca']
        cert_value = ctx.node.properties['cert']
        key_value = ctx.node.properties['key']
        ca= open(config_dir+'/ca.cert.pem',"w+")
        ca.write(ca_value)
        ca.close()
        cert= open(config_dir+'/helm.cert.pem',"w+")
        cert.write(cert_value)
        cert.close()
        key= open(config_dir+'/helm.key.pem',"w+")
        key.write(key_value)
        key.close()
    else:
        ctx.logger.debug('tls disable' )

    # create helm value.yaml file
    configPath=config_dir_root+str(ctx.deployment.id)+'/'+componentName+'.yaml'
    ctx.logger.debug(configPath)

    configObj ={}
    if configJson == '' and configUrl == '':
        ctx.logger.debug("Will use default HELM value")
    elif configJson == '' and configUrl != '':
        response = urllib2.urlopen(configUrl)
        if configUrlInputFormat == 'json':
             configObj = json.load(response)
        elif configUrlInputFormat == 'yaml':
             configObj = yaml.load(response)
        else:
            raise NonRecoverableError("Unable to get config input format.")
    elif configJson != '' and configUrl == '':
        configObj = json.loads(configJson)
    else:
        raise NonRecoverableError("Unable to get Json config input")

    # load runtime config
    ctx.logger.debug("debug check runtime config")
    if runtime_config == '':
        ctx.logger.debug("there is no runtime config value")
    else:
        runtime_config_obj= json.loads(runtime_config)
        mergedict(configObj,runtime_config_obj)

    with open(configPath, 'w') as outfile:
        yaml.safe_dump(configObj, outfile, default_flow_style=False)

    output = execute_command('helm init --client-only --stable-repo-url '+stable_repo_url)
    if output == False :
        raise NonRecoverableError("helm init failed")




@operation
def start(**kwargs):
    # install the ONAP Helm chart
    # get properties from node
    chartRepo = ctx.node.properties['chart-repo-url']
    componentName = ctx.node.properties['component-name']
    chartVersion = ctx.node.properties['chart-version']
    config_dir_root= str(ctx.node.properties['config-dir'])
    configPath=config_dir_root+str(ctx.deployment.id)+'/'+componentName+'.yaml'
    namespace = ctx.node.properties['namespace']
    configJson = str(ctx.node.properties['config'])
    configUrl = str(ctx.node.properties['config-url'])
    runtimeconfigJson =  str(ctx.node.properties['runtime-config'])


    chart = chartRepo + "/" + componentName + "-" + chartVersion + ".tgz"
    chartName = namespace + "-" + componentName

    if configJson == '' and runtimeconfigJson == '' and configUrl == '':
        installCommand = 'helm install '+ chart + ' --name ' + chartName + ' --namespace ' + namespace+tiller_host()+tls()
    else:
        installCommand = 'helm install ' + chart + ' --name ' + chartName + ' --namespace ' + namespace + ' -f '+ configPath +tiller_host()+tls()

    output =execute_command(installCommand)
    if output == False :
        return ctx.operation.retry(message='helm install failed, re-try after 5 second ',
                                   retry_after=5)

    get_current_helm_value(chartName)
    get_helm_history(chartName)

@operation
def stop(**kwargs):
    # delete the ONAP helm chart
    #configure_admin_conf()
    # get properties from node
    namespace = ctx.node.properties['namespace']
    component = ctx.node.properties['component-name']
    chartName = namespace + "-" + component
    config_dir_root= str(ctx.node.properties['config-dir'])
    # Delete helm chart
    command = 'helm delete --purge '+ chartName+tiller_host()+tls()
    output =execute_command(command)
    config_dir=config_dir_root+str(ctx.deployment.id)
    shutil.rmtree(config_dir)
    if output == False :
        raise NonRecoverableError("helm delete failed")

@operation
def upgrade(**kwargs):
    # upgrade the helm chart
    componentName = ctx.node.properties['component-name']
    config_dir_root= str(ctx.node.properties['config-dir'])
    configPath=config_dir_root+str(ctx.deployment.id)+'/'+componentName+'.yaml'
    componentName = ctx.node.properties['component-name']
    namespace = ctx.node.properties['namespace']
    configJson = kwargs['config']
    chartRepo =  kwargs['chart_repo']
    chartVersion = kwargs['chart_version']

    ctx.logger.debug('debug ' + str(configJson))
    chartName = namespace + "-" + componentName
    chart=chartRepo + "/" + componentName + "-" + chartVersion + ".tgz"
    if str(configJson) == '':
        upgradeCommand = 'helm upgrade '+ chartName + ' '+ chart+tiller_host()+tls()
    else:
        with open(configPath, 'w') as outfile:
            yaml.safe_dump(configJson, outfile, default_flow_style=False)
        #configure_admin_conf()
        upgradeCommand = 'helm upgrade '+ chartName + ' '+ chart + ' -f ' + configPath+tiller_host()+tls()
    output=execute_command(upgradeCommand)
    if output == False :
        return ctx.operation.retry(message='helm upgrade failed, re-try after 5 second ',
                                   retry_after=5)
    get_current_helm_value(chartName)
    get_helm_history(chartName)

@operation
def rollback(**kwargs):
    # rollback to some revision
    componentName = ctx.node.properties['component-name']
    namespace = ctx.node.properties['namespace']
    revision = kwargs['revision']
    #configure_admin_conf()
    chartName = namespace + "-" + componentName
    rollbackCommand = 'helm rollback '+ chartName + ' '+ revision+tiller_host()+tls()
    output=execute_command(rollbackCommand)
    if output == False :
        return ctx.operation.retry(message='helm rollback failed, re-try after 5 second ',
                                   retry_after=5)
    get_current_helm_value(chartName)
    get_helm_history(chartName)
