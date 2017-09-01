#!/bin/bash
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

echo "running script: [$0] for module [$1] at stage [$2]"

echo "=> Prepare environment "

# This is the base for where "deploy" will upload
# MVN_NEXUSPROXY is set in the pom.xml
REPO=$MVN_NEXUSPROXY/content/sites/raw/$MVN_PROJECT_GROUPID

TIMESTAMP=$(date +%C%y%m%dT%H%M%S)
export BUILD_NUMBER="${TIMESTAMP}"

# expected environment variables
if [ -z "${MVN_NEXUSPROXY}" ]; then
    echo "MVN_NEXUSPROXY environment variable not set.  Cannot proceed"
    exit
fi
MVN_NEXUSPROXY_HOST=$(echo $MVN_NEXUSPROXY |cut -f3 -d'/' | cut -f1 -d':')


# use the version text detect which phase we are in in LF CICD process: verify, merge, or (daily) release

# mvn phase in life cycle
MVN_PHASE="$2"

case $MVN_PHASE in
clean)
  echo "==> clean phase script"
  rm -rf .testenv .pkgenv $PLUGIN_NAME-*.wgn $PLUGIN_SUBDIR/.tox $PLUGIN_SUBDIR/$PLUGIN_NAME.egg-info $(find $PLUGIN_SUBDIR -name __pycache__ -type d -print)
  ;;
generate-sources)
  echo "==> generate-sources phase script"
  # Nothing to do
  ;;
compile)
  echo "==> compile phase script"
  # Nothing to do
  # TEMPORARY: PLAN TO ABANDON.  TRYING TO GET DEPLOY STEP WORKING PROPERLY.  DO NOT APPROVE.
  set -e -x
  function setnetrc {
    # Turn off -x so won't leak the credentials
    set +x
    hostport=$(echo $1 | cut -f3 -d /)
    host=$(echo $hostport | cut -f1 -d:)
    settings=${SETTINGS_FILE:-$HOME/.m2/settings.xml}
    echo machine $host login $(xpath -q -e "//servers/server[id='$MVN_SERVER_ID']/username/text()" $settings) password $(xpath -q -e "//servers/server[id='$MVN_SERVER_ID']/password/text()" $settings) >$HOME/.netrc
    chmod 600 $HOME/.netrc
    set -x
  }
  function putraw {
    curl -X PUT -H "Content-Type: text/plain" --netrc --upload-file $1 --url $REPO/$2
  }
  if [ "$MVN_SERVER_ID" != "" ]
  then
    echo Choices: $(xpath -q -e "//servers/server/id" ${SETTINGS_FILE:-$HOME/.m2/settings.xml}
    echo Using: $MVN_SERVER_ID
    setnetrc $REPO
    putraw $TYPE_FILE_SOURCE $TYPE_FILE_DEST
    false
  fi
  set +e +x
  ;;
test)
  echo "==> test phase script"
  if [ -f $PLUGIN_SUBDIR/tox.ini ]
  then
    set -e -x
    rm -rf .testenv
    mkdir .testenv
    virtualenv .testenv
    . .testenv/bin/activate
    pip install --upgrade pip
    pip install tox
    (cd $PLUGIN_SUBDIR; tox)
    deactivate
    rm -rf .testenv
    set +e +x
  fi
  ;;
package)
  echo "==> package phase script"
  set -e -x
  rm -rf $PLUGIN_NAME-*.wgn .pkgenv
  mkdir .pkgenv
  virtualenv .pkgenv
  . .pkgenv/bin/activate
  pip install --upgrade pip
  pip install wagon
  wagon create --format tar.gz $PLUGIN_SUBDIR
  deactivate
  rm -rf .pkgenv
  ;;
install)
  echo "==> install phase script"
  # Nothing to do
  ;;
deploy)
  echo "==> deploy phase script"
  # Just upload files to Nexus
  set -e -x
  function setnetrc {
    # Turn off -x so won't leak the credentials
    set +x
    hostport=$(echo $1 | cut -f3 -d /)
    host=$(echo $hostport | cut -f1 -d:)
    settings=${SETTINGS_FILE:-$HOME/.m2/settings.xml}
    ( echo machine $host; echo login $(xpath -q -e "//servers/server[id='$MVN_SERVER_ID']/username/text()" $settings); echo password $(xpath -q -e "//servers/server[id='$MVN_SERVER_ID']/password/text()" $settings) ) >$HOME/.netrc
    chmod 600 $HOME/.netrc
    set -x
  }
  function putraw {
    curl -X PUT -H "Content-Type: text/plain" --netrc --upload-file $1 --url $REPO/$2
  }
  setnetrc $REPO
  PLUGIN_FILE=$(echo $PLUGIN_NAME-*.wgn)
  putraw $PLUGIN_FILE plugins/$PLUGIN_FILE
  putraw $TYPE_FILE_SOURCE $TYPE_FILE_DEST
  set +e +x
  ;;
*)
  echo "==> unprocessed phase"
  ;;
esac

