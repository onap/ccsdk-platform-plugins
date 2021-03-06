# org.onap.ccsdk
# ============LICENSE_START====================================================
# =============================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
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

from setuptools import setup, find_packages

setup(
  name="pgaas",
  version="1.2.0",
  packages=find_packages(),
  author="AT&T",
  description=("Cloudify plugin for pgaas/pgaas."),
  license="http://www.apache.org/licenses/LICENSE-2.0",
  keywords="",
  url="https://onap.org",
  zip_safe=False,
  install_requires=[
    'psycopg2-binary',
    'cloudify-common>=5.0.5',
  ],
)
