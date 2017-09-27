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

"""

This is a mock psycopg2 module.

"""

class csr(object):
  def __init__(self, **kwargs):
    pass

  def execute(self, cmd, exc = None):
    pass
  
  def close(self):
    pass

  def __iter__(self):
    return iter([])
  
class conn(object):
  def __init__(self, **kwargs):
    pass

  def __enter__(self):
    return self
  
  def __exit__(self, exc_type, exc_value, traceback):
    pass

  def cursor(self):
    return csr()

def connect(**kwargs):
  return conn()

