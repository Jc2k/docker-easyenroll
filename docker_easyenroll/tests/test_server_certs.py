# Copyright 2017 John Carr
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import shutil
import tempfile
import unittest

from docker_easyenroll.primitives import get_private_key
from docker_easyenroll.server.certs import get_selfsigned_certificate
from docker_easyenroll.store import LocalCertificateStore
from docker_easyenroll.utils import fingerprint


class TestPrimitives(unittest.TestCase):

    def test_get_private_key(self):
        cert_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, cert_dir)

        store = LocalCertificateStore(cert_dir)

        private_key = get_private_key(store, 'server')

        cert1 = get_selfsigned_certificate(store, private_key)
        cert2 = get_selfsigned_certificate(store, private_key)
        assert fingerprint(cert1) == fingerprint(cert2)
