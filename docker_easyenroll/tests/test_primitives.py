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
from docker_easyenroll.store import LocalCertificateStore


class TestPrimitives(unittest.TestCase):

    def test_get_private_key(self):
        cert_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, cert_dir)

        store = LocalCertificateStore(cert_dir)

        key1 = get_private_key(store, 'test')
        key2 = get_private_key(store, 'test')
        assert key1.public_key().public_numbers() == key2.public_key().public_numbers()

        key3 = get_private_key(store, 'test3')
        assert key1.public_key().public_numbers() != key3.public_key().public_numbers()
