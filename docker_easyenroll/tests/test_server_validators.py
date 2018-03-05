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
from unittest import mock

from cryptography.hazmat.primitives import serialization

from docker_easyenroll.ca import get_ca_certificate
from docker_easyenroll.client import get_client_certificate
from docker_easyenroll.server import validators
from docker_easyenroll.store import LocalCertificateStore


class TestBaseCAValidator(unittest.TestCase):

    def test_not_implemented(self):
        validator = validators._BaseCAValidator()
        self.assertRaises(NotImplementedError, validator.get_ca_certificate)


class TestStoreCAValidator(unittest.TestCase):

    def test_valid_cert(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        store = LocalCertificateStore(tmpdir)
        _, ca = get_ca_certificate(store)
        _, client = get_client_certificate(store)

        validator = validators.StoreCAValidator(store)
        assert validator.validate(client)

    def test_invalid_cert(self):
        # CA 1 + client 1
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        store = LocalCertificateStore(tmpdir)
        _, ca = get_ca_certificate(store)
        _, client = get_client_certificate(store)

        # CA 2
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        store = LocalCertificateStore(tmpdir)
        _, ca = get_ca_certificate(store)

        validator = validators.StoreCAValidator(store)
        assert not validator.validate(client)


class TestGuestInfoCAValidator(unittest.TestCase):

    def test_happy_path(self):
        client_tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, client_tmpdir)
        client_store = LocalCertificateStore(client_tmpdir)

        _, ca = get_ca_certificate(client_store)
        _, cert = get_client_certificate(client_store)

        server_tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, server_tmpdir)
        server_store = LocalCertificateStore(server_tmpdir)

        validator = validators.GuestInfoCAValidator(server_store, 'ca')
        with mock.patch('docker_easyenroll.server.validators.subprocess') as subprocess:
            subprocess.check_output.return_value = ca.public_bytes(serialization.Encoding.PEM)

            assert validator.validate(cert)

            subprocess.check_output.assert_called_with([
                '/usr/bin/vmware-rpctool',
                'info-get guestinfo.ca'
            ])
