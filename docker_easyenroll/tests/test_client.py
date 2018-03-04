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

import datetime
import shutil
import tempfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from docker_easyenroll import client
from docker_easyenroll.primitives import generate_private_key
from docker_easyenroll.store import LocalCertificateStore
from docker_easyenroll.utils import fingerprint, is_signed_by


class TestClient(unittest.TestCase):

    @mock.patch('docker_easyenroll.client.socket')
    @mock.patch('docker_easyenroll.client.ssl')
    @mock.patch('docker_easyenroll.client.requests')
    def test_enrollment(self, requests, ssl, socket):
        backend = default_backend()

        private_key = generate_private_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "DOCKER-ENROLLMENT"),
        ])

        cert = x509.CertificateBuilder().\
            subject_name(subject).\
            issuer_name(issuer).\
            public_key(private_key.public_key()).\
            serial_number(x509.random_serial_number()).\
            not_valid_before(datetime.datetime.utcnow()).\
            not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).\
            add_extension(
                x509.SubjectAlternativeName([x509.DNSName('localhost')]),
                critical=False
            ).\
            sign(private_key, hashes.SHA256(), backend)

        ssl.wrap_socket.return_value.getpeercert.return_value = \
            cert.public_bytes(serialization.Encoding.DER)

        store = LocalCertificateStore('/tmp')
        client.ensure_server_enrolled(store, '8.8.8.8')

        assert requests.post.call_count == 1
        args, kwargs = requests.post.call_args_list[0]

        # We should only be connecting to addresses retrieved from etcd
        assert args[0] == 'https://8.8.8.8:2375'

        # We must POST a valid certificate to the docker we are adopting
        assert kwargs['json']['certificate'].startswith('-----BEGIN CERTIFICATE-----\n')
        assert kwargs['json']['certificate'].endswith('\n-----END CERTIFICATE-----\n')

        new_cert = x509.load_pem_x509_certificate(
            kwargs['json']['certificate'].encode('utf-8'),
            default_backend()
        )

        # New certificate must be for the same system we connected to
        assert new_cert.public_key().public_numbers() == cert.public_key().public_numbers()

        # The cert issued by our API must be signed by the right cert/key
        issuer = store.get_certificate('ca')
        assert is_signed_by(new_cert, issuer)

        # We haven't signed its certificate yet, so we can't verify the cert of
        # the Docker we are adopting
        assert kwargs['verify'] is False

        # We *must* use our SSL client verification so that the Docker we are
        # are adopting trusts us
        assert kwargs['cert'] == (
            store.get_certificate_path('client'),
            store.get_private_key_path('client'),
        )

    @mock.patch('docker_easyenroll.client.socket')
    @mock.patch('docker_easyenroll.client.ssl')
    @mock.patch('docker_easyenroll.client.requests')
    def test_enrollment_idempotent(self, requests, ssl, socket):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        client_key = generate_private_key()

        store = LocalCertificateStore(tmpdir)
        cert = client.build_certificate_for_server(store, '8.8.8.8', client_key.public_key())

        ssl.wrap_socket.return_value.getpeercert.return_value = \
            cert.public_bytes(serialization.Encoding.DER)

        cert_fingerprint = client.ensure_server_enrolled(store, '8.8.8.8')

        # Cert shouldn't have changed
        assert cert_fingerprint == fingerprint(cert)

        assert requests.post.call_count == 0

    @mock.patch('docker_easyenroll.client.socket')
    @mock.patch('docker_easyenroll.client.ssl')
    @mock.patch('docker_easyenroll.client.requests')
    def test_enrollment_invalid_enrollment(self, requests, ssl, socket):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        client_key = generate_private_key()

        store = LocalCertificateStore(tmpdir)
        cert = client.build_certificate_for_server(store, '8.8.8.8', client_key.public_key())

        ssl.wrap_socket.return_value.getpeercert.return_value = \
            cert.public_bytes(serialization.Encoding.DER)

        store = LocalCertificateStore('/tmp')
        self.assertRaises(RuntimeError, client.ensure_server_enrolled, store, '8.8.8.8')

        assert requests.post.call_count == 0
