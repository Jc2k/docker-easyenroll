import shutil
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization

from docker_easyenroll.ca import get_ca_certificate
from docker_easyenroll.client import get_client_certificate
from docker_easyenroll.server import validators
from docker_easyenroll.store import LocalCertificateStore


class TestGuestInfoValidator(unittest.TestCase):

    def test_happy_path(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        store = LocalCertificateStore(tmpdir)
        _, ca = get_ca_certificate(store)
        _, cert = get_client_certificate(store)

        validator = validators.GuestInfoCAValidator('ca')
        with mock.patch('docker_easyenroll.server.validators.subprocess') as subprocess:
            subprocess.check_output.return_value = ca.public_bytes(serialization.Encoding.PEM)

            assert validator.validate(cert)

            subprocess.check_output.assert_called_with([
                '/usr/bin/vmware-rpctool',
                'info-get guestinfo.ca'
            ])