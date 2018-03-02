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
