import shutil
import tempfile
import unittest
from unittest import mock

from docker_easyenroll.server.dockerd import start_dockerd
from docker_easyenroll.store import LocalCertificateStore


class TestDockerd(unittest.TestCase):

    @mock.patch('os.execv')
    def test_start_dockerd(self, execv):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        store = LocalCertificateStore(tmpdir)

        start_dockerd(store)

        execv.assert_called_with('/usr/bin/dockerd', [
            '/usr/bin/dockerd',
            '-H', 'fd://',
            '--tlsverify',
            '--tlscacert={}'.format(store.get_certificate_path('ca')),
            '--tlscert={}'.format(store.get_certificate_path('server')),
            '--tlskey={}'.format(store.get_private_key_path('server')),
        ])

    @mock.patch('os.execv')
    def test_start_dockerd_with_args(self, execv):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        store = LocalCertificateStore(tmpdir)

        start_dockerd(store, ['--log-driver=journald'])

        execv.assert_called_with('/usr/bin/dockerd', [
            '/usr/bin/dockerd',
            '-H', 'fd://',
            '--tlsverify',
            '--tlscacert={}'.format(store.get_certificate_path('ca')),
            '--tlscert={}'.format(store.get_certificate_path('server')),
            '--tlskey={}'.format(store.get_private_key_path('server')),
            '--log-driver=journald',
        ])
