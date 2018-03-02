import unittest
from unittest import mock

from docker_easyenroll.scripts import docker_enrollment


class TestEntrypoint(unittest.TestCase):

    @mock.patch('docker_easyenroll.scripts.docker_enrollment.LocalCertificateStore')
    @mock.patch('docker_easyenroll.scripts.docker_enrollment.listen_until_enrollment')
    @mock.patch('docker_easyenroll.scripts.docker_enrollment.start_dockerd')
    def test_entrypoint(self, a, b, c):
        docker_enrollment.main()
        assert a.call_count == 1
        assert b.call_count == 1
        assert c.call_count == 1
