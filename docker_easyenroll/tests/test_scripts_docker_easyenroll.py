import unittest
from unittest import mock

from docker_easyenroll.scripts import docker_enrollment
from docker_easyenroll.server.validators import (
    GuestInfoCAValidator,
    StoreCAValidator,
)


class TestEntrypoint(unittest.TestCase):

    @mock.patch('docker_easyenroll.scripts.docker_enrollment.LocalCertificateStore')
    @mock.patch('docker_easyenroll.scripts.docker_enrollment.listen_until_enrollment')
    @mock.patch('docker_easyenroll.scripts.docker_enrollment.start_dockerd')
    def test_entrypoint(self, a, listen_until_enrollment, c):
        docker_enrollment.main([])
        assert a.call_count == 1

        assert listen_until_enrollment.call_count == 1
        assert isinstance(listen_until_enrollment.call_args[0][1], StoreCAValidator)

        assert c.call_count == 1

    @mock.patch('docker_easyenroll.scripts.docker_enrollment.LocalCertificateStore')
    @mock.patch('docker_easyenroll.scripts.docker_enrollment.listen_until_enrollment')
    @mock.patch('docker_easyenroll.scripts.docker_enrollment.start_dockerd')
    def test_entrypoint_guestinfoca(self, a, listen_until_enrollment, c):
        docker_enrollment.main(['--guestinfoca', 'ca'])
        assert a.call_count == 1

        assert listen_until_enrollment.call_count == 1
        assert isinstance(listen_until_enrollment.call_args[0][1], GuestInfoCAValidator)

        assert c.call_count == 1
