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

    @mock.patch('docker_easyenroll.scripts.docker_enrollment.LocalCertificateStore')
    @mock.patch('docker_easyenroll.scripts.docker_enrollment.listen_until_enrollment')
    @mock.patch('docker_easyenroll.scripts.docker_enrollment.start_dockerd')
    def test_entrypoint_pass_args_to_docker(self, start_dockerd, listen_until_enrollment, LCS):
        docker_enrollment.main(['--', '--log-driver=journald'])

        assert LCS.call_count == 1

        assert listen_until_enrollment.call_count == 1
        assert isinstance(listen_until_enrollment.call_args[0][1], StoreCAValidator)

        assert start_dockerd.call_count == 1
        start_dockerd.assert_called_with(LCS.return_value, ['--log-driver=journald'])
