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
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from docker_easyenroll.ca import get_ca_certificate
from docker_easyenroll.client import ensure_server_enrolled
from docker_easyenroll.exceptions import TransientError
from docker_easyenroll.server.server import listen_until_enrollment
from docker_easyenroll.server.validators import StoreCAValidator
from docker_easyenroll.store import LocalCertificateStore


class TestIntegration(unittest.TestCase):

    def test_integration(self):
        cert_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, cert_dir)

        store = LocalCertificateStore(cert_dir)
        get_ca_certificate(store)

        def get_tcp_socket_from_systemd():
            sock = socket.socket()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', 2375))
            sock.listen(5)
            return sock

        patcher = mock.patch(
            'docker_easyenroll.server.server.get_tcp_socket_from_systemd',
            side_effect=get_tcp_socket_from_systemd
        )
        self.addCleanup(patcher.stop)
        patcher.start()

        def server():
            store = LocalCertificateStore(cert_dir)
            listen_until_enrollment(store, StoreCAValidator(store))

        server_thread = threading.Thread(target=server)
        server_thread.start()

        time.sleep(0.1)

        for i in range(5):
            try:
                ensure_server_enrolled(store, '127.0.0.1')
                break
            except TransientError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError('Failed to connect to server')

        server_thread.join()
