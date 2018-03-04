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

import io
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization

from docker_easyenroll.client import get_client_certificate
from docker_easyenroll.server import server
from docker_easyenroll.server.validators import (
    AcceptFirstClientValidator,
    _BaseValidator,
)
from docker_easyenroll.store import LocalCertificateStore


class HttpError(Exception):
    pass


class MockRequestHandler(server.RequestHandler):

    request_version = ''

    def __init__(self):
        self.wfile = io.BytesIO()

    def log_request(self, *args, **kwargs):
        pass

    def send_error(self, code, message):
        raise HttpError(message)


class TestRequestHandler(unittest.TestCase):

    def setUp(self):
        self.request_handler = MockRequestHandler()

    def test_invalid_json(self):
        post_body = b'invalid_json'
        self.request_handler.headers = {'content-length': len(post_body)}
        rfile = self.request_handler.rfile = mock.Mock()
        rfile.read.return_value = post_body
        self.assertRaises(HttpError, self.request_handler.do_POST)

    def test_no_cert(self):
        post_body = b'{}'
        self.request_handler.headers = {'content-length': len(post_body)}
        rfile = self.request_handler.rfile = mock.Mock()
        rfile.read.return_value = post_body
        self.assertRaises(HttpError, self.request_handler.do_POST)

    def test_invalid_cert(self):
        post_body = b'{"certificate": "zz"}'
        self.request_handler.headers = {'content-length': len(post_body)}
        rfile = self.request_handler.rfile = mock.Mock()
        rfile.read.return_value = post_body
        self.assertRaises(HttpError, self.request_handler.do_POST)

    def test_validator_failed(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        store = LocalCertificateStore(tmpdir)
        _, cert = get_client_certificate(store)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        post_body = json.dumps({'certificate': cert_pem}).encode('utf-8')
        self.request_handler.headers = {'content-length': len(post_body)}
        rfile = self.request_handler.rfile = mock.Mock()
        rfile.read.return_value = post_body
        self.request_handler.validator = _BaseValidator()
        self.assertRaises(HttpError, self.request_handler.do_POST)

    def test_POST_success(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        store = LocalCertificateStore(tmpdir)
        _, cert = get_client_certificate(store)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        post_body = json.dumps({'certificate': cert_pem}).encode('utf-8')
        self.request_handler.headers = {'content-length': len(post_body)}
        rfile = self.request_handler.rfile = mock.Mock()
        rfile.read.return_value = post_body
        self.request_handler.validator = AcceptFirstClientValidator()

        self.request_handler.store = store

        assert not store.has_certificate('server')
        self.request_handler.do_POST()
        assert store.has_certificate('server')

    def test_get(self):
        self.assertRaises(HttpError, self.request_handler.do_GET)

    def test_head(self):
        self.assertRaises(HttpError, self.request_handler.do_HEAD)


class TestSocketUtils(unittest.TestCase):

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires linux")
    def test_get_family(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        assert server.get_family(sock.fileno()) == socket.AF_INET

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires linux")
    def test_get_type(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        assert server.get_type(sock.fileno()) == socket.SOCK_STREAM

    @mock.patch.dict(os.environ, {})
    def test_get_tcp_socket_from_systemd_no_FDNAMES(self):
        self.assertRaises(ValueError, server.get_tcp_socket_from_systemd)

    @mock.patch.dict(os.environ, {})
    def test_get_tcp_socket_from_systemd_no_FDS(self):
        os.environ['LISTEN_FDNAMES'] = 'name1'
        self.assertRaises(ValueError, server.get_tcp_socket_from_systemd)

    @mock.patch.dict(os.environ, {})
    def test_get_tcp_socket_from_systemd_FDNAMES_FDS_mismatch(self):
        os.environ['LISTEN_FDNAMES'] = 'name1:name2:name3'
        os.environ['LISTEN_FDS'] = '10'
        self.assertRaises(ValueError, server.get_tcp_socket_from_systemd)

    @mock.patch.dict(os.environ, {})
    @mock.patch.object(server, 'get_family', return_value=socket.AF_UNIX)
    @mock.patch.object(server, 'get_type', return_value=socket.SOCK_STREAM)
    @mock.patch('socket.fromfd')
    def test_get_tcp_socket_from_systemd_wrong_fam(self, fromfd, get_type, get_family):
        os.environ['LISTEN_FDNAMES'] = 'name1'
        os.environ['LISTEN_FDS'] = '1'

        self.assertRaises(ValueError, server.get_tcp_socket_from_systemd)

    @mock.patch.dict(os.environ, {})
    @mock.patch.object(server, 'get_family', return_value=socket.AF_INET)
    @mock.patch.object(server, 'get_type', return_value=socket.SOCK_DGRAM)
    @mock.patch('socket.fromfd')
    def test_get_tcp_socket_from_systemd_wrong_type(self, fromfd, get_type, get_family):
        os.environ['LISTEN_FDNAMES'] = 'name1'
        os.environ['LISTEN_FDS'] = '1'

        self.assertRaises(ValueError, server.get_tcp_socket_from_systemd)

    @mock.patch.dict(os.environ, {})
    @mock.patch.object(server, 'get_family', return_value=socket.AF_INET)
    @mock.patch.object(server, 'get_type', return_value=socket.SOCK_STREAM)
    @mock.patch('socket.fromfd')
    def test_get_tcp_socket_from_systemd(self, fromfd, get_type, get_family):
        os.environ['LISTEN_FDNAMES'] = 'name1'
        os.environ['LISTEN_FDS'] = '1'

        sentinel = fromfd.return_value = mock.MagicMock()

        sock = server.get_tcp_socket_from_systemd()
        assert sock == sentinel

        fromfd.assert_called_with(3, socket.AF_INET, socket.SOCK_STREAM)
