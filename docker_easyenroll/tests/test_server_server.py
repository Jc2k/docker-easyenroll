import io
import json
import shutil
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
        self.assertRaises(HttpError, self.request_handler.do_GET)
