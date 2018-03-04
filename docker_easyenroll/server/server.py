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

import ctypes
import http.server
import json
import os
import socket
import ssl
from ctypes.util import find_library

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from docker_easyenroll.primitives import get_private_key
from docker_easyenroll.server.certs import get_selfsigned_certificate

_libc_name = find_library('c')
if _libc_name is not None:
    libc = ctypes.CDLL(_libc_name, use_errno=True)
else:
    raise OSError('libc not found')


def _errcheck_errno(result, func, arguments):
    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return arguments


_libc_getsockopt = libc.getsockopt
_libc_getsockopt.argtypes = [
    ctypes.c_int,  # int sockfd
    ctypes.c_int,  # int level
    ctypes.c_int,  # int optname
    ctypes.c_void_p,  # void *optval
    ctypes.POINTER(ctypes.c_uint32)  # socklen_t *optlen
]
_libc_getsockopt.restype = ctypes.c_int  # 0: ok, -1: err
_libc_getsockopt.errcheck = _errcheck_errno


def _raw_getsockopt(fd, level, optname):
    optval = ctypes.c_int(0)
    optlen = ctypes.c_uint32(4)
    _libc_getsockopt(fd, level, optname,
                     ctypes.byref(optval), ctypes.byref(optlen))
    return optval.value


def get_family(sockfd):
    return _raw_getsockopt(sockfd, socket.SOL_SOCKET, 39)


def get_type(sockfd):
    return _raw_getsockopt(sockfd, socket.SOL_SOCKET, 3)


def get_tcp_socket_from_systemd():
    if 'LISTEN_FDNAMES' not in os.environ:
        raise ValueError('No systemd sockets found')
    if 'LISTEN_FDS' not in os.environ:
        raise ValueError('No systemd sockets found')

    fdnames = os.environ['LISTEN_FDNAMES'].split(':')

    if not len(fdnames) == int(os.environ['LISTEN_FDS']):
        raise ValueError('Found unexpected number of sockets')

    for i, name in enumerate(fdnames, 3):
        print(i, name, get_family(i), get_type(i))
        if get_family(i) != socket.AF_INET:
            continue
        if get_type(i) != socket.SOCK_STREAM:
            continue

        sock = socket.fromfd(
            i,
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        print("Waiting for enrollment on fd {} ({}, {})".format(i, name, sock.getsockname()))

        return sock

    raise ValueError('Could not find a TCP socket')


class RequestHandler(http.server.BaseHTTPRequestHandler):

    server_version = "DockerEnrollment/1.0"

    def do_POST(self):
        # FIXME: Limit to known URI
        # FIXME: Validated content-type header

        content_len = int(self.headers.get('content-length'))
        post_body = self.rfile.read(content_len)

        try:
            body = json.loads(post_body.decode('utf-8'))
        except json.JSONDecodeError:
            return self.send_error(401, 'Invalid body data')

        if 'certificate' not in body:
            return self.send_error(401, 'Invalid body data')

        backend = default_backend()

        try:
            cert = x509.load_pem_x509_certificate(
                body['certificate'].encode('utf-8'),
                backend=backend,
            )
        except ValueError:
            self.send_error(401, 'Invalid certificate')

        if not self.validator.validate(cert):
            self.send_error(401, 'Invalid certificate')

        self.store.set_certificate('server', cert)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({}).encode('utf-8'))

    def do_GET(self):
        self.send_error(404, "File not found")

    def do_HEAD(self):
        self.send_error(404, "File not found")

    @classmethod
    def factory(cls, store, validator):
        _store, _validator = store, validator

        class RequestHandler(cls):
            store = _store
            validator = _validator

        return RequestHandler


def listen_until_enrollment(store, validator):
    if store.has_certificate('server'):
        return

    private_key = get_private_key(store, 'server')
    get_selfsigned_certificate(store, private_key)

    httpd = http.server.HTTPServer(
        ('localhost', 2375),
        RequestHandler.factory(store, validator),
        bind_and_activate=False,
    )

    httpd.socket = ssl.wrap_socket(
        get_tcp_socket_from_systemd(),
        server_side=True,
        # Certs used for server side
        keyfile=store.get_private_key_path('server'),
        certfile=store.get_certificate_path('selfsigned'),
        # For client-side authentication
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=store.get_certificate_path('ca'),
    )

    while not store.has_certificate('server'):
        httpd.handle_request()
