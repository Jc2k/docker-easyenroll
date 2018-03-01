#! /usr/bin/env python3

import ctypes
from ctypes.util import find_library
import datetime
import http.server
import json
import os
import socket
import ssl

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding

SSL_DIR = os.environ.get('SSL_DIR', '/etc/docker/ssl')
SSL_PRIVATE_KEY = os.path.join(SSL_DIR, 'key.pem')
SSL_CERTIFICATE = os.path.join(SSL_DIR, 'cert.pem')
SSL_CERTIFICATE_SELFSIGNED = os.path.join(SSL_DIR, 'cert.selfsigned.pem')
SSL_CA = os.path.join(SSL_DIR, 'ca.pem')


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


backend = default_backend()


def get_private_key():
    if os.path.exists(SSL_PRIVATE_KEY):
        with open(SSL_PRIVATE_KEY, 'r') as fp:
            return serialization.load_pem_private_key(
                fp.read().encode('utf-8'),
                password=None,
                backend=backend,
            )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=backend
    )

    with open(SSL_PRIVATE_KEY, 'w') as fp:
        os.fchmod(fp.fileno(), 0o600)
        fp.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8'))

    return private_key


def get_selfsigned_certificate(private_key):
    if os.path.exists(SSL_CERTIFICATE_SELFSIGNED):
        with open(SSL_CERTIFICATE_SELFSIGNED, 'r') as fp:
            return x509.load_pem_x509_certificate(
                fp.read().encode('utf-8'),
                backend=backend,
            )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "DOCKER-ENROLLMENT"),
    ])

    cert = x509.CertificateBuilder().\
        subject_name(subject).\
        issuer_name(issuer).\
        public_key(private_key.public_key()).\
        serial_number(x509.random_serial_number()).\
        not_valid_before(datetime.datetime.utcnow()).\
        not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).\
        add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost')]),
            critical=False
        ).\
        sign(private_key, hashes.SHA256(), backend)

    with open(SSL_CERTIFICATE_SELFSIGNED, 'wb') as fp:
        fp.write(cert.public_bytes(serialization.Encoding.PEM))


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

        cert = x509.load_pem_x509_certificate(
            body['certificate'].encode('utf-8'),
            backend=backend,
        )

        with open(SSL_CA, 'rb') as fp:
            ca = x509.load_pem_x509_certificate(
                fp.read(),
                backend=backend,
            )

        try:
            ca.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return self.send_error(401, 'Invalid certificate')

        with open(SSL_CERTIFICATE, 'w') as fp:
            fp.write(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({}).encode('utf-8'))

    def do_GET(self):
        self.send_error(404, "File not found")

    def do_HEAD(self):
        self.send_error(404, "File not found")


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
        print("fd {} ({}) looks to be a TCP socket".format(i, name))
        return i

    print(fdnames)

    raise ValueError('Could not find a TCP socket')


def wait_for_enrollment():
    httpd = http.server.HTTPServer(('localhost', 2375), RequestHandler, bind_and_activate=False)
    httpd.socket = ssl.wrap_socket(
        socket.fromfd(
            get_tcp_socket_from_systemd(),
            socket.AF_INET,
            socket.SOCK_STREAM,
        ),
        server_side=True,
        # Certs used for server side
        keyfile=SSL_PRIVATE_KEY,
        certfile=SSL_CERTIFICATE_SELFSIGNED,
        # For client-side authentication
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=SSL_CA,
    )

    while not os.path.exists(SSL_CERTIFICATE):
        httpd.handle_request()


def main():
    '''
    This is a python script that can be started by systemd instead of dockerd.
    Because of socket activation it will implicitly be able to listen on the
    same socket as dockerd.

    It will 404 all API requests apart from its own enrollment URL.

    When enrollment is complete dockerd is started in place of the current
    process. Docker will inherit the sockets from the current process.

    Enrollment can only occur when a client certificate signed by the SSL_CA
    cert is presented using TLS-level client cert based authentication.
    '''

    if not os.path.exists(SSL_DIR):
        os.makedirs(SSL_DIR)

    private_key = get_private_key()
    get_selfsigned_certificate(private_key)

    if not os.path.exists(SSL_CERTIFICATE):
        wait_for_enrollment()

    # FIXME: Pass client parameters through to dockerd
    os.execv('/usr/bin/dockerd', [
        '/usr/bin/dockerd',
        '-H', 'fd://',
        '--tlsverify',
        '--tlscacert={}'.format(SSL_CA),
        '--tlscert={}'.format(SSL_CERTIFICATE),
        '--tlskey={}'.format(SSL_PRIVATE_KEY),
    ])


if __name__ == "__main__":
    main()
