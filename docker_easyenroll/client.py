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

import datetime
import ipaddress
import socket
import ssl

import requests
import requests.exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import oid
from cryptography.x509.oid import NameOID

from .ca import get_ca_certificate
from .exceptions import TransientError
from .primitives import get_private_key
from .utils import build_key_usage, fingerprint, is_signed_by


def get_client_certificate(store):
    if store.has_certificate('client'):
        return store.get_private_key('client'), store.get_certificate('client')

    private_key = get_private_key(store, 'client')
    ca_private_key, ca_cert = get_ca_certificate(store)

    cn = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, 'client')])
    now = datetime.datetime.utcnow()
    ku = build_key_usage(['content_commitment', 'digital_signature', 'key_encipherment'])
    eku = x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CLIENT_AUTH])
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski)

    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())

    certificate = x509.CertificateBuilder().\
        public_key(private_key.public_key()).\
        serial_number(x509.random_serial_number()).\
        not_valid_before(now).\
        not_valid_after(now + datetime.timedelta(days=4096)).\
        add_extension(eku, critical=False).\
        add_extension(ku, critical=False).\
        add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=False,
        ).\
        add_extension(ski, critical=False).\
        add_extension(aki, critical=False).\
        subject_name(cn).\
        issuer_name(ca_cert.subject).\
        sign(ca_private_key, hashes.SHA256(), default_backend())

    store.set_certificate('client', certificate)

    return private_key, certificate


def build_certificate_for_server(store, ip_address, public_key):
    ca_key, ca = get_ca_certificate(store)

    now = datetime.datetime.utcnow()

    serial_number = x509.random_serial_number()

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip_address)])
    san = x509.SubjectAlternativeName([
        x509.IPAddress(ipaddress.ip_address(ip_address))
    ])

    ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski)

    key_usage = build_key_usage([
        'content_commitment',
        'digital_signature',
        'key_encipherment'
    ])

    extended_key_usage = x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.SERVER_AUTH])

    certificate = x509.CertificateBuilder().\
        public_key(public_key).\
        serial_number(serial_number).\
        not_valid_before(now).\
        not_valid_after(now + datetime.timedelta(days=4096)).\
        add_extension(extended_key_usage, critical=False).\
        add_extension(key_usage, critical=False).\
        add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=False,
        ).\
        add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False).\
        add_extension(san, critical=False).\
        add_extension(aki, critical=False).\
        subject_name(name).\
        issuer_name(ca.subject).\
        sign(ca_key, hashes.SHA256(), default_backend())

    return certificate


def get_certificate_for_server(store, management_ip):
    '''
    Connect to docker worker at TLS level (not HTTP at this stage) and retrieve
    and decode ASN encoded cert.

    The server will only accept connections from certificates signed by our CA.
    '''

    # Make sure ca and client certs exist in the store before connecting to
    # anything
    get_ca_certificate(store)
    get_client_certificate(store)

    try:
        sock = socket.create_connection((management_ip, 2375))
    except OSError as e:
        raise TransientError(str(e))

    try:
        sock = ssl.wrap_socket(
            sock,
            keyfile=store.get_private_key_path('client'),
            certfile=store.get_certificate_path('client'),
            ca_certs=store.get_certificate_path('ca'),
            cert_reqs=ssl.CERT_NONE,
            do_handshake_on_connect=True,
        )

        asn_cert = sock.getpeercert(True)
    finally:
        sock.close()

    return default_backend().load_der_x509_certificate(asn_cert)


def push_certificate_to_server(store, server_ip, cert):
    print(requests.exceptions.ConnectionError)
    try:
        requests.post(
            f'https://{server_ip}:2375',
            json={
                'certificate': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            },
            verify=False,
            cert=(
                store.get_certificate_path('client'),
                store.get_private_key_path('client'),
            ),
        )
    except requests.exceptions.ConnectionError as e:
        raise TransientError(e)


def ensure_server_enrolled(store, server_ip):
    ca_private_key, ca_cert = get_ca_certificate(store)

    cert = get_certificate_for_server(store, server_ip)

    name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    if name == 'DOCKER-ENROLLMENT' and not is_signed_by(cert, ca_cert):
        new_cert = build_certificate_for_server(store, server_ip, cert.public_key())
        push_certificate_to_server(store, server_ip, new_cert)
        return fingerprint(new_cert)

    if name == server_ip and is_signed_by(cert, ca_cert):
        # Certificate only valid if signed by CA cert and has right CN
        return fingerprint(cert)

    # Cert is neither a valid self-signed enrollment cert nor signed by our CA
    raise RuntimeError('Invalid enrollment')
