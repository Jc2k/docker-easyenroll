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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


def get_selfsigned_certificate(store, private_key):
    if store.has_certificate('selfsigned'):
        return store.get_certificate('selfsigned')

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "DOCKER-ENROLLMENT"),
    ])

    backend = default_backend()

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

    store.set_certificate('selfsigned', cert)

    return cert
