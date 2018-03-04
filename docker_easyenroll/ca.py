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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import oid

from .primitives import get_private_key
from .utils import get_basic_certificate


def get_ca_certificate(store):
    if store.has_certificate('ca'):
        return store.get_private_key('ca'), store.get_certificate('ca')

    private_key = get_private_key(store, 'ca')
    public_key = private_key.public_key()

    cn = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, '*')])
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)

    cert = get_basic_certificate(public_key, ca=True, key_usage=('key_cert_sign', 'crl_sign')).\
        subject_name(cn).\
        issuer_name(cn).\
        add_extension(aki, critical=False).\
        sign(private_key, hashes.SHA256(), default_backend())

    store.set_certificate('ca', cert)

    return private_key, cert
