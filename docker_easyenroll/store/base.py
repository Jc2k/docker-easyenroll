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
from cryptography.hazmat.primitives import serialization


class CertificateStore(object):

    encoding = serialization.Encoding.PEM

    def deserialize_private_key(self, serialized_key):
        return serialization.load_pem_private_key(
            serialized_key,
            password=None,
            backend=default_backend(),
        )

    def serialize_private_key(self, private_key):
        return private_key.private_bytes(
            encoding=self.encoding,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def deserialize_certificate(self, serialized_cert):
        return x509.load_pem_x509_certificate(serialized_cert, default_backend())

    def serialize_certificate(self, cert):
        return cert.public_bytes(self.encoding)
