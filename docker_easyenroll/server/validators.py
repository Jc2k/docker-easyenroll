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

import subprocess

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding


class _BaseValidator(object):

    def validate(self, certificate):
        return False


class AcceptFirstClientValidator(_BaseValidator):

    def validate(self, certificate):
        return True


class _BaseCAValidator(_BaseValidator):

    def get_ca_certificate(self):
        raise NotImplementedError(self.get_ca_certificate)

    def validate(self, certificate):
        ca = self.get_ca_certificate()

        try:
            ca.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False

        return True


class StoreCAValidator(_BaseCAValidator):

    def __init__(self, store, name='ca'):
        self.store = store
        self.name = name

    def get_ca_certificate(self):
        return self.store.get_certificate(self.name)


class GuestInfoCAValidator(_BaseCAValidator):

    def __init__(self, store, key):
        '''
        A validator that uses a CA certificate stored in guestinfo.

        key: A guestinfo key that contains a CA certificate.
        '''
        self.store = store
        self.key = key

    def guestinfo(self, key):
        try:
            output = subprocess.check_output(
                ['/usr/bin/vmware-rpctool', 'info-get guestinfo.{}'.format(key)]
            ).strip()
        except subprocess.CalledProcessError:
            raise KeyError(key)
        return output

    def get_ca_certificate(self):
        ca_certificate = self.store.deserialize_certificate(self.guestinfo(self.key))
        self.store.set_certificate('ca', ca_certificate)
        return ca_certificate
