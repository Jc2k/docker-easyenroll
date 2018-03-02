import subprocess

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding

from docker_easyenroll.store.base import CertificateStore


class _BaseValidator(object):

    def validate(self, certificate):
        return False


class AcceptFirstClientValidator(_BaseValidator):

    def validate(self, certificate):
        return True


class _BaseCAValidator(_BaseValidator):

    def get_ca_certificate(self):
        return RuntimeError('No known CA')

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

    def __init__(self, key):
        '''
        A validator that uses a CA certificate stored in guestinfo.

        key: A guestinfo key that contains a CA certificate.
        '''
        self.key = key

        # Just so we can reuse the deserialize code
        self.store = CertificateStore()

    def guestinfo(self, key):
        try:
            output = subprocess.check_output(
                ['/usr/bin/vmware-rpctool', 'info-get guestinfo.{}'.format(key)]
            ).strip()
        except subprocess.CalledProcessError:
            raise KeyError(key)
        return output

    def get_ca_certificate(self):
        return self.store.deserialize_certificate(self.guestinfo(self.key))
