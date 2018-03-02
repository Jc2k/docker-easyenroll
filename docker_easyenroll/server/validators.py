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

    def get_ca_certificate(self):
        return self.store.get_certificate(self.name)


class GuestInfoCAValidator(_BaseCAValidator):

    def get_ca_certificate(self):
        return RuntimeError('No known CA')
