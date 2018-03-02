import os

from .base import CertificateStore


class LocalCertificateStore(CertificateStore):

    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            os.makedirs(path)

    def _get_path(self, name, suffix):
        return os.path.join(self.path, '.'.join((name, suffix)))

    def get_private_key_path(self, name):
        return self._get_path(name, 'key')

    def has_private_key(self, name):
        return os.path.exists(self.get_private_key_path(name))

    def get_private_key(self, name):
        with open(self.get_private_key_path(name), 'rb') as fp:
            return self.deserialize_private_key(fp.read())

    def set_private_key(self, name, private_key):
        with open(self.get_private_key_path(name), 'wb') as fp:
            os.fchmod(fp.fileno(), 0o600)
            fp.write(self.serialize_private_key(private_key))

    def get_certificate_path(self, name):
        return self._get_path(name, 'pem')

    def has_certificate(self, name):
        return os.path.exists(self.get_certificate_path(name))

    def get_certificate(self, name):
        with open(self.get_certificate_path(name), 'rb') as fp:
            return self.deserialize_certificate(fp.read())

    def set_certificate(self, name, cert):
        with open(self.get_certificate_path(name), 'wb') as fp:
            fp.write(self.serialize_certificate(cert))
