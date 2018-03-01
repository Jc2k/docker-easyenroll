import datetime
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import oid


def random_subject_name(prefix):
    return x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, prefix + str(uuid.uuid4())),
    ])


def build_key_usage(key_usage):
    possible_uses = [
        'content_commitment', 'key_encipherment', 'data_encipherment',
        'key_cert_sign', 'crl_sign', 'encipher_only', 'decipher_only',
        'digital_signature', 'key_agreement',
    ]
    key_usage_dict = {key: False for key in possible_uses}
    key_usage_dict.update({key: True for key in key_usage})
    return x509.KeyUsage(**key_usage_dict)


def get_basic_certificate(public_key, days=365*10, ca=False, key_usage=None):
    now = datetime.datetime.utcnow()

    builder = x509.CertificateBuilder().\
        public_key(public_key).\
        serial_number(x509.random_serial_number()).\
        not_valid_before(now).\
        not_valid_after(now + datetime.timedelta(days=days)).\
        add_extension(
            x509.BasicConstraints(ca=ca, path_length=None),
            critical=False,
        ).\
        add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)

    if key_usage:
        builder = builder.add_extension(build_key_usage(key_usage), critical=False)

    return builder


def serialize_certificate(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')


def fingerprint(cert):
    return ':'.join('%02x' % c for c in cert.fingerprint(hashes.SHA256()))


def is_signed_by(cert, ca):
    try:
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False

    return True
