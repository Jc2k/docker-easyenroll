from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def get_private_key(store, name):
    if store.has_private_key(name):
        return store.get_private_key(name)
    private_key = generate_private_key()
    store.set_private_key(name, private_key)
    return private_key
