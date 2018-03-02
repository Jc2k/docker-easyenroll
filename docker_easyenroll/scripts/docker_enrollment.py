#! /usr/bin/env python3

import os

from docker_easyenroll.store import LocalCertificateStore
from docker_easyenroll.server import listen_until_enrollment
from docker_easyenroll.server.validators import StoreCAValidator


def main():
    store = LocalCertificateStore('/etc/docker/ssl')

    listen_until_enrollment(store, StoreCAValidator(store))

    # FIXME: Pass client parameters through to dockerd
    os.execv('/usr/bin/dockerd', [
        '/usr/bin/dockerd',
        '-H', 'fd://',
        '--tlsverify',
        '--tlscacert={}'.format(store.get_certificate_path('ca')),
        '--tlscert={}'.format(store.get_certificate_path('server')),
        '--tlskey={}'.format(store.get_private_key_path('server')),
    ])


if __name__ == "__main__":
    main()
