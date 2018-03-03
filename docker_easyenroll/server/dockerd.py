import os


def start_dockerd(store, extra=None):
    extra = extra or []

    # FIXME: Pass client parameters through to dockerd
    os.execv('/usr/bin/dockerd', [
        '/usr/bin/dockerd',
        '-H', 'fd://',
        '--tlsverify',
        '--tlscacert={}'.format(store.get_certificate_path('ca')),
        '--tlscert={}'.format(store.get_certificate_path('server')),
        '--tlskey={}'.format(store.get_private_key_path('server')),
    ] + extra)
