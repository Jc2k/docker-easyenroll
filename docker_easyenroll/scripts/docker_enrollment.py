#! /usr/bin/env python3

import argparse
import sys

from docker_easyenroll.server import listen_until_enrollment
from docker_easyenroll.server.dockerd import start_dockerd
from docker_easyenroll.server.validators import (
    GuestInfoCAValidator,
    StoreCAValidator,
)
from docker_easyenroll.store import LocalCertificateStore


def main(argv=None):
    argv = argv if argv is not None else sys.argv

    if '--' in argv:
        idx = argv.index("--")
        argv, extra = argv[:idx], argv[idx + 1:]
    else:
        extra = []

    parser = argparse.ArgumentParser()
    parser.add_argument('--storedir', '-s', action='store')
    parser.add_argument('--guestinfoca', action='store')
    args = parser.parse_args(sys.argv if argv is None else argv)

    store = LocalCertificateStore(args.storedir)

    if args.guestinfoca:
        validator = GuestInfoCAValidator(args.guestinfoca)
    else:
        validator = StoreCAValidator(store)

    listen_until_enrollment(store, validator)
    start_dockerd(store, extra)
