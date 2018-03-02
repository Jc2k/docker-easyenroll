#! /usr/bin/env python3

from docker_easyenroll.server import listen_until_enrollment
from docker_easyenroll.server.dockerd import start_dockerd
from docker_easyenroll.server.validators import StoreCAValidator
from docker_easyenroll.store import LocalCertificateStore


def main():
    store = LocalCertificateStore('/etc/docker/ssl')
    listen_until_enrollment(store, StoreCAValidator(store))
    start_dockerd(store)


if __name__ == "__main__":
    main()
