#! /usr/bin/env python3

from docker_easyenroll.store import LocalCertificateStore
from docker_easyenroll.server import listen_until_enrollment
from docker_easyenroll.server.validators import StoreCAValidator
from docker_easyenroll.server.docker import start_dockerd


def main():
    store = LocalCertificateStore('/etc/docker/ssl')
    listen_until_enrollment(store, StoreCAValidator(store))
    start_dockerd(store)


if __name__ == "__main__":
    main()
