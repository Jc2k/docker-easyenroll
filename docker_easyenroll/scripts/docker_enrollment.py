#! /usr/bin/env python3

# Copyright 2017 John Carr
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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
    argv = argv if argv is not None else sys.argv[1:]

    if '--' in argv:
        idx = argv.index("--")
        argv, extra = argv[:idx], argv[idx + 1:]
    else:
        extra = []

    parser = argparse.ArgumentParser()
    parser.add_argument('--storedir', '-s', action='store', default="/etc/docker/ssl")
    parser.add_argument('--guestinfoca', action='store')
    args = parser.parse_args(sys.argv if argv is None else argv)

    store = LocalCertificateStore(args.storedir)

    if args.guestinfoca:
        validator = GuestInfoCAValidator(store, args.guestinfoca)
    else:
        validator = StoreCAValidator(store)

    listen_until_enrollment(store, validator)
    start_dockerd(store, extra)
