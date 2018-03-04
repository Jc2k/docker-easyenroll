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
