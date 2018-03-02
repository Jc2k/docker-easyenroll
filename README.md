# docker-easyenroll

[![PyPI](https://img.shields.io/pypi/v/docker_easyenroll.svg)](https://pypi.python.org/pypi/docker_easyenroll) [![Codecov](https://img.shields.io/codecov/c/github/Jc2k/docker_easyenroll.svg)](https://codecov.io/gh/Jc2k/docker_easyenroll)

A framework for implementing Docker TLS enrollment schemes, including an SSH style 'pair on first connect' scheme.


## A simple example

We have 2 entities that we want to 'pair'. The client (the entity that makes API calls to Docker) and the server (the Docker instance that we need to control) must establish mutual trust. This mutual trust is usually established entirely out of band:

 * The sysadmin maintains a PKI CA.
 * The sysadmin generates a private key and CSR for the client and signs it with the CA key.
 * The sysadmin generates a private key and CSR for the Docker API and signs it with the CA key.

After this is done the client can verify that it has a direct and trusted connection to the Docker API and the Docker API.

Assuming that the SSH sessions used in this process where appropriately validated (i.e. you checked the SSH host keys out of band) then this is the most secure way to setup mutual trust. The private key material never left the server it is needed on and there was no opportunity to MITM this process.

When needing to communicate with multiple Docker services this process doesn't scale up very well. A fully best practice PKI may have offline keys or a HSM that makes the process cumbersome.

This project aims to implement enrollment that is reasonably secure and is suited to cloud or otherwise elastic environments.


## What can we do

This project provides an agent that runs before `dockerd` and handles enrollment. This agent runs on the same port as `dockerd`. It uses `systemd` socket activation. This means that it won't drop any connections between enrollment completing and `dockerd` starting.

It also provides a python client for connecting to the enrollment agent and handling idempotent delivery of a certificate signed by a CA it manages.

It provides hooks for implementing validation of TLS certificates on both ends of this process.


## Docker server setup

Obviously you need to install Docker itself:

```
apt-get -y install apt-transport-https ca-certificates curl software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -

add-apt-repository \
       "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
       $(lsb_release -cs) \
       stable"

apt-get update
apt-get -y install docker-ce
```

If you are using a built in enrollment scheme you just need to install our python package:

```
apt-get install -y python3-pip
pip3 install -U docker_easyenroll
```

We create a systemd socket and configure docker to use it.

```
mkdir -p /etc/docker/ssl

cat <<EOF > /etc/systemd/system/docker-tls.socket
[Unit]
Description=Docker Socket for the API

[Socket]
ListenStream=0.0.0.0:2375
Service=docker.service
BindToDevice=eth0

[Install]
WantedBy=sockets.target
EOF

mkdir -p /etc/systemd/system/docker.service.d/

cat <<EOF > /etc/systemd/system/docker.service.d/01-docker-enrollment.conf
[Unit]
Requires=docker-tls.socket
After=docker-tls.socket

[Service]
Environment=PYTHONUNBUFFERED=1
ExecStart=
ExecStart=/usr/local/bin/docker-easyenroll
EOF
```

Interesting/important things:

 * We use `BindToDevice`: You can avoid listening on public interfaces entirely with this gem.
 * It's important to have a `Requires` and `After` for `dockerd` - otherwise starting docker won't start the sockets its supposed to listen on!
 * We Used `ExecStart=` to clear the existing `dockerd` invocation, then we start our `docker-enrollment` wrapper. This will immediately start docker if its already enrolled, otherwise it will wait for enrollment.


## Docker client setup

From your orchestration code you can 'enroll' a server with:

```
from docker_easyenroll.store import LocalCertificateStore
from docker_easyenroll.client import ensure_server_enrolled

store = LocalCertificateStore('/path/to/certificates')
ensure_server_enrolled(store, '1.2.3.4')
```

This will connect to `1.2.3.4` on port 2375 with a TLS client certificate signed by a CA it manages. If the connection is accepted (the remote Docker server might reject your certificate) then it will generate a certificate for that server signed by its CA and `POST` it to the server over HTTPS.

At this point `dockerd` will start normally, and be ready to accept connections over mutually authenticated TLS.

You can now use the normal Docker API:

```
from docker.client import DockerClient
from docker.tls import TLSConfig
from docker_easyenroll.store import LocalCertificateStore

store = LocalCertificateStore('/path/to/certificates')

client = DockerClient(
    base_url=f'tcp://1.2.3.4:2375',
    tls=TLSConfig(
        client_cert=(
            store.get_certificate_path('client'),
            store.get_private_key_path('client'),
        ),
        ca_cert=store.get_certificate_path('ca'),
        verify=True,
    ),
)
```
