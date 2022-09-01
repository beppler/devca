# DevCA

Manages Certificate Authorities and Server Certificates for development.

## Usage

### Initialize Certificate Authority

To initialize certificate authority create a directory and run `devca init` on it.

```shell
mkdir my-dev-ca
cd my-dev-ca
devca init
```

This command will create files `ca.crt` and `ca.key` with the certificate and private key for the Certificate Authority.

The certificate can be distributed and must be installed on Operating System stores to be trusted.

### Create Server Certificate

To create a new server certificate, go to directory created on previous step and run `devca server hostname` on it.

```shell
cd my-dev-ca
devca server example.com
```

This command will create files `hostname-serial.crt` and `hostname-serial.key` with certificate and private key for the server.

## Install

Binaries can be downloaded from github releases or can be compiled using `build.sh` script.
