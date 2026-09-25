# DevCA

Manages Certificate Authorities and Server Certificates for development.

## Install

Pre-built binaries for Windows, Linux and macOS are available on the [GitHub releases page](https://github.com/beppler/devca/releases). Download the archive for your system and architecture (`.zip` for Windows, `.tar.gz` for Linux and macOS), extract it and put the `devca` binary somewhere on your `PATH`.

Or, if you have go on your system you can install it using

```shell
go install github.com/beppler/devca@latest
```

Or you can compile it by cloning this repository and running:

```shell
go build
```

Or you can compile it using `build.sh` script that generates binaries for multiple systems and architectures.

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

To create a new server certificate, go to directory created on previous step and run `devca issue server hostname` on it.

```shell
cd my-dev-ca
devca issue server example.com
```

This command will create files `hostname-serial.crt` and `hostname-serial.key` with certificate and private key for the server.

## Release

Pushing a tag that starts with `v` (for example `v1.2.0`) triggers the [Release workflow](.github/workflows/release.yml), which builds the binaries with `build.sh` and creates a GitHub release with them attached.

The release notes are taken from the tag message, so use an annotated tag:

```shell
git tag -a v1.2.0 -m "Release notes for v1.2.0"
git push origin v1.2.0
```
