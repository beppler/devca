# DevCA

Manages Certificate Authorities and Server Certificates for development.

## Install

Pre-built binaries for Windows, Linux and macOS are available on the [GitHub releases page](https://go.beppler.dev.br/devca/releases). Download the archive for your system and architecture (`.zip` for Windows, `.tar.gz` for Linux and macOS), extract it and put the `devca` binary somewhere on your `PATH`.

Or, if you have go on your system you can install it using

```shell
go install go.beppler.dev.br/devca@latest
```

Or you can compile it by cloning this repository and running:

```shell
go build
```

Or you can build binaries for multiple systems and architectures using [GoReleaser](https://goreleaser.com) (the output goes to `dist/`):

```shell
goreleaser release --snapshot --clean
```

## Usage

### Initialize Certificate Authority

To initialize certificate authority create a directory and run `devca init` on it.

```shell
mkdir my-dev-ca
cd my-dev-ca

devca init
```

This command will create files `ca.crt` and `ca.key` with the certificate and private key for the Certificate Authority.

The private key uses the P-384 elliptic curve by default. Use `-c` (`--curve`) to choose `p256`, `p384` or `p521` (for example `devca init -c p256`). Certificates issued by the authority use the same curve.

The certificate can be distributed and must be installed on Operating System stores to be trusted.

### Create Subordinate Certificate Authority

To create a subordinate certificate authority, go to the certificate authority directory and run `devca issue ca name` on it. The name is required. The domains (`-d`) and networks (`-n`) are optional and limit the names the subordinate authority can issue certificates for.

```shell
cd my-dev-ca
devca issue ca "Team CA" -d team.example.com -n 10.0.0.0/8
```

This command will create files `name-serial.crt` and `name-serial.key` with certificate and private key for the subordinate authority. Characters that are not safe in file names are replaced with `-` (for example `team-ca-serial.crt`).

The subordinate authority is valid for 5 years, can issue server and code signing certificates but not other authorities, and its constraints must be within the ones of the signing authority (they are required when the authority has any).

To issue certificates with a subordinate authority, copy its certificate and private key to a new directory as `ca.crt` and `ca.key` and run `devca issue server` or `devca issue codesign` there. The parent authority must be the one installed on the Operating System stores, and servers must present the subordinate authority certificate along with their own certificate in the chain (for example `cat hostname-serial.crt team-ca-serial.crt > fullchain.crt`).

### Create Server Certificate

To create a new server certificate, go to the certificate authority directory and run `devca issue server hostname` on it.

```shell
cd my-dev-ca
devca issue server example.com
```

This command will create files `hostname-serial.crt` and `hostname-serial.key` with certificate and private key for the server.

### Create Code Signing Certificate

To create a new code signing certificate, go to the certificate authority directory and run `devca issue codesign name` on it. The country (`-c`, two-letter code) and organization (`-o`) are optional.

```shell
cd my-dev-ca
devca issue codesign "John Doe" -c US -o "ACME Corp"
```

This command will create files `name-serial.crt` and `name-serial.key` with certificate and private key for code signing. Characters that are not safe in file names are replaced with `-` (for example `john-doe-serial.crt`).

## Release

Pushing a tag that starts with `v` (for example `v1.2.0`) triggers the [Release workflow](.github/workflows/release.yml), which builds the binaries with [GoReleaser](https://goreleaser.com) and creates a GitHub release with them attached.

The release notes are taken from the tag message, so use an annotated tag:

```shell
git tag -a v1.2.0 -m "Release notes for v1.2.0"
git push origin v1.2.0
```
