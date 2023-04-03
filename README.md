# trivy-db 

![Build DB](https://github.com/aquasecurity/trivy-db/workflows/Trivy%20DB/badge.svg)
[![GitHub Release][release-img]][release]
![Downloads][download]
[![Go Report Card][report-card-img]][report-card]
[![Go Doc][go-doc-img]][go-doc]
[![License][license-img]][license]

[download]: https://img.shields.io/github/downloads/aquasecurity/trivy-db/total?logo=github
[release-img]: https://img.shields.io/github/release/aquasecurity/trivy-db.svg?logo=github
[release]: https://github.com/aquasecurity/trivy-db/releases
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/trivy-db
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/trivy-db
[go-doc-img]: https://godoc.org/github.com/aquasecurity/trivy-db?status.svg
[go-doc]: https://godoc.org/github.com/aquasecurity/trivy-db
[code-cov]: https://codecov.io/gh/aquasecurity/trivy-db/branch/main/graph/badge.svg
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://github.com/aquasecurity/trivy-db/blob/main/LICENSE

## Overview
`trivy-db` is a CLI tool and a library to manipulate Trivy DB.

### Library
Trivy uses `trivy-db` internally to manipulate vulnerability DB. This DB has vulnerability information from NVD, Red Hat, Debian, etc.

### CLI
`trivy-db` builds vulnerability DBs on GitHub Actions and uploads them to GitHub Release periodically.

```
NAME:
   trivy-db - Trivy DB builder

USAGE:
   main [global options] command [command options] image_name

VERSION:
   0.0.1

COMMANDS:
     build    build a database file
     upload   upload database files to GitHub Release
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

### Building the DB
You can utilize `make db-all` to build the database, the DB artifact is outputted to the assets folder.

Alternatively Docker is supported, you can run `docker build . -t trivy-db`.

If you want to build a trivy integration test DB, please run `make create-test-db`

## Update interval
Every 6 hours

## Download the vulnerability database
### version 1 (deprecated)
Trivy DB v1 reached the end of support on February 2023. Please upgrade Trivy to v0.23.0 or later.

Read more about the Trivy DB v1 deprecation in [the discussion](https://github.com/aquasecurity/trivy/discussions/1653).

### version 2
Trivy DB v2 is hosted on [GHCR](https://github.com/orgs/aquasecurity/packages/container/package/trivy-db).
Although GitHub displays the `docker pull` command by default, please note that it cannot be downloaded using `docker pull` as it is not a container image.

You can download the actual compiled database via [Trivy](https://aquasecurity.github.io/trivy/) or [Oras CLI](https://oras.land/cli/).

Trivy:
```sh
TRIVY_TEMP_DIR=$(mktemp -d)
trivy --cache-dir $TRIVY_TEMP_DIR image --download-db-only
tar -cf ./db.tar.gz -C $TRIVY_TEMP_DIR/db metadata.json trivy.db
rm -rf $TRIVY_TEMP_DIR
```
oras >= v0.13.0:
```sh
$ oras pull ghcr.io/aquasecurity/trivy-db:2
```

oras < v0.13.0:
```sh
$ oras pull -a ghcr.io/aquasecurity/trivy-db:2
```
The database can be used for [Air-Gapped Environment](https://aquasecurity.github.io/trivy/latest/docs/advanced/air-gap/).