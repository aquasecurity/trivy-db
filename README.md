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

If you want to build the light DB, please set your environment to contain `DB_TYPE=trivy-light`.

Alternatively Docker is supported, you can run `docker build . -t trivy-db`.

If you want to build the light DB, please run `docker build --build-arg DB_TYPE=trivy-light . -t trivy-db-light`

If you want to build a trivy integration test DB, please run `make create-test-db`

## Update interval
Every 6 hours