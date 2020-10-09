# trivy-db
![Trivy DB](https://github.com/aquasecurity/trivy-db/workflows/Trivy%20DB/badge.svg)

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


## Contributing


### Pull Requests

We welcome pull requests!

- Your PR is more likely to be accepted if it focuses on just one change.
- Please include a comment with the results before and after your change.
- Your PR is more likely to be accepted if it includes tests. (We have not historically been very strict about tests, but we would like to improve this!).
- You're welcome to submit a draft PR if you would like early feedback on an idea or an approach.
- Happy coding!
