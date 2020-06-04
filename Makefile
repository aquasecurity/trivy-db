LDFLAGS=-ldflags "-s -w"

GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

u := $(if $(update),-u)

$(GOBIN)/wire:
	GO111MODULE=off go get github.com/google/wire/cmd/wire

.PHONY: wire
wire: $(GOBIN)/wire
	wire gen ./...

$(GOBIN)/mockery:
	GO111MODULE=off go get -u github.com/knqyf263/mockery/...

.PHONY: mock
mock: $(GOBIN)/mockery
	$(GOBIN)/mockery -all -inpkg -case=snake

.PHONY: deps
deps:
	go get ${u} -d
	go mod tidy

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.21.0

.PHONY: test
test:
	go test -v -short ./...

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/trivy-db

.PHONY: clean
clean:
	rm -rf integration/testdata/fixtures/

$(GOBIN)/bbolt:
	go get -v go.etcd.io/bbolt/...

export DB_TYPE ?= trivy

ifeq ($(DB_TYPE),trivy-light)
	DB_ARG := --light
endif

trivy-db:
	make build

.PHONY: db-all
db-all:
	make build db-fetch
	make db-build
	make db-compact
	make db-compress

.PHONY: db-fetch
db-fetch:
	mkdir -p cache/vuln-list cache/ruby-advisory-db cache/rust-advisory-db cache/php-security-advisories cache/nodejs-security-wg cache/python-safety-db
	wget -qO - https://github.com/aquasecurity/vuln-list/archive/master.tar.gz | tar xz -C cache/vuln-list --strip-components=1
	wget -qO - https://github.com/rubysec/ruby-advisory-db/archive/master.tar.gz | tar xz -C cache/ruby-advisory-db --strip-components=1
	wget -qO - https://github.com/RustSec/advisory-db/archive/master.tar.gz | tar xz -C cache/rust-advisory-db --strip-components=1
	wget -qO - https://github.com/FriendsOfPHP/security-advisories/archive/master.tar.gz | tar xz -C cache/php-security-advisories --strip-components=1
	wget -qO - https://github.com/nodejs/security-wg/archive/master.tar.gz | tar xz -C cache/nodejs-security-wg --strip-components=1
	wget -qO - https://github.com/pyupio/safety-db/archive/master.tar.gz | tar xz -C cache/python-safety-db --strip-components=1

.PHONY: db-build
db-build: trivy-db
	./trivy-db build $(DB_ARG) --cache-dir cache --update-interval 12h

.PHONY: db-compact
db-compact: $(GOBIN)/bbolt cache/db/trivy.db
	mkdir -p assets/$(DB_TYPE)
	$(GOBIN)/bbolt compact -o ./assets/$(DB_TYPE)/$(DB_TYPE).db cache/db/trivy.db
	cp cache/db/metadata.json ./assets/$(DB_TYPE)/metadata.json
	rm cache/db/trivy.db

.PHONY: db-compress
db-compress: assets/$(DB_TYPE)/$(DB_TYPE).db assets/$(DB_TYPE)/metadata.json
	tar cvzf assets/$(DB_TYPE)-offline.db.tgz -C assets/$(DB_TYPE) $(DB_TYPE).db metadata.json
	gzip --best -c assets/$(DB_TYPE)/$(DB_TYPE).db > assets/$(DB_TYPE).db.gz

.PHONY: db-clean
db-clean:
	rm -rf cache assets
