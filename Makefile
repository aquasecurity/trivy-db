LDFLAGS=-ldflags "-s -w"

GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

ifndef REPO_OWNER
    REPO_OWNER=aquasecurity
endif

u := $(if $(update),-u)

$(GOBIN)/wire:
	go install github.com/google/wire/cmd/wire@v0.5.0

.PHONY: wire
wire: $(GOBIN)/wire
	wire gen ./...

$(GOBIN)/mockery:
	go install github.com/knqyf263/mockery/cmd/mockery@latest

.PHONY: mock
mock: $(GOBIN)/mockery
	$(GOBIN)/mockery -all -inpkg -case=snake

.PHONY: deps
deps:
	go get ${u} -d
	go mod tidy

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) v1.41.0

.PHONY: test
test:
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

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
	go install go.etcd.io/bbolt/cmd/bbolt@v1.3.5

trivy-db:
	make build

.PHONY: db-fetch-langs
db-fetch-langs:
	mkdir -p cache/{ruby-advisory-db,php-security-advisories,nodejs-security-wg,ghsa,cocoapods-specs,bitnami-vulndb}
	wget -qO - https://github.com/rubysec/ruby-advisory-db/archive/master.tar.gz | tar xz -C cache/ruby-advisory-db --strip-components=1
	wget -qO - https://github.com/FriendsOfPHP/security-advisories/archive/master.tar.gz | tar xz -C cache/php-security-advisories --strip-components=1
	wget -qO - https://github.com/nodejs/security-wg/archive/main.tar.gz | tar xz -C cache/nodejs-security-wg --strip-components=1
	wget -qO - https://github.com/bitnami/vulndb/archive/main.tar.gz | tar xz -C cache/bitnami-vulndb --strip-components=1
	wget -qO - https://github.com/github/advisory-database/archive/refs/heads/main.tar.gz | tar xz -C cache/ghsa --strip-components=1
	## required to convert GHSA Swift repo links to Cocoapods package names
	wget -qO - https://github.com/CocoaPods/Specs/archive/master.tar.gz | tar xz -C cache/cocoapods-specs --strip-components=1

.PHONY: db-build
db-build: trivy-db
	./trivy-db build --cache-dir cache --update-interval 6h

.PHONY: db-compact
db-compact: $(GOBIN)/bbolt cache/db/trivy.db
	mkdir -p assets/
	$(GOBIN)/bbolt compact -o ./assets/trivy.db cache/db/trivy.db
	cp cache/db/metadata.json ./assets/metadata.json
	rm -rf cache/db

.PHONY: db-compress
db-compress: assets/trivy.db assets/metadata.json
	tar cvzf assets/db.tar.gz -C assets/ trivy.db metadata.json

.PHONY: db-clean
db-clean:
	rm -rf cache assets

.PHONY: db-fetch-vuln-list
db-fetch-vuln-list:
	mkdir -p cache/vuln-list
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list/archive/main.tar.gz | tar xz -C cache/vuln-list --strip-components=1
	mkdir -p cache/vuln-list-redhat
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list-redhat/archive/main.tar.gz | tar xz -C cache/vuln-list-redhat --strip-components=1
	mkdir -p cache/vuln-list-debian
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list-debian/archive/main.tar.gz | tar xz -C cache/vuln-list-debian --strip-components=1
	mkdir -p cache/vuln-list-nvd
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list-nvd/archive/main.tar.gz | tar xz -C cache/vuln-list-nvd --strip-components=1
