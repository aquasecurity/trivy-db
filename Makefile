SHELL=/bin/bash
LDFLAGS=-ldflags "-s -w"

CACHE_DIR ?= cache
OUT_DIR ?= out
ASSET_DIR ?= assets

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
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) v1.63.4

.PHONY: test
test:
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run

.PHONY: lintfix
lintfix: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run --fix

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
	mkdir -p $(CACHE_DIR)/{ruby-advisory-db,php-security-advisories,nodejs-security-wg,ghsa,cocoapods-specs,bitnami-vulndb,govulndb,k8s-cve-feed,julia}
	wget -qO - https://github.com/rubysec/ruby-advisory-db/archive/master.tar.gz | tar xz -C $(CACHE_DIR)/ruby-advisory-db --strip-components=1
	wget -qO - https://github.com/FriendsOfPHP/security-advisories/archive/master.tar.gz | tar xz -C $(CACHE_DIR)/php-security-advisories --strip-components=1
	wget -qO - https://github.com/nodejs/security-wg/archive/main.tar.gz | tar xz -C $(CACHE_DIR)/nodejs-security-wg --strip-components=1
	wget -qO - https://github.com/bitnami/vulndb/archive/main.tar.gz | tar xz -C $(CACHE_DIR)/bitnami-vulndb --strip-components=1
	wget -qO - https://github.com/github/advisory-database/archive/refs/heads/main.tar.gz | tar xz -C $(CACHE_DIR)/ghsa --strip-components=1
	wget -qO - https://github.com/golang/vulndb/archive/refs/heads/master.tar.gz | tar xz -C $(CACHE_DIR)/govulndb --strip-components=1
	## required to convert GHSA Swift repo links to Cocoapods package names
	wget -qO - https://github.com/CocoaPods/Specs/archive/master.tar.gz | tar xz -C $(CACHE_DIR)/cocoapods-specs --strip-components=1
	wget -qO - https://github.com/kubernetes-sigs/cve-feed-osv/archive/main.tar.gz | tar xz -C $(CACHE_DIR)/k8s-cve-feed --strip-components=1
	wget -qO - https://github.com/JuliaLang/SecurityAdvisories.jl/archive/refs/heads/generated/osv.tar.gz | tar xz -C $(CACHE_DIR)/julia --strip-components=1

.PHONY: db-build
db-build: trivy-db
	./trivy-db build --cache-dir ./$(CACHE_DIR) --output-dir ./$(OUT_DIR) --update-interval 24h

.PHONY: db-compact
db-compact: $(GOBIN)/bbolt ./$(OUT_DIR)/trivy.db
	mkdir -p ./$(ASSET_DIR)
	$(GOBIN)/bbolt compact -o ./$(ASSET_DIR)/trivy.db ./$(OUT_DIR)/trivy.db
	cp ./$(OUT_DIR)/metadata.json ./$(ASSET_DIR)/metadata.json
	rm -rf ./$(OUT_DIR)

.PHONY: db-compress
db-compress: $(ASSET_DIR)/trivy.db $(ASSET_DIR)/metadata.json
	tar cvzf ./$(ASSET_DIR)/db.tar.gz -C $(ASSET_DIR) trivy.db metadata.json

.PHONY: db-clean
db-clean:
	rm -rf $(CACHE_DIR) $(OUT_DIR) $(ASSET_DIR)

.PHONY: db-fetch-vuln-list
db-fetch-vuln-list:
	mkdir -p $(CACHE_DIR)/vuln-list
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list/archive/main.tar.gz | tar xz -C $(CACHE_DIR)/vuln-list --strip-components=1
	mkdir -p $(CACHE_DIR)/vuln-list-redhat
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list-redhat/archive/main.tar.gz | tar xz -C $(CACHE_DIR)/vuln-list-redhat --strip-components=1
	mkdir -p $(CACHE_DIR)/vuln-list-debian
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list-debian/archive/main.tar.gz | tar xz -C $(CACHE_DIR)/vuln-list-debian --strip-components=1
	mkdir -p $(CACHE_DIR)/vuln-list-nvd
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list-nvd/archive/main.tar.gz | tar xz -C $(CACHE_DIR)/vuln-list-nvd --strip-components=1
	mkdir -p $(CACHE_DIR)/vuln-list-aqua
	wget -qO - https://github.com/$(REPO_OWNER)/vuln-list-aqua/archive/main.tar.gz | tar xz -C $(CACHE_DIR)/vuln-list-aqua --strip-components=1
