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
	GO111MODULE=off go get github.com/knqyf263/mockery

.PHONY: mock
mock: $(GOBIN)/mockery
	mockery -all -inpkg -case=snake

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
