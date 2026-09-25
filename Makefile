VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/afsharid/passess/internal/buildinfo.Version=$(VERSION)

.PHONY: build test vet lint check hooks clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/passess ./cmd/passess

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

check: vet test lint

hooks:
	git config core.hooksPath .githooks

clean:
	rm -rf bin
