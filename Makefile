PROGRAM  := norsign
VERSION  := 1.0.0
IMAGE    ?= ghcr.io/if4020-k18/norsign

GOFILES  := $(shell find cmd internal -name '*.go')

.PHONY: all build test test-race test-verbose vet fmt fmt-check cover docker-build docker-run clean

all: build

build: $(PROGRAM)

$(PROGRAM): $(GOFILES)
	go build -trimpath -ldflags "-s -w -X signer/internal/cli.programVersion=$(VERSION)" -o bin/$(PROGRAM) ./cmd/norsign

test:
	go test ./...

test-race:
	go test -race ./...

test-verbose:
	go test -v ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal tests

fmt-check:
	@test -z "$$(gofmt -l cmd internal tests)" || { gofmt -l cmd internal tests; exit 1; }

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

docker-build:
	docker build --build-arg PROGRAM_VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

docker-run:
	docker run --rm $(IMAGE):$(VERSION) --help

clean:
	rm -rf bin coverage.out
