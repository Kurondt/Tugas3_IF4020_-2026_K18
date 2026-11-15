PROGRAM  := jarsign
VERSION  := 1.0.0
IMAGE    ?= ghcr.io/kurondt/jarsign

GOFILES  := $(shell find cmd internal -name '*.go')

.PHONY: all build test test-race test-verbose vet fmt fmt-check cover docker-build docker-run clean

all: build

build: $(PROGRAM)

$(PROGRAM): $(GOFILES)
	@mkdir -p bin
	go build -trimpath -ldflags "-s -w -X signer/internal/cli.programVersion=$(VERSION)" -o bin/$(PROGRAM) ./cmd/jarsign

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

.PHONY: benchmark interoperability docs check test-consumer

benchmark: build
	go run ./cmd/jarsign-bench --binary bin/jarsign --out tests/results/benchmark

interoperability:
	go test -v ./tests/interoperability

docs:
	mkdir -p docs/site
	pandoc --standalone --metadata title="jarsign API" docs/API.md -o docs/site/index.html

test-consumer:
	python3 -m unittest discover -s scripts -p 'test_*.py'

check: fmt-check vet test test-race test-consumer
