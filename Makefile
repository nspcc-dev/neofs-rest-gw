#!/usr/bin/make -f

REPO ?= "$(shell go list -m)"
VERSION ?= "$(shell git describe --tags --match "v*" --dirty --always --abbrev=8 | sed 's/^v//' 2>/dev/null || cat VERSION 2>/dev/null || echo "develop")"

BUILD_OS ?= linux
BUILD_ARCH ?= amd64
GO_VERSION ?= 1.22
LINT_VERSION ?= v1.49.0

HUB_IMAGE ?= nspccdev/neofs-rest-gw
HUB_TAG ?= "$(shell echo ${VERSION} | sed 's/^v//')"

UNAME = "$(shell uname)/$(shell uname -m)"

ifeq ($(UNAME), "Darwin/arm64")
	BUILD_OS=darwin
	BUILD_ARCH=arm64
endif
ifeq ($(UNAME), "Darwin/x86_64")
	BUILD_OS=darwin
endif

# List of binaries to build. For now just one.
BINDIR = bin
DIRS = "$(BINDIR)"
BINS = "$(BINDIR)/neofs-rest-gw"

.PHONY: help all dep clean format test cover lint docker/lint

# Make all binaries
all: generate-server $(BINS)

$(BINS): $(DIRS) dep
	@echo "⇒ Build $@"
	CGO_ENABLED=0 \
	GOOS=$(BUILD_OS) \
	GOARCH=$(BUILD_ARCH) \
	go build -v -trimpath \
	-ldflags "-X main.Version=$(VERSION)" \
	-o $@ ./cmd/neofs-rest-gw

$(DIRS):
	@echo "⇒ Ensure dir: $@"
	@mkdir -p $@

# Pull go dependencies
dep:
	@printf "⇒ Download requirements: "
	@CGO_ENABLED=0 \
	go mod download && echo OK
	@printf "⇒ Tidy requirements: "
	@CGO_ENABLED=0 \
	go mod tidy -v && echo OK

# Install generator
install-generator:
	@go install github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen@v2.1.0

# Generate server by openapi spec
generate-server: install-generator
	@oapi-codegen --config=./oapi-generator.cfg.yaml ./spec/rest.yaml

# Run tests
test:
	@go test ./... -cover

# Run tests with race detection and produce coverage output
cover:
	@go test -v -race ./... -coverprofile=coverage.txt -covermode=atomic
	@go tool cover -html=coverage.txt -o coverage.html

# Reformat code
format:
	@echo "⇒ Processing gofmt check"
	@gofmt -s -w ./
	@echo "⇒ Processing goimports check"
	@goimports -w ./

# Build clean Docker image
image:
	@echo "⇒ Build NeoFS REST Gateway docker image "
	@docker build \
		--build-arg REPO=$(REPO) \
		--build-arg VERSION=$(VERSION) \
		--rm \
		-f Dockerfile \
		-t $(HUB_IMAGE):$(HUB_TAG) .

# Push Docker image to the hub
image-push:
	@echo "⇒ Publish image"
	@docker push $(HUB_IMAGE):$(HUB_TAG)

# Build dirty Docker image
image-dirty:
	@echo "⇒ Build NeoFS REST Gateway dirty docker image "
	@docker build \
		--build-arg REPO=$(REPO) \
		--build-arg VERSION=$(VERSION) \
		--rm \
		-f Dockerfile.dirty \
		-t $(HUB_IMAGE)-dirty:$(HUB_TAG) .

# Run linters
lint:
	@golangci-lint --timeout=5m run

# Make all binaries in clean docker environment
docker/all:
	@echo "=> Running 'make all' in clean Docker environment" && \
	docker run --rm -t \
		-v `pwd`:/src \
		-w /src \
		-u `stat -c "%u:%g" .` \
		--env HOME=/src \
		--env BUILD_OS=$(BUILD_OS) \
		--env BUILD_ARCH=$(BUILD_ARCH) \
		golang:$(GO_VERSION) make all

# Run linters in Docker
docker/lint:
	docker run --rm -it \
	-v `pwd`:/src \
	-u `stat -c "%u:%g" .` \
	--env HOME=/src \
	golangci/golangci-lint:$(LINT_VERSION) bash -c 'cd /src/ && make lint'

# Print version
version:
	@echo $(VERSION)

# Show this help prompt
help:
	@echo '  Usage:'
	@echo ''
	@echo '    make <target>'
	@echo ''
	@echo '  Targets:'
	@echo ''
	@awk '/^#/{ comment = substr($$0,3) } comment && /^[a-zA-Z][a-zA-Z0-9_-]+ ?:/{ print "   ", $$1, comment }' $(MAKEFILE_LIST) | column -t -s ':' | grep -v 'IGNORE' | sort -u

# Clean up
clean:
	rm -rf .cache
	rm -rf $(BINDIR)
