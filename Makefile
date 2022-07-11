#!/usr/bin/make -f

REPO ?= "$(shell go list -m)"
VERSION ?= "$(shell git describe --tags --dirty --always 2>/dev/null || cat VERSION 2>/dev/null || echo "develop")"

HUB_IMAGE ?= nspccdev/neofs-rest-gw
HUB_TAG ?= "$(shell echo ${VERSION} | sed 's/^v//')"

DOCKER_LIST_VERSION ?= v1.42

SWAGGER_VERSION ?= v0.29.0
SWAGGER_ARCH ?= linux_amd64

SWAGGER_URL = "$(shell curl -s https://api.github.com/repos/go-swagger/go-swagger/releases/tags/$(SWAGGER_VERSION) | \
    jq -r '.assets[] | select(.name | contains("swagger_$(SWAGGER_ARCH)")) | .browser_download_url')"

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
	GO111MODULE=on \
	go build -v -trimpath \
	-ldflags "-X cmd/neofs-rest-gw/main.Version=$(VERSION)" \
	-o $@ ./cmd/neofs-rest-gw

$(DIRS):
	@echo "⇒ Ensure dir: $@"
	@mkdir -p $@

# Pull go dependencies
dep:
	@printf "⇒ Download requirements: "
	@CGO_ENABLED=0 \
	GO111MODULE=on \
	go mod download && echo OK
	@printf "⇒ Tidy requirements: "
	@CGO_ENABLED=0 \
	GO111MODULE=on \
	go mod tidy -v && echo OK

# Install swagger
swagger:
ifeq (,$(wildcard ./bin/swagger))
	curl --create-dirs -o ./bin/swagger -L'#' $(SWAGGER_URL)
	chmod +x ./bin/swagger

#	curl --create-dirs -o ./bin/swagger $(SWAGGER_URL)
#	chmod +x ./bin/swagger
endif

# Generate server by swagger spec
generate-server: swagger
	./bin/swagger generate server -t gen -f ./spec/rest.yaml --exclude-main \
 		-A neofs-rest-gw -P models.Principal \
 		-C templates/server-config.yaml --template-dir templates

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

# Run linters in Docker
docker-lint:
	docker run --rm -it \
	-v `pwd`:/src \
	-u `stat -c "%u:%g" .` \
	--env HOME=/src \
	golangci/golangci-lint:$(DOCKER_LINT_VERSION) bash -c 'cd /src/ && make lint'

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
	rm -rf vendor
	rm -rf $(BINDIR)
