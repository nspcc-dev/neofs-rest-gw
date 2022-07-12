<p align="center">
<img src="./.github/logo.svg" width="500px" alt="NeoFS">
</p>
<p align="center">
  <a href="https://fs.neo.org">NeoFS</a> is a decentralized distributed object storage integrated with the <a href="https://neo.org">NEO Blockchain</a>.
</p>

---
[![Report](https://goreportcard.com/badge/github.com/nspcc-dev/neofs-rest-gw)](https://goreportcard.com/report/github.com/nspcc-dev/neofs-rest-gw)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/nspcc-dev/neofs-rest-gw?sort=semver)
![License](https://img.shields.io/github/license/nspcc-dev/neofs-rest-gw.svg?style=popout)

# neofs-rest-gw

NeoFS REST Gateway bridges NeoFS internal protocol and REST API server.

## Installation

### Building

Before building make sure you have the following tools:

* go
* make
* jq
* git
* curl


To build neofs-rest-gw call `make` the cloned repository (the binary will end up in `bin/neofs-rest-gw`).

Notable make targets:

```
dep             Check and ensure dependencies
image           Build clean docker image
image-dirty     Build dirty docker image with host-built binaries
formats         Run all code formatters
lint            Run linters
version         Show current version
generate-server Generate boilerplate by spec
```

### Docker

Or you can also use a [Docker image](https://hub.docker.com/r/nspccdev/neofs-rest-gw) provided for released
(and occasionally unreleased) versions of gateway (`:latest` points to the latest stable release).

## Execution

REST gateway itself is not a NeoFS node, so to access NeoFS it uses node's gRPC interface and you need to provide some
node that it will connect to. This can be done either via `-p` parameter or via `REST_GW_PEERS_<N>_ADDRESS` and
`REST_GW_PEERS_<N>_WEIGHT` environment variables (the gate supports multiple NeoFS nodes with weighted load balancing).

If you're launching REST gateway in bundle with [neofs-dev-env](https://github.com/nspcc-dev/neofs-dev-env), you can get
an IP address of the node in output of `make hosts` command
(with s0*.neofs.devenv name).

These two commands are functionally equivalent, they run the gate with one backend node (and otherwise default
settings):

```
$ neofs-rest-gw -p 192.168.130.72:8080
$ REST_GW_PEERS_0_ADDRESS=192.168.130.72:8080 neofs-rest-gw
```

It's also possible to specify uri scheme (grpc or grpcs) when using `-p`:

```
$ neofs-rest-gw -p grpc://192.168.130.72:8080
$ REST_GW_PEERS_0_ADDRESS=grpcs://192.168.130.72:8080 neofs-rest-gw
```

## Configuration

In general, everything available as CLI parameter can also be specified via environment variables, so they're not
specifically mentioned in most cases
(see `--help` also). If you prefer a config file you can use it in yaml format. See config [examples](./config) for
details.

## Docs
You can see additional docs and swagger specification using the following url (suppose you ran rest-gw on `localhost:8090`):
* http://localhost:8090/docs - rest-gw documentation
* http://localhost:8090/v1/docs - swagger specification
