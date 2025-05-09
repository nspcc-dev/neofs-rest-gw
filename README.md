<p align="center">
<img src="./.github/logo.svg" width="500px" alt="NeoFS">
</p>
<p align="center">
  REST server to interact with <a href="https://fs.neo.org">NeoFS</a>.
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
* git
* curl
* docker

First clone this repository:

```shell
$ git clone https://github.com/nspcc-dev/neofs-rest-gw
```

Then run make to build `bin/neofs-rest-gw` binary:

```shell
$ make
```

Or you can build it using docker:

```shell
$ make docker/all
```

#### Generate openapi boilerplate code

If you change the [spec file](./spec/rest.yaml) you have to re-generate server code.

You have several approaches:

1. Run make. It automatically downloads `oapi-codegen` and generates boilerplate.

```shell
$ make
```

2. Generate code separately:

```shell
$ make generate-server
```

#### Other targets

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
node that it will connect to. This can be done either via `-p` parameter or via `REST_GW_POOL_PEERS_<N>_ADDRESS` and
`REST_GW_POOL_PEERS_<N>_WEIGHT` environment variables (the gate supports multiple NeoFS nodes with weighted load balancing).

If you're launching REST gateway in bundle with [neofs-dev-env](https://github.com/nspcc-dev/neofs-dev-env), you can get
an IP address of the node in output of `make hosts` command
(with s0*.neofs.devenv name).

These two commands are functionally equivalent, they run the gate with one backend node (and otherwise default
settings):

```shell
$ neofs-rest-gw -p 192.168.130.72:8080
$ REST_GW_POOL_PEERS_0_ADDRESS=192.168.130.72:8080 neofs-rest-gw
```

It's also possible to specify uri scheme (grpc or grpcs) when using `-p`:

```shell
$ neofs-rest-gw -p grpc://192.168.130.72:8080
$ REST_GW_POOL_PEERS_0_ADDRESS=grpcs://192.168.130.72:8080 neofs-rest-gw
```

## Configuration

In general, everything available as CLI parameter can also be specified via environment variables, so they're not
specifically mentioned in most cases (see `--help` also). If you prefer a config file you can use it in yaml format.
See [config](./config/config.yaml) and [defaults](./docs/gate-configuration.md) for example.

```shell
$ neofs-rest-gw --config config.yaml
```

## Docs

You can see swagger specification using the following url
(suppose you ran rest-gw on `localhost:8090`):

* http://localhost:8090/v1/docs

## Known issues

Using `%` in path parameters [leads to error](https://github.com/nspcc-dev/neofs-rest-gw/issues/195). For instance, getting object by attribute:
* /v1/get_by_attribute/A9pnctophx5PFt4eUd8d2aa6otjgnQZNzyvt3HCeygFD/cat%25jpeg/cat%25jpeg

> cat%25jpeg - already URL escaped string, original value is cat%jpeg.

Also, when you run rest-gw, you will see a line similar to:
```shell
...
2024/02/12 13:21:31 Serving neofs rest gw at http://192.168.130.72:8080
```
You will find an auto-redirect to the specification page via this link.

### Migrating from HTTP gateway

See [docs/migration-from-http.md](./docs/migration-from-http.md).

### Migrating  Object search from V1 to V2

See [docs/migration-to-search-v2](./docs/migration-to-search-v2.md).

## Contributing

Feel free to contribute to this project after reading the [contributing guidelines](CONTRIBUTING.md).

Before starting to work on a certain topic, create a new issue first, describing
the feature/topic you are going to implement.

## License

This project is licensed under the GNU GPL v3 License -
see the [LICENSE](LICENSE) file for details.
