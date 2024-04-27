# Changelog

This document outlines major changes between releases.

## [Unreleased]

### Updating from 0.8.3

Notice that configuration parameters in the `server` section were reorganized. 
For example e.g.`server.schema` and `tls-listen-limit` were removed, and some 
others were moved inside the array `endpoints`. Check your configuration with 
the help of the [gate-configuration.md](./docs/gate-configuration.md) and 
[config](./config/config.yaml). Also, flags in the command arguments were 
changed.

## [0.8.3] - 2024-03-25

### Fixed
- CORS for upload request (#187)

## [0.8.2] - 2024-03-21

### Fixed
- Fetching bearer token from cookie (#179)
- CORS for auth bearer and other requests (#180, #182)

## [0.8.1] - 2024-03-21

### Fixed
- Incorrect answer to OPTIONS request (#169)
- Garbage in "object not found" error messages (#174)
- Missing additional data in some error messages (#175)
- Incorrect ExternalAddress option handling (#165)

## [0.8.0] - 2024-03-19

### Fixed
- Handling nested path in get_by_attribute API (#153)
- Static MIME type defined for APIs with dynamic one (#153)

### Changed

- OpenAPI specification was updated to 3.0.1 version (#153)
- Bumped google.golang.org/protobuf dependency from 1.32.0 to 1.33.0

### Updating from 0.7.2

Notice that server.scheme setting is an array, it was not enforced in the
previous version (it worked fine with a string), but 0.8.0 will not work with
this incorrect configuration, so please check your configurations.

## [0.7.2] - 2024-03-13

### Fixed
- Response for GET and HEAD methods in `get_by_attribute` when object is not 
  found (#155)
- Transform attribute key to Canonical MIME Header Key, which corresponds to
  the format used on upload (#155)

### Changed
- Simplified auth test, dropped the unnecessary `neofs-crypto` dependency (#150)
- Upgraded Go version to a minimum 1.20 and updated versions for GitHub Actions
  and workflows (#149, #152)

## [0.7.1] - 2024-02-19

### Added
- OPTIONS handling for HTTP-alike requests (#145)

### Fixed
- Improper non-bearer cookie handling (#142)
- Error messages (#142)
- Incorrect data returned from get APIs in some cases (#146)
- OPTIONS handling for all requests (#145)

## [0.7.0] - 2024-02-12

### Added
- Object getter compatible with HTTP gateway (#114, #127, #133)
- Object uploader compatible with HTTP gateway (#124)
- External address show in documentation can be configured now (#134)

### Fixed
- Bump NeoFS SDK dependency fixing "no healthy client" problem (#128)

### Changed
- Bump google.golang.org/grpc from 1.57.0 to 1.57.1 (#120)
- Bump golang.org/x/crypto from 0.16.0 to 0.17.0 (#123)
- Bump NeoGo dependency to 0.105.1 (#128)
- Bump go-openapi dependencies (#128)
- "/" now redirects to documentation page (#130)
- Gateway version doesn't have "v" prefix now (#135)
- Documentation is completely embedded into the specification now (#138)

## [0.6.0] - 2023-10-19

### Added
- Stop pool dial on SIGINT (#76)
- Unauthenticated GET/SEARCH requests (#2)
- Version metric (#102)

### Fixed
- Panic when getting an empty object (#79)

### Changed
- Configuration parameters (#66, #71)
- Build releases with Go 1.20 (#86)
- Drop support for Go 1.17, 1.18 (#86, #107)
- Use SDK 1.0.0-rc.11 (#86, #91, #96, #104, #107)
- Use NeoGo 0.102.0 (#107)
- Use go.uber.org/zap 1.26.0 (#107)
- Use newer go-openapi modules (#107)
- Use golang.org/x/net 0.17.0 (#108)

### Updating from v0.5.0

Now all pool config parameters moved to `pool` section. So you need to change:

* `peers` -> `pool.peers` (`REST_GW_PEERS` -> `REST_GW_POOL_PEERS`)
* `node-dial-timeout` -> `pool.node-dial-timeout` (`REST_GW_NODE_DIAL_TIMEOUT` -> `REST_GW_POOL_NODE_DIAL_TIMEOUT`)
* `healthcheck-timeout` -> `pool.healthcheck-timeout` (`REST_GW_HEALTHCHECK_TIMEOUT` -> `REST_GW_POOL_HEALTHCHECK_TIMEOUT`)
* `rebalance-timer` -> `pool.rebalance-timer` (`REST_GW_REBALANCE_TIMER` -> `REST_GW_POOL_REBALANCE_TIMER`)
* `pool-error-threshold` -> `pool.error-threshold`

Besides all other parameters that doesn't belong any section, now in `server` section:
* `listen-address` -> `server.listen-address`

The same should be done for the following parameters as well:
```
scheme, cleanup-timeout, graceful-timeout, max-header-size, listen-limit, keep-alive, read-timeout, write-timeout,
tls-listen-address, tls-certificate, tls-key, tls-ca, tls-listen-limit, tls-keep-alive, tls-read-timeout, tls-write-timeout
```

Environment variables should be changed appropriately.

## [0.5.0] "Undercity" - 2022-10-07

### Added
- ACL sanity checks (#68, #69)
- Cross platform builds (#26)

### Fixed
- Fix expiration epoch calculation (#62)
- Typos in Makefile (#65)
- CORS for authentication (#73)

### Changed
- Update go version for build to 1.19 (#61)

## [0.4.0] "Shadowglen" - 2022-08-30

### Fixed
- NeoFS client metrics (#52)
- Panic in go1.19 build (#53)
- Add CORS Allow-Origin header (#56)

### Added
- Canned ACL in container info (#38)
- Native bearer token support (#32)
- `Keys` target in extended ACL (#54)

### Changed
- Unify application version format (#49)

## [0.3.0] "Thunder Bluff" - 2022-08-15

### Added
- CORS headers (#39)
- Expose metrics (#44)
- Documentation for default params (#45)
- Route to get NeoFS balance (#33)
- New field for object search response (#40)
- Building in docker (#46)

### Removed
- Drop GO111MODULE from builds (#34)

## [0.2.1] "Razor Hill" - 2022-07-22

### Fixed
- Fix application version (#30)

## [0.2.0] "Orgrimmar" - 2022-07-22

### Added
- Support macOS build (#18)

### Changed
- Update version calculating (#20)
- New error response and auth request format (#15)
- NeoFS SDK version update (#16)
- Set container attributes in body rather than in headers (#25)

### Fixed
- Fix .env variables in sample config (#22)
- Fix typos and examples in spec (#24)

## Older versions

Please refer to [GitHub releases](https://github.com/nspcc-dev/neofs-rest-gw/releases/) for older releases.

[0.2.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.1.0...v0.2.0
[0.2.1]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.2.0...v0.2.1
[0.3.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.2.0...v0.3.0
[0.4.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.3.0...v0.4.0
[0.5.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.4.0...v0.5.0
[0.6.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.5.0...v0.6.0
[0.7.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.6.0...v0.7.0
[0.7.1]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.7.0...v0.7.1
[0.7.2]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.7.1...v0.7.2
[0.8.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.7.2...v0.8.0
[0.8.1]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.8.0...v0.8.1
[0.8.2]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.8.1...v0.8.2
[0.8.3]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.8.2...v0.8.3
[Unreleased]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.8.3...master
