# Changelog

This document outlines major changes between releases.

## [Unreleased]

### Added
- `pool.container-ops-poll-interval` option to control polling behavior for container operations (#315)

### Fixed
- Expiration parameter using pre-2.18 API meaning of EpochDuration (blocks vs seconds, #313)
- Incorrect error code for wrong EACL tables (#315)

### Changed
- Default container-ops-timeout to 10s (previously dynamic, based on block time, #313)
- Network info is cached for half epoch duration now (#313)
- Default polling interval for container operations from fixed 1s to dynamic value based on block time (#315)

### Removed

### Updated

### Upgrading from 0.13.0

## [0.13.0] - 2025-07-22

### Fixed
- Panic on search v1 (#305, #308)

### Changed
- Peers list definition in config files (#302)
- `pool.container_ops_timeout` name to `pool.container-ops-timeout` (#307)

### Updated
- NeoFS SDK to v1.0.0-rc.13.0.20250715070617-c7038b450691 (API 2.18, #311)

### Upgrading from 0.12.0
Rename `pool.container_ops_timeout` option to `pool.container-ops-timeout`
if used. Update peer configuration from the old format:
```yaml
peers:
  0:
    address: node1.neofs:8080
    priority: 1
    weight: 1
```
to the new one:
```yaml
peers:
  - address: node1.neofs:8080
    priority: 1
    weight: 1
```

## [0.12.0] - 2025-04-30

### Added
- `logger.encoding` config option (#273)
- `logger.timestamp` config option (#273)
- `/v2/objects/{containerId}/search` entrypoint with `cursor` support (instead of `offset`) for objects search (#276, #294)
- Ability to request and return attributes for `search v2` (#277)
- `pool.container_ops_timeout` config option (#254)
- POST /containers API replacing the old PUT-based one (#287)
- Request processing histograms in metrics (#285)
- `MatchNumGT`, `MatchNumGE`, `MatchNumLT`, `MatchNumLE` operators to search (#260)

### Fixed
- Double JSON response output for failed PUT operation (#265)

### Changed
- Log sampling is disabled now (#258)
- Go 1.23+ is required to build now (#235)
- Maximum search limit shrunk from 10000 to 1000 (#276)
- Attribute-based GET and HEAD now return the latest (wrt `Timestamp` attribute) object from the first 1000 search results (#276)
- Incorrect HTTP codes returned in many cases (#291)
- More informative operation logs (#289)
- Implicit root object filter is removed from search, other object types can be searched for properly now (#298)

### Updated
- `github.com/nspcc-dev/neofs-sdk-go` dependency to `v1.0.0-rc.13` (#267)
- `github.com/nspcc-dev/neo-go` dependency to `v0.108.1` (#259, #267)
- `golang.org/x/crypto` dependency to 0.31.0 (#262)
- `github.com/stretchr/testify` dependency to `v1.10.0` (#267)
- `github.com/testcontainers/testcontainers-go` dependency to `v0.35.0` (#267)
- `github.com/getkin/kin-openapi` dependency to `v0.131.0` (#277)
- `github.com/labstack/echo/v4` dependency to `v4.13.3` (#277)

## [0.11.1] - 2024-10-28

### Changed
- Network settings are cached now for faster processing (#251)

### Fixed
- Gateway not reacting to network settings changes (#251)
- Incorrect request for container creation hangs indefinitely (#253)
- Incorrect HTTP codes returned in many cases (#252, #253)

## [0.11.0] - 2024-08-28

### Added
- WalletConnect auth scheme to `/objects/${cid}/by...` APIs (#236)
- Support for 'Range' headers (#241)

### Changed
- Go 1.22+ is required to build now (#98, #136)
- Default read/write timeouts to 60s (#244)

### Removed
- `fullBearer` parameter from all requests (it's autodetected now, #238)

### Updated
- github.com/nspcc-dev/neo-go dependency from v0.106.0 to v0.106.3 (#98)
- github.com/oapi-codegen/echo-middleware dependency from v1.0.1 to v1.0.2 (#98)
- github.com/labstack/echo/v4 dependency from v4.11.4 to v4.12.0 (#98)
- github.com/getkin/kin-openapi from v0.118.0 to v0.127.0 (#98)

## [0.10.1] - 2024-08-12

### Fixed
- Missing proper shutdown for Pprof and Prometheus services (#227)
- Missing Content-Type header in responses for HEAD requests (#232)

### Changed
- More efficient buffering for PUT requests (#225)

## [0.10.0] - 2024-06-10

### Fixed
- Documentation for the `server` section (#220)
- "unknown config parameter listen-address" warning (#220)

### Changed
- `external-address` configuration behavior to include scheme (#218)
- Timestamp is no longer logged if program is not running in TTY (#222)

### Updating from 0.9.0

Notice that the configuration parameter `external-address` in the
`server.endpoints` section now also includes the scheme (http/https), not just
the host and port. If `external-address` is not set, it will be generated from
`address` and `tls.enabled`.

## [0.9.0] - 2024-05-30

### Added
- HEAD request handling for documentation (#199)
- Darwin binaries (#204)
- `network-info` path to request network parameters (#198)
- Proper TLS server support (#200)
- DefaultTimestamp configuration (#209)
- New upload/download APIs (#206, #210, #211, #214)

### Changed
- github.com/nspcc-dev/neofs-sdk-go dependency to v1.0.0-rc.12 (#191, #176, #212)
- golang.org/x/net dependency to 0.23.0 (#201)
- Documentation to reflect known limitations (#196)
- github.com/nspcc-dev/neofs-api-go/v2 is no longer used (#176)
- Server listener configuration to conform to other NeoFS services (#200)
- github.com/nspcc-dev/neo-go dependency to v0.106.0 (#208)

### Updating from 0.8.3

Notice that configuration parameters in the `server` section were reorganized.
For example e.g.`server.schema` and `tls-listen-limit` were removed, and some
others were moved inside the array `endpoints`. Check your configuration with
the help of the [gate-configuration.md](./docs/gate-configuration.md) and
[config](./config/config.yaml). Also, flags in the command arguments were
changed.

A new upload object request has been introduced: `/objects/{containerId}`. This
is a POST request that accepts the `X-Attributes` header, where all custom
object attributes can be included in a JSON-formatted key-value map. Also, new
GET and HEAD requests are added for object downloading:
`/objects/{containerId}/by_id/{objectId}` and
`/objects/{containerId}/by_attribute/{attrKey}/{attrVal}`.
For more information, see the [migration documentation](./docs/migration-new-upload.md).
In the future, we plan to use these requests as the only option for object
upload and download. We recommend starting to use them now.

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
[0.9.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.8.3...v0.9.0
[0.10.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.9.0...v0.10.0
[0.10.1]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.10.0...v0.10.1
[0.11.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.10.1...v0.11.0
[0.11.1]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.11.0...v0.11.1
[0.12.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.11.1...v0.12.0
[0.13.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.12.0...v0.13.0
[Unreleased]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.13.0...master
