# Changelog

This document outlines major changes between releases.

## [Unreleased]

### Added
- Stop pool dial on SIGINT (#76)

### Changed
- Pool configuration parameters (#66)

### Updating from v0.5.0

Now all pool config parameters moved to `pool` section. So you need to change:

* `peers` -> `pool.peers` (`REST_GW_PEERS` -> `REST_GW_POOL_PEERS`)
* `node-dial-timeout` -> `pool.node-dial-timeout` (`REST_GW_NODE_DIAL_TIMEOUT` -> `REST_GW_POOL_NODE_DIAL_TIMEOUT`)
* `healthcheck-timeout` -> `pool.healthcheck-timeout` (`REST_GW_HEALTHCHECK_TIMEOUT` -> `REST_GW_POOL_HEALTHCHECK_TIMEOUT`)
* `rebalance-timer` -> `pool.rebalance-timer` (`REST_GW_REBALANCE_TIMER` -> `REST_GW_POOL_REBALANCE_TIMER`)
* `pool-error-threshold` -> `pool.error-threshold` 

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

[0.2.1]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.1.0...v0.2.0
[0.3.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.2.0...v0.3.0
[0.4.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.3.0...v0.4.0
[0.5.0]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.4.0...v0.5.0
[Unreleased]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.5.0...master
