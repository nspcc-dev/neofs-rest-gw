# Changelog

This document outlines major changes between releases.

## [Unreleased]

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
[Unreleased]: https://github.com/nspcc-dev/neofs-rest-gw/compare/v0.4.0...master
