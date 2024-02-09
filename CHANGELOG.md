# Changelog

## [1.3.0][] (2024-01-12)

### Fixed

- Log level selection by [@sosthene-nitrokey][] in [#184][]
- Version in user agent by [@sosthene-nitrokey][] in [#186][]
- Certificate listing with `certutil` by [@sosthene-nitrokey][] in [#185][]
- Parrallel reading of all keys by [@sosthene-nitrokey][] in [#177][]

[Full Changelog](https://github.com/Nitrokey/nethsm-pkcs11/compare/1.2.0...1.3.0)

[1.3.0]: https://github.com/Nitrokey/nethsm-pkcs11/releases/tag/1.3.0

[#184]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/#184
[#186]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/#186
[#185]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/#185
[#177]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/#177

## [1.2.0][] (2024-01-24)

### Added

- Add configuration example with all available configuration by [@sosthene-nitrokey][] in [#172][]
- Support syslog logging by [@sosthene-nitrokey][] in [#176][]

### Changed

- Improve logging: by [@sosthene-nitrokey][] in ,[#180][] and [#181][] 
  - Log the number of retries and the timeouts for each slot
  - Log the number of attempts on each network failure
  - Log the paths of the source configuration files

[Full Changelog](https://github.com/Nitrokey/nethsm-pkcs11/compare/1.1.0...1.2.0)

[#180]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/180
[#181]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/181
[#176]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/176
[#172]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/172

[1.2.0]: https://github.com/Nitrokey/nethsm-pkcs11/releases/tag/1.2.0

## [1.1.0][] (2024-01-12)

## Examples

- Added Webserver PKCS11 Examples by [@q-nk][] in [#149][]
- Releases: add fedora 39 build by [@sosthene-nitrokey][] in [#159][]

## Additions

- Nginx test by [@sosthene-nitrokey][] in [#171][]

## Changes

- Dependency updates by [@sosthene-nitrokey][] in [#162][]
- Better handle network errors by [@sosthene-nitrokey][] in [#164][]
- Improve CF_INFO by [@sosthene-nitrokey][] in [#167][]
- Improve multithreaded performance by [@sosthene-nitrokey][] in [#173][]

## Fixes

- Fix panics on failed initialization by [@sosthene-nitrokey][] in [#165][]

[Full Changelog](https://github.com/Nitrokey/nethsm-pkcs11/compare/1.0.0...1.1.0)

[#149]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/149
[#159]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/159
[#162]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/162
[#164]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/164
[#167]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/167
[#171]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/171
[#165]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/165
[#173]: https://github.com/Nitrokey/nethsm-pkcs11/pulls/173

[1.1.0]: https://github.com/Nitrokey/nethsm-pkcs11/releases/tag/1.1.0

[@q-nk]: https://github.com/q-nk
[@sosthene-nitrokey]: https://github.com/sosthene-nitrokey

## [1.0.0][] (2023-11-27)

Initial release

[1.0.0]: https://github.com/Nitrokey/nethsm-pkcs11/releases/tag/1.0.0
