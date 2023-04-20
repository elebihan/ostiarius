# What's New?

## [0.6.0] - 2023-04-20
### Changed

- Handle special characters in passwords
- Strip trailing newline in Password::provide()
- Use SoftHSM for tests using PKCS11 token with special characters

### Fixed

- Fix code formatting
- core: authorization: tests: fix create_checker()
- core: fix clippy warnings

## [0.4.2] - 2022-12-19
### Fixed

- core: fix build for MS Windows

## [0.4.0] - 2022-12-05
### Added

- core: add password provider.
- server: add private key password handling.
- server: add logging.

### Changed

- requires rust >= 1.64.0

### Fixed

- client, server: fix typo in program name.
- server: fix private key default value.

## [0.2.0] - 2022-10-12
### Added

- Initial version
