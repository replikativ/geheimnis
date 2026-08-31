# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](http://keepachangelog.com/).

## [Unreleased][unreleased]
### Added
- Add a JVM/ClojureScript implementation of
  `Noise_XX_25519_AESGCM_SHA256`, including single-use handshake and transport
  states, rekeying, message bounds, and Cacophony reference-vector coverage.

### Changed
- Correct legacy package metadata to declare the repository's Apache-2.0
  license.

## [0.1.1] - 2016-04-05
### Changed
- Documentation on how to make the widgets.

### Removed
- `make-widget-sync` - we're all async, all the time.

### Fixed
- Fixed widget maker to keep working when daylight savings switches over.

## 0.1.0 - 2016-04-05
### Added
- Files from the new template.
- Widget maker public API - `make-widget-sync`.

[unreleased]: https://github.com/replikativ/geheimnis/compare/0.2.37...HEAD
[0.1.1]: https://github.com/replikativ/geheimnis/compare/0.1.0...0.1.1
