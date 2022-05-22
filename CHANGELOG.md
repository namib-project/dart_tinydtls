## 1.0.1

- Added missing override of the `toString()` method to `TinyDtlsLoadException`

## 1.0.0

### New Features
- Added getters for `closed` class members to client and server
- Changed parameters of credentials constructors to named ones
- Replaced pskCredentials parameter of `DtlsClient` constructor with callback
- Added callback for indicating PSK identity hints to `DtlsServer` class

### Bugfixes
- Fixed bug that prevented the use of ECDSA keys with the `DtlsServer`

### Other Changes
- Improved documentation of library and `DtlsConnection` class

## 0.5.0

- Reworked and fixed the internal mechanism for finding tinyDTLS binaries

## 0.4.1

- Applied minor refactorings and style changes

## 0.4.0

- The `DtlsClient` and `DtlsServer` should now handle connections closed by the peer correctly
- When generating bindings, `CPATH` is now used in place of `-I` compiler option to find headers

## 0.3.0

- Reworked server API using a generic DtlsConnection interface
- Improved documentation

## 0.2.1

- Expanded package description in pubspec.yaml

## 0.2.0

- Refactored tests and example
- Renamed the `data` field of the  `DtlsServerEvent` class to `datagram`

## 0.1.0

- Initial version.
