# dart_tinydtls

Dart ffi bindings to the tinydtls library.
Provides wrappers for both a DTLS client and server.

## Using the wrapper classes

The library provides a high level API for accessing tinyDTLS functionality.
Both client and server APIs are exposed through the `DtlsClient` and `DtlsServer`
classes. These allow users to connect to a peer or wait for incoming connections,
respectively.

A basic example for the use of the `DtlsClient` class can be seen below. As tinyDTLS
only supports ciphers using either a Pre-Shared Key (PSK) or an ECDSA key, at least
one of these types of credentials have to be provided (in this case, a PSK).

Once the connection has been established, a `DtlsConnection` object is returned which
can be used for sending data to the peer. The `DtlsConnection` also allows listening
for incoming application data (in the form of `Datagram` objects). This and other
use cases are demonstrated more thoroughly in the `example.dart` file.

```dart
import 'dart:convert';
import 'dart:io';

import 'package:dart_tinydtls/dart_tinydtls.dart';

Future<void> main() async {
  const address = "fe80::abcd:ef00";
  const port = 5684;
  final pskCredentials = PskCredentials("Client_identity", "secretPSK");

  final client = await DtlsClient.bind(InternetAddress.anyIPv6, 0);
  final connection = await client.connect(InternetAddress(address), port,
      pskCredentials: pskCredentials);

  final data = utf8.encode('Hello World!');
  connection.send(data);
  client.close();
}
```

## Generating the bindings

1. Clone the repository and initialize its submodules
   (i.e. `git submodule update --init --recursive`).
2. Generate the bindings using `dart run ffigen`.
   - If you encounter a `SEVERE` error regarding a missing header file (e.g. `stddef.h`),
     please consult the *Troubleshooting* section below.
3. There are exactly two warnings which can be ignored:
    1. `Removed All Struct Members from dtls_handshake_parameters_t(dtls_handshake_parameters_t), Bit Field members not supported.`
       - The struct `dtls_handshake_parameters_t` won't be used by library clients, so the
         fact that it's opaque in the bindings can safely be ignored.
    2. `Generated declaration '__socklen_t' start's with '_' and therefore will be private.`
        - Similarly, it won't cause any problems for `__socklen_t` to be private.

## Troubleshooting

### `stddef.h` (or other header) file not found
It may be that you'll encounter the following error (maybe with another header 
file in place of `stddef.h`) when generating the bindings using `dart run ffigen`:
```
[SEVERE] : Header third_party/tinydtls/dtls.h: Total errors/warnings: 1.
[SEVERE] :     /usr/include/sys/types.h:144:10: fatal error: 'stddef.h' file not found [Lexical or Preprocessor Issue]
```
To fix this, `ffigen` needs to know where it can find this header file using the 
`CPATH` environment variable, which should point to the location of the header files.
To set this environment variable automatically by detecting the location using `clang`, 
run the following command[^cpath]:
```bash
export CPATH="$(clang -v 2>&1 | grep "Selected GCC installation" | rev | cut -d' ' -f1 | rev)/include"
```
Simply execute this before running `dart run ffigen` and the headers should be correctly detected.

[^cpath]: From [this GitHub comment](https://github.com/dart-lang/ffigen/issues/257#issuecomment-1061788936). 
          Of course, you can also set the path manually.

## License

Matching the license of the tinydtls C library, this library is made available both under
the terms of the Eclipse Public License v1.0 and 3-Clause BSD License (which the
Eclipse Distribution License v1.0 that is used for tinydtls is based on).
Additionally, the tinydtls C library contains third party code that might be included
in compiled binaries that link to tinydtls.
For information on third-party code and its licenses, see
https://github.com/eclipse/tinydtls/blob/develop/ABOUT.md.
See https://github.com/eclipse/tinydtls/blob/develop/LICENSE for more information on the
tinydtls licensing terms and https://www.eclipse.org/legal/eplfaq.php for more information
on the EPL 1.0.

Note: This binding is neither supported nor endorsed by the Eclipse Foundation.

## Maintainers

This project is currently maintained by the following developers:

|      Name      |      Email Address       |            GitHub Username            |
|:--------------:|:------------------------:|:-------------------------------------:|
|   Jan Romann   | jan.romann@uni-bremen.de |   [JKRhb](https://github.com/JKRhb)   |
| Falko Galperin |   falko1@uni-bremen.de   | [falko17](https://github.com/falko17) |
