// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

/// Dart ffi bindings to the tinydtls library.
///
/// `dart_tinydtls` provides a high level API for accessing tinyDTLS
/// functionality. Both client and server APIs are exposed through the
/// [DtlsClient] and [DtlsServer] classes. These allow users to connect to a
/// peer or wait for incoming [DtlsConnection]s, respectively.
///
/// tinyDTLS only supports ciphers using either a Pre-Shared Key (PSK) or an
/// ECDSA key. These are realized in Dart as the [PskCredentials] and
/// [EcdsaKeys] classes. At least one of these types of credentials have to be
/// provided, otherwise an [ArgumentError] is thrown.
///
/// Once the connection has been established, a [DtlsConnection] object is
/// returned which can be used for sending data to the peer. The
/// [DtlsConnection] also allows listening for incoming application data
/// (in the form of [Datagram] objects).
///
/// Below you can see a simple example for how the [DtlsClient] class can be
/// used for establishing a [DtlsConnection]. In this case, the [PskCredentials]
/// class is used for passing a PSK and an identity to the [DtlsClient].
///
/// ```dart
/// import 'dart:convert';
/// import 'dart:io';
///
/// import 'package:dart_tinydtls/dart_tinydtls.dart';
///
/// Future<void> main() async {
///   const address = "fe80::abcd:ef00";
///   const port = 5684;
///   final pskCredentials = PskCredentials("Client_identity", "secretPSK");
///
///   final client = await DtlsClient.bind(InternetAddress.anyIPv6, 0);
///   final connection = await client.connect(InternetAddress(address), port,
///       pskCredentials: pskCredentials);
///
///   final data = utf8.encode('Hello World!');
///   connection.send(data);
///   client.close();
/// }
/// ```
///
library dart_tinydtls;

import 'dart:io';

import 'src/client.dart';
import 'src/dtls_connection.dart';
import 'src/ecdsa_keys.dart';
import 'src/psk_credentials.dart';
import 'src/server.dart';

export 'src/client.dart' show DtlsClient;
export 'src/dtls_connection.dart';
export 'src/dtls_event.dart' show DtlsEvent;
export 'src/ecdsa_keys.dart' show EcdsaKeys, EcdsaCurve;
export 'src/ffi/generated_bindings.dart' show TinyDTLS;
export 'src/psk_credentials.dart';
export 'src/server.dart' show DtlsServer;
export 'src/types.dart' show PskCallback;
