// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

/// Dart ffi bindings to the tinydtls library.
///
/// Provides a DTLS client with PSK and ECC support.
library dart_tinydtls;

export 'src/client.dart' show DtlsClient;
export 'src/dtls_connection.dart';
export 'src/dtls_event.dart' show DtlsEvent;
export 'src/ecdsa_keys.dart' show EcdsaKeys, EcdsaCurve;
export 'src/ffi/generated_bindings.dart' show TinyDTLS;
export 'src/psk_credentials.dart';
export 'src/server.dart' show DtlsServer;
