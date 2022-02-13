// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

/// Dart ffi bindings to the tinydtls library.
///
/// Provides a DTLS client with PSK and ECC support.
library dart_tindydtls;

export 'src/client.dart' show DtlsClient, PskCredentials, DtlsConnection;
export 'src/ecdsa_keys.dart';
export 'src/ffi/generated_bindings.dart' show TinyDTLS;
