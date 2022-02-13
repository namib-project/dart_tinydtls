// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:typed_data';

import 'ffi/generated_bindings.dart';

/// Enumeration of the elliptic curves supported by tinyDTLS.
enum EcdsaCurve {
  /// Represents the secp256r1 curve.
  dtlsEcdhCurveSecp256R1
}

/// Class representing ECC keys (one private and two public ones).
class EcdsaKeys {
  /// The elliptic curve these keys are associated with.
  final EcdsaCurve ecdsaCurve;

  /// The private key.
  final Uint8List privateKey;

  /// The x coordinate of the public key.
  final Uint8List publicKeyX;

  /// The y coordinate of the public key.
  final Uint8List publicKeyY;

  /// Constructor.
  EcdsaKeys(
      this.ecdsaCurve, this.privateKey, this.publicKeyX, this.publicKeyY) {
    for (final key in [privateKey, publicKeyX, publicKeyY]) {
      if (key.length != DTLS_EC_KEY_SIZE) {
        throw ArgumentError("All ECDSA Keys must have a length of 32 bytes!");
      }
    }
  }
}
