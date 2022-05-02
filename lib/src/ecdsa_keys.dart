// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'ffi/generated_bindings.dart';

/// Enumeration of the elliptic curves supported by tinyDTLS.
enum EcdsaCurve {
  /// Represents the secp256r1 curve.
  secp256r1
}

enum _ArgumentType {
  x,
  y,
  private,
}

class _EcdsaValidationError extends ArgumentError {
  final EcdsaCurve _ecdsaCurve;

  final _ArgumentType _argumentType;

  final int _expectedByteLength;

  final int _actualByteLength;

  _EcdsaValidationError(this._ecdsaCurve, this._argumentType,
      this._expectedByteLength, this._actualByteLength);

  String get _parameterDescription {
    if (_argumentType == _ArgumentType.private) {
      return "private key";
    }

    return "${_argumentType.name} coordinate of the public key";
  }

  @override
  String get message {
    final expectedBitLength = _expectedByteLength * 8;

    return "Expected a length of $_expectedByteLength bytes "
        "($expectedBitLength bits) for the $_parameterDescription of "
        "the curve ${_ecdsaCurve.name}, but found $_actualByteLength bytes "
        "instead!";
  }
}

class _Secp256r1ValidationError extends _EcdsaValidationError {
  _Secp256r1ValidationError(_ArgumentType argumentType, int actualByteLength)
      : super(EcdsaCurve.secp256r1, argumentType, DTLS_EC_KEY_SIZE,
            actualByteLength);
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

  void _verifySecp256R1() {
    if (publicKeyX.length != DTLS_EC_KEY_SIZE) {
      throw _Secp256r1ValidationError(_ArgumentType.x, publicKeyX.length);
    }

    if (publicKeyY.length != DTLS_EC_KEY_SIZE) {
      throw _Secp256r1ValidationError(_ArgumentType.y, publicKeyY.length);
    }

    if (privateKey.length != DTLS_EC_KEY_SIZE) {
      throw _Secp256r1ValidationError(_ArgumentType.private, privateKey.length);
    }
  }

  void _verifyEcdsaKeys() {
    switch (ecdsaCurve) {
      case EcdsaCurve.secp256r1:
        _verifySecp256R1();
    }
  }

  /// Constructor.
  EcdsaKeys(
      this.ecdsaCurve, this.privateKey, this.publicKeyX, this.publicKeyY) {
    _verifyEcdsaKeys();
  }
}

/// Convert [EcdsaKeys] object to a Dart ffi [Pointer].
Pointer<dtls_ecdsa_key_t> ecdsaKeysToPointer(EcdsaKeys ecdsaKeys) {
  final ecdsaKeyStruct = malloc<dtls_ecdsa_key_t>();
  final structReference = ecdsaKeyStruct.ref
    ..priv_key = malloc<Uint8>(DTLS_EC_KEY_SIZE)
    ..pub_key_x = malloc<Uint8>(DTLS_EC_KEY_SIZE)
    ..pub_key_y = malloc<Uint8>(DTLS_EC_KEY_SIZE);

  switch (ecdsaKeys.ecdsaCurve) {
    case EcdsaCurve.secp256r1:
      structReference.curve = dtls_ecdh_curve.DTLS_ECDH_CURVE_SECP256R1;
      break;
    default:
      throw ArgumentError("Unknown Cipher ${ecdsaKeys.ecdsaCurve} found.");
  }
  structReference.priv_key
      .asTypedList(DTLS_EC_KEY_SIZE)
      .setAll(0, ecdsaKeys.privateKey);
  structReference.pub_key_x
      .asTypedList(DTLS_EC_KEY_SIZE)
      .setAll(0, ecdsaKeys.publicKeyX);
  structReference.pub_key_y
      .asTypedList(DTLS_EC_KEY_SIZE)
      .setAll(0, ecdsaKeys.publicKeyY);

  return ecdsaKeyStruct;
}

/// Free the memory allocated to an [ecdsaKeyStruct].
void freeEdcsaStruct(Pointer<dtls_ecdsa_key_t> ecdsaKeyStruct) {
  if (ecdsaKeyStruct != nullptr) {
    final structReference = ecdsaKeyStruct.ref;
    for (final keyPointer in [
      structReference.priv_key,
      structReference.pub_key_x,
      structReference.pub_key_y
    ]) {
      malloc.free(keyPointer);
    }
    malloc.free(ecdsaKeyStruct);
  }
}
