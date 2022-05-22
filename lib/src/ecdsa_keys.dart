// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'ffi/generated_bindings.dart';

const _bitsPerByte = 8;

/// Enumeration of the elliptic curves supported by tinyDTLS.
enum EcdsaCurve {
  /// Represents the secp256r1 curve.
  secp256r1(DTLS_EC_KEY_SIZE, dtls_ecdh_curve.DTLS_ECDH_CURVE_SECP256R1);

  final int _internalEnumValue;

  /// The key size of this curve in bytes.
  final int byteLength;

  /// The key size of this curve in bits.
  int get bitLength => byteLength * _bitsPerByte;

  /// Constructor.
  const EcdsaCurve(this.byteLength, this._internalEnumValue);
}

/// A component (private key, or x or y coordinate of the public key) of an
/// [EcdsaKeys] object.
class _KeyComponent {
  final _ArgumentType _argumentType;

  /// The list of bytes representing this component of the [EcdsaKeys].
  final Uint8List byteArray;

  /// The byte length of this component of the [EcdsaKeys].
  int get length => byteArray.length;

  final EcdsaCurve _ecdsaCurve;

  _KeyComponent(this._argumentType, this.byteArray, this._ecdsaCurve) {
    _verify();
  }

  void _verify() {
    if (length != _ecdsaCurve.byteLength) {
      throw _EcdsaValidationError(_ecdsaCurve, _argumentType, length);
    }
  }
}

enum _ArgumentType {
  x,
  y,
  private;

  @override
  String toString() {
    if (this == private) {
      return "private key";
    }

    return "$name coordinate of the public key";
  }
}

class _EcdsaValidationError extends ArgumentError {
  final EcdsaCurve _ecdsaCurve;

  final _ArgumentType _argumentType;

  final int _actualByteLength;

  _EcdsaValidationError(
      this._ecdsaCurve, this._argumentType, this._actualByteLength);

  @override
  String get message {
    return "Expected a length of ${_ecdsaCurve.byteLength} bytes "
        "(${_ecdsaCurve.bitLength} bits) for the $_argumentType of the curve "
        "${_ecdsaCurve.name}, but found $_actualByteLength bytes instead!";
  }
}

/// Class representing ECC keys (one private and two public ones).
class EcdsaKeys {
  /// The elliptic curve these keys are associated with.
  final EcdsaCurve ecdsaCurve;

  /// The private key.
  final _KeyComponent privateKey;

  /// The x coordinate of the public key.
  final _KeyComponent publicKeyX;

  /// The y coordinate of the public key.
  final _KeyComponent publicKeyY;

  /// Constructor.
  EcdsaKeys(
    this.ecdsaCurve, {
    required Uint8List privateKey,
    required Uint8List publicKeyX,
    required Uint8List publicKeyY,
  })  : privateKey =
            _KeyComponent(_ArgumentType.private, privateKey, ecdsaCurve),
        publicKeyX = _KeyComponent(_ArgumentType.x, publicKeyX, ecdsaCurve),
        publicKeyY = _KeyComponent(_ArgumentType.y, publicKeyY, ecdsaCurve);
}

/// Convert [EcdsaKeys] object to a Dart ffi [Pointer].
Pointer<dtls_ecdsa_key_t> ecdsaKeysToPointer(EcdsaKeys ecdsaKeys) {
  final keySize = ecdsaKeys.ecdsaCurve.byteLength;
  final ecdsaKeyStruct = malloc<dtls_ecdsa_key_t>();

  ecdsaKeyStruct.ref
    ..priv_key = malloc<Uint8>(keySize)
    ..pub_key_x = malloc<Uint8>(keySize)
    ..pub_key_y = malloc<Uint8>(keySize)
    ..curve = ecdsaKeys.ecdsaCurve._internalEnumValue
    ..priv_key.asTypedList(keySize).setAll(0, ecdsaKeys.privateKey.byteArray)
    ..pub_key_x.asTypedList(keySize).setAll(0, ecdsaKeys.publicKeyX.byteArray)
    ..pub_key_y.asTypedList(keySize).setAll(0, ecdsaKeys.publicKeyY.byteArray);

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
