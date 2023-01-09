// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:ffi';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'ffi/generated_bindings.dart';
import 'psk_credentials.dart';

/// Magic number used for error codes.
const errorCode = -1;

/// Magic number used for success return codes.
const success = 0;

/// Magic number for indicating IPv4 usage.
// ignore: constant_identifier_names
const AF_INET = 2;

/// Magic number for indicating IPv6 usage.
// ignore: constant_identifier_names
const AF_INET6 = 10;

/// Native function signature of a Write handler for tinyDTLS.
typedef NativeWriteHandler = ffi.Int Function(Pointer<dtls_context_t>,
    Pointer<session_t>, Pointer<ffi.UnsignedChar>, ffi.Size);

/// Native function signature of a Read handler for tinyDTLS.
///
/// Has the same signature as the Write handler.
typedef NativeReadHandler = NativeWriteHandler;

/// Native function signature of an Event handler for tinyDTLS.
typedef NativeEventHandler = ffi.Int Function(
    Pointer<dtls_context_t>, Pointer<session_t>, ffi.Int32, ffi.UnsignedShort);

/// Native function signature of a PSK store handler for tinyDTLS.
typedef NativePskHandler = ffi.Int Function(
    ffi.Pointer<dtls_context_t>,
    ffi.Pointer<session_t>,
    ffi.Int32,
    ffi.Pointer<ffi.UnsignedChar>,
    ffi.Size,
    ffi.Pointer<ffi.UnsignedChar>,
    ffi.Size);

/// Native function signature of an ECDSA key store handler for tinyDTLS.
typedef NativeEcdsaHandler = ffi.Int Function(ffi.Pointer<dtls_context_t>,
    ffi.Pointer<session_t>, ffi.Pointer<ffi.Pointer<dtls_ecdsa_key_t>>);

/// Native function signature of an ECDSA verification handler for tinyDTLS.
typedef NativeEcdsaVerifyHandler = ffi.Int Function(
    ffi.Pointer<dtls_context_t>,
    ffi.Pointer<session_t>,
    ffi.Pointer<ffi.UnsignedChar>,
    ffi.Pointer<ffi.UnsignedChar>,
    ffi.Size);

/// Function signature for a callback function for retrieving/generating
/// [PskCredentials].
///
/// As the format of the [identityHint] is not well-defined, this parameter
/// can probably be ignored in most cases, when both the identity and the key
/// are known in advance.
typedef PskCallback = PskCredentials Function(Uint8List identityHint);

/// Function signature for a callback function for generating a PSK identity
/// hint for a peer, optionally based on its [address] and/or [port].
typedef PskIdentityHintCallback = Uint8List Function(
    InternetAddress address, int port);
