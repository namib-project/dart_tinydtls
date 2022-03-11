// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:ffi';
import 'dart:ffi' as ffi;

import 'ffi/generated_bindings.dart';

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
typedef NativeWriteHandler = ffi.Int32 Function(Pointer<dtls_context_t>,
    Pointer<session_t>, Pointer<ffi.Uint8>, ffi.Uint64);

/// Native function signature of a Read handler for tinyDTLS.
///
/// Has the same signature as the Write handler.
typedef NativeReadHandler = NativeWriteHandler;

/// Native function signature of an Event handler for tinyDTLS.
typedef NativeEventHandler = ffi.Int32 Function(
    Pointer<dtls_context_t>, Pointer<session_t>, ffi.Int32, ffi.Uint16);

/// Native function signature of a PSK store handler for tinyDTLS.
typedef NativePskHandler = ffi.Int32 Function(
    ffi.Pointer<dtls_context_t>,
    ffi.Pointer<session_t>,
    ffi.Int32,
    ffi.Pointer<ffi.Uint8>,
    size_t,
    ffi.Pointer<ffi.Uint8>,
    size_t);

/// Native function signature of an ECDSA key store handler for tinyDTLS.
typedef NativeEcdsaHandler = ffi.Int32 Function(ffi.Pointer<dtls_context_t>,
    ffi.Pointer<session_t>, ffi.Pointer<ffi.Pointer<dtls_ecdsa_key_t>>);

/// Native function signature of an ECDSA verification handler for tinyDTLS.
typedef NativeEcdsaVerifyHandler = ffi.Int32 Function(
    ffi.Pointer<dtls_context_t>,
    ffi.Pointer<session_t>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    size_t);
