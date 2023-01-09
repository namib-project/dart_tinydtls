// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'dtls_exception.dart';
import 'ffi/generated_bindings.dart';
import 'library.dart';

import 'types.dart';

/// Used to check whether a [TinyDTLS] object has already been initialized.
final List<TinyDTLS> _initializationList = [];

/// Initializes either a user-defined [TinyDTLS] instance or a global one.
///
/// Keeps track of initialized [TinyDTLS] instances in order to not initalize
/// the same instance twice.
TinyDTLS initializeTinyDtls(TinyDTLS? tinyDtls, {bool server = false}) {
  final TinyDTLS selectedTinyDtls = tinyDtls ?? globalTinyDtls;
  if (!_initializationList.contains(selectedTinyDtls)) {
    selectedTinyDtls.dtls_init();
    _initializationList.add(selectedTinyDtls);
  }
  return selectedTinyDtls;
}

/// Creates an IPv4 [sockaddr] struct and returns a [Pointer] to it.
Pointer<sockaddr> _fromIPv4Address(InternetAddress address, int port) {
  final sockAddr = malloc<sockaddr_in>();
  sockAddr.ref.sin_family = AF_INET;

  final Pointer<Uint8> addressArray = Pointer.fromAddress(sockAddr.address);
  final addressOffset = sizeOf<sa_family_t>() + sizeOf<in_port_t>();

  addressArray
      .elementAt(addressOffset)
      .asTypedList(sizeOf<in_addr>())
      .setAll(0, address.rawAddress.toList());

  final sinPort = Uint16List(1)
    ..buffer.asByteData().setUint16(0, port, Endian.little);
  sockAddr.ref.sin_port = sinPort[0];

  return sockAddr.cast();
}

/// Creates an IPv6 [sockaddr] struct and returns a [Pointer] to it.
Pointer<sockaddr> _fromIPv6Address(InternetAddress address, int port) {
  final sockAddr = malloc<sockaddr_in6>();
  sockAddr.ref.sin6_family = AF_INET6;

  final Pointer<Uint8> addressArray = Pointer.fromAddress(sockAddr.address);
  final addressOffset =
      sizeOf<sa_family_t>() + sizeOf<in_port_t>() + sizeOf<Uint32>();
  addressArray
      .elementAt(addressOffset)
      .asTypedList(sizeOf<in6_addr>())
      .setAll(0, address.rawAddress.toList());

  final sinPort = Uint16List(1)
    ..buffer.asByteData().setUint16(0, port, Endian.big);
  sockAddr.ref.sin6_port = sinPort[0];

  return sockAddr.cast();
}

Pointer<sockaddr> _createSockAddr(InternetAddress address, int port) {
  switch (address.type) {
    case InternetAddressType.IPv4:
      return _fromIPv4Address(address, port);
    case InternetAddressType.IPv6:
      return _fromIPv6Address(address, port);
    default:
      throw ArgumentError(
          "InternetAddressType '${address.type}' not supported");
  }
}

int _getAddrLen(InternetAddressType type) {
  switch (type) {
    case InternetAddressType.IPv4:
      return sizeOf<sockaddr_in>();
    case InternetAddressType.IPv6:
      return sizeOf<sockaddr_in6>();
    default:
      throw ArgumentError("Invalid InternetAddressType $type");
  }
}

/// Creates and allocates a new [session_t] from an [address] and a [port] and
/// returns a [Pointer] to it.
Pointer<session_t> createSession(
    TinyDTLS tinyDTLS, InternetAddress address, int port) {
  final addr = _createSockAddr(address, port);
  final addrlen = _getAddrLen(address.type);
  final session = tinyDTLS.dtls_new_session(addr, addrlen);
  malloc.free(addr);

  if (session.address == nullptr.address) {
    throw DtlsException("Error occurred establishing DTLS session");
  }

  return session;
}

InternetAddressType _addressTypeFromSession(Pointer<session_t> session) {
  final type = session.ref.addr.sa.sa_family;
  if (type == AF_INET) {
    return InternetAddressType.IPv4;
  } else if (type == AF_INET6) {
    return InternetAddressType.IPv6;
  }

  throw StateError("Unknown Internetaddress type $type in DTLS session");
}

InternetAddress _ipv4AddressFromSession(Pointer<session_t> session) {
  final Pointer<Uint8> pointer = session.cast();
  const ipv4AddressOffset = 12;
  const ipv4AddressByteLength = 4;
  return InternetAddress.fromRawAddress(
      pointer.elementAt(ipv4AddressOffset).asTypedList(ipv4AddressByteLength));
}

InternetAddress _ipv6AddressFromSession(Pointer<session_t> session) {
  final Pointer<Uint8> pointer = session.cast();

  const ipv6AddressOffset = 16;
  const ipv6AddressByteLength = 16;

  return InternetAddress.fromRawAddress(
      pointer.elementAt(ipv6AddressOffset).asTypedList(ipv6AddressByteLength));
}

/// Determines the [InternetAddress] used by a given DTLS [session].
InternetAddress addressFromSession(Pointer<session_t> session) {
  final type = _addressTypeFromSession(session);

  if (type == InternetAddressType.IPv4) {
    return _ipv4AddressFromSession(session);
  } else {
    // type must be InternetAddressType.IPv6 here
    return _ipv6AddressFromSession(session);
  }
}

/// Determines the port number used by a given DTLS [session].
int portFromSession(Pointer<session_t> session) {
  final type = _addressTypeFromSession(session);

  if (type == InternetAddressType.IPv4) {
    final sin = session.ref.addr.sin;
    return sin.sin_port;
  } else {
    // type must be InternetAddressType.IPv6 here
    final sin6 = session.ref.addr.sin6;
    final sinPort = Uint16List(1)
      ..buffer.asByteData().setUint16(0, sin6.sin6_port, Endian.big);
    return sinPort[0];
  }
}

/// Reimplementation of an inline function that encodes a log level for fatal
/// errors and a numeric [description] code into a single value.
int createFatalError(int description) {
  return -((dtls_alert_level_t.DTLS_ALERT_LEVEL_FATAL << 8) | description);
}

/// Creates a string key from an [address] and [port] intended for caching a
/// connection.
String getConnectionKey(InternetAddress address, int port) {
  return "${address.address}:$port";
}
