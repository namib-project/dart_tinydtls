// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'ecdsa_keys.dart';
import 'ffi/generated_bindings.dart';
import 'library.dart';
import 'types.dart';

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
  final Pointer<ffi.Uint8> pointer = session.cast();
  const _ipv4AddressOffset = 8;
  const _ipv4AddressByteLength = 4;
  return InternetAddress.fromRawAddress(pointer
      .elementAt(_ipv4AddressOffset)
      .asTypedList(_ipv4AddressByteLength));
}

InternetAddress _ipv6AddressFromSession(Pointer<session_t> session) {
  final Pointer<ffi.Uint8> pointer = session.cast();

  const _ipv6AddressOffset = 16;
  const _ipv6AddressByteLength = 16;

  return InternetAddress.fromRawAddress(pointer
      .elementAt(_ipv6AddressOffset)
      .asTypedList(_ipv6AddressByteLength));
}

InternetAddress _addressFromSession(Pointer<session_t> session) {
  final type = _addressTypeFromSession(session);

  if (type == InternetAddressType.IPv4) {
    return _ipv4AddressFromSession(session);
  } else {
    // type must be InternetAddressType.IPv6 here
    return _ipv6AddressFromSession(session);
  }
}

int _portFromSession(Pointer<session_t> session) {
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

int _handleWrite(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<ffi.Uint8> dataAddress, int dataLength) {
  final data = dataAddress.asTypedList(dataLength).buffer.asUint8List();
  final address = _addressFromSession(session);
  final port = _portFromSession(session);

  final connection = DtlsConnection._connections[context.address];
  return connection?._sendInternal(data, address, port) ?? errorCode;
}

int _handleRead(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<ffi.Uint8> dataAddress, int dataLength) {
  final connection = DtlsConnection._connections[context.address];

  if (connection == null) {
    return errorCode;
  }

  final data = dataAddress.asTypedList(dataLength);
  final address = _addressFromSession(session);
  final port = _portFromSession(session);

  connection._receive(Datagram(data, address, port));

  return dataLength;
}

/// Events that are being signalled by tinyDTLS during and after the
/// connection establishment.
enum DtlsEvent {
  /// Occurs when the Client is trying to connect to the peer.
  dtlsEventConnect,

  /// Occurs when the connection has been successfully established.
  dtlsEventConnected,

  /// Occurs if the Client is trying to re-connect to an endpoint.
  dtlsEventRenegotiate
}

DtlsEvent? _eventFromCode(int code) {
  switch (code) {
    case DTLS_EVENT_CONNECT:
      return DtlsEvent.dtlsEventConnect;
    case DTLS_EVENT_CONNECTED:
      return DtlsEvent.dtlsEventConnected;
    case DTLS_EVENT_RENEGOTIATE:
      return DtlsEvent.dtlsEventRenegotiate;
    default:
      return null;
  }
}

int _handleEvent(Pointer<dtls_context_t> context, Pointer<session_t> session,
    int level, int code) {
  final connection = DtlsConnection._connections[context.address];

  if (connection == null) {
    return errorCode;
  }

  final dtlsEvent = _eventFromCode(code);

  if (dtlsEvent != null) {
    connection._emitDtlsEvent(dtlsEvent);
  }

  return success;
}

/// Reimplementation of an inline function that encodes a log level for fatal errors
/// and a numeric [description] code into a single value.
int _createFatalError(int description) {
  return -((dtls_alert_level_t.DTLS_ALERT_LEVEL_FATAL << 8) | description);
}

int _retrievePskInfo(
  Pointer<dtls_context_t> context,
  Pointer<session_t> session,
  int type,
  Pointer<ffi.Uint8> id,
  int idLen,
  Pointer<ffi.Uint8> result,
  int resultLength,
) {
  final connection = DtlsConnection._connections[context.address];

  if (connection == null) {
    return errorCode;
  }

  final pskCredentials = connection._pskCredential;

  final psk = pskCredentials?.preSharedKey;
  final identity = pskCredentials?.identity;

  final idString = utf8.decode(id.asTypedList(idLen));

  switch (type) {
    case dtls_credentials_type_t.DTLS_PSK_IDENTITY:
      final _identity = identity ?? "";
      if (resultLength < _identity.length) {
        return _createFatalError(dtls_alert_t.DTLS_ALERT_INTERNAL_ERROR);
      }
      final identityBytes = utf8.encoder.convert(_identity);
      result.asTypedList(resultLength).setAll(0, identityBytes);
      return identityBytes.lengthInBytes;
    case dtls_credentials_type_t.DTLS_PSK_KEY:
      {
        if (psk == null || identity != idString) {
          return _createFatalError(dtls_alert_t.DTLS_ALERT_ILLEGAL_PARAMETER);
        }

        final pskBytes = utf8.encoder.convert(psk);
        result.asTypedList(resultLength).setAll(0, pskBytes);
        return pskBytes.lengthInBytes;
      }
    case dtls_credentials_type_t.DTLS_PSK_HINT:
    default:
      return _createFatalError(dtls_alert_t.DTLS_ALERT_INTERNAL_ERROR);
  }
}

int _retrieveEcdsaInfo(
    Pointer<dtls_context_t> context,
    Pointer<session_t> session,
    ffi.Pointer<ffi.Pointer<dtls_ecdsa_key_t>> key) {
  final connection = DtlsConnection._connections[context.address];

  if (connection == null) {
    return errorCode;
  }

  final ecdsaKey = connection._ecdsaKeyStruct;

  key.value = Pointer.fromAddress(ecdsaKey.address);

  return success;
}

int _verifyEcdsaKey(
    ffi.Pointer<dtls_context_t> context,
    ffi.Pointer<session_t> session,
    ffi.Pointer<ffi.Uint8> publicKeyX,
    ffi.Pointer<ffi.Uint8> publicKeyY,
    int keySize) {
  return success;
}

/// Credentials used for PSK Cipher Suites consisting of an [identity]
/// and a [preSharedKey].
class PskCredentials {
  /// The identity used with the [preSharedKey].
  String identity;

  /// The actual pre-shared key.
  String preSharedKey;

  /// Constructor
  PskCredentials(this.identity, this.preSharedKey);
}

/// Client for connecting to DTLS Servers and sending UDP packets with encrpyted
/// payloads afterwards.
///
/// Uses a [RawDatagramSocket] for connection establishment and sending. This
/// socket can either be created by the [DtlsClient] itself, using the [bind]
/// method, or provided by the user with the regular constructor.
///
/// Connections to a peer are established using the [connect] method. Here,
/// you can either provide [PskCredentials] or [EcdsaKeys] for using Elliptic
/// Curve Cryptography (ECC). If the connection is successful, a
/// [DtlsConnection] is returned that can be used for sending the actual
/// application data.
///
/// Closing the [DtlsClient] with the [close] method also closes all existing
/// [DtlsConnection]s.
class DtlsClient {
  final TinyDTLS _tinyDtls;

  bool _closed = false;

  final int _maxTimeoutSeconds;

  final RawDatagramSocket _socket;

  static const _bufferSize = (1 << 16);
  static final Pointer<Uint8> _buffer = malloc.call<Uint8>(_bufferSize);

  final _received = StreamController<Datagram>();
  Stream<Datagram> get _receivedStream => _received.stream;

  final Map<String, DtlsConnection> _connections = {};

  /// Used to check whether a [TinyDTLS] object has already been initialized.
  static final List<TinyDTLS> _initializationList = [];

  bool _externalSocket = true;

  static TinyDTLS _initializeTinyDtls(TinyDTLS? tinyDtls) {
    final selectedTinyDtls = tinyDtls ?? globalTinyDtls;
    if (!_initializationList.contains(selectedTinyDtls)) {
      selectedTinyDtls.dtls_init();
      _initializationList.add(selectedTinyDtls);
    }
    return selectedTinyDtls;
  }

  /// Creates a new [DtlsClient] that uses a pre-existing [RawDatagramSocket].
  ///
  /// During connection, the client uses a default maximal timeout of 60 seconds
  /// for each handshake exchange and will resend messages during each exchange
  /// with an increasing delay. The total time span used for the timeout of
  /// message exchanges can be set with the [_maxTimeoutSeconds] argument.
  DtlsClient(this._socket, {int maxTimeoutSeconds = 60, TinyDTLS? tinyDTLS})
      : _maxTimeoutSeconds = maxTimeoutSeconds,
        _tinyDtls = _initializeTinyDtls(tinyDTLS) {
    _startListening();
  }

  /// Binds a [DtlsClient] to the given [host] and [port].
  ///
  /// Uses a [RawDatagramSocket] internally and passes the [host], [port],
  /// [reusePort], [reuseAddress], and [ttl] arguments to it.
  ///
  /// During connection, the client uses a default maximal timeout of 60 seconds
  /// for each handshake exchange and will resend messages during each exchange
  /// with an increasing delay. The total time span used for the timeout of
  /// message exchanges can be set with the [maxTimeoutSeconds] argument.
  static Future<DtlsClient> bind(dynamic host, int port,
      {bool reusePort = false,
      bool reuseAddress = true,
      int ttl = 1,
      int maxTimeoutSeconds = 60,
      TinyDTLS? tinyDtls}) async {
    final socket = await RawDatagramSocket.bind(host, port,
        reusePort: reusePort, reuseAddress: reuseAddress, ttl: ttl);
    return DtlsClient(socket,
        maxTimeoutSeconds: maxTimeoutSeconds, tinyDTLS: tinyDtls)
      .._externalSocket = false;
  }

  /// Listens for incoming application data that will be passed to the [onData]
  /// handler as [Datagram]s.
  ///
  /// Data from all receiving connections will be passed to this callback.
  ///
  /// The [onError], [onDone], and [cancelOnError] parameters are passed to the
  /// underlying [Stream], just as the [onData] handler.
  // TODO(JKRhb): Consider returning a custom event class instead.
  StreamSubscription<Datagram> listen(void Function(Datagram event)? onData,
      {Function? onError, void Function()? onDone, bool? cancelOnError}) {
    return _receivedStream.listen(onData,
        onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  }

  Pointer<dtls_context_t> _createContext(
      {required bool hasPsk, required bool hasEcdsaKey}) {
    final context = _tinyDtls.dtls_new_context(nullptr);

    final Pointer<NativeFunction<NativeWriteHandler>> writeHandler =
        Pointer.fromFunction(_handleWrite, errorCode);

    final Pointer<NativeFunction<NativeReadHandler>> readHandler =
        Pointer.fromFunction(_handleRead, errorCode);

    final Pointer<NativeFunction<NativeEventHandler>> eventHandler =
        Pointer.fromFunction(_handleEvent, errorCode);

    final Pointer<NativeFunction<NativePskHandler>> pskHandler;

    if (hasPsk) {
      pskHandler = Pointer.fromFunction(_retrievePskInfo, errorCode);
    } else {
      pskHandler = nullptr;
    }

    Pointer<NativeFunction<NativeEcdsaHandler>> ecdsaHandler =
        Pointer.fromFunction(_retrieveEcdsaInfo, errorCode);

    Pointer<NativeFunction<NativeEcdsaVerifyHandler>> verifyEcdsaHandler =
        Pointer.fromFunction(_verifyEcdsaKey, errorCode);

    if (hasEcdsaKey) {
      ecdsaHandler = Pointer.fromFunction(_retrieveEcdsaInfo, errorCode);
      verifyEcdsaHandler = Pointer.fromFunction(_verifyEcdsaKey, errorCode);
    } else {
      ecdsaHandler = nullptr;
      verifyEcdsaHandler = nullptr;
    }

    final handlers = malloc<dtls_handler_t>();
    handlers.ref.write = writeHandler;
    handlers.ref.read = readHandler;
    handlers.ref.event = eventHandler;
    handlers.ref.get_psk_info = pskHandler;
    handlers.ref.get_ecdsa_key = ecdsaHandler;
    handlers.ref.verify_ecdsa_key = verifyEcdsaHandler;

    context.ref.h = handlers;
    return context;
  }

  /// Creates an IPv4 [sockaddr] struct and returns a [Pointer] to it.
  static Pointer<sockaddr> _fromIPv4Address(InternetAddress address, int port) {
    final sockAddr = malloc<sockaddr_in>();
    sockAddr.ref.sin_family = AF_INET;
    final inAddr = malloc<in_addr>();

    // The IPv4 version of the sockaddr struct seems to use network byte order,
    // therefore the bytes representing the address and the port have to be
    // reversed.
    inAddr.ref.s_addr = ByteData.view(
            Uint8List.fromList(address.rawAddress.reversed.toList()).buffer)
        .getUint32(0);
    sockAddr.ref.sin_addr = inAddr.ref;

    final sinPort = Uint16List(1)
      ..buffer.asByteData().setUint16(0, port, Endian.big);
    sockAddr.ref.sin_port = sinPort[0];

    return sockAddr.cast();
  }

  /// Creates an IPv6 [sockaddr] struct and returns a [Pointer] to it.
  static Pointer<sockaddr> _fromIPv6Address(InternetAddress address, int port) {
    final sockAddr = malloc<sockaddr_in6>();
    sockAddr.ref.sin6_family = AF_INET6;

    final Pointer<ffi.Uint8> addressArray =
        Pointer.fromAddress(sockAddr.address);
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

  static Pointer<sockaddr> _createSockAddr(InternetAddress address, int port) {
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

  static int _getAddrLen(InternetAddressType type) {
    switch (type) {
      case InternetAddressType.IPv4:
        return sizeOf<sockaddr_in>();
      case InternetAddressType.IPv6:
        return sizeOf<sockaddr_in6>();
      default:
        throw ArgumentError("Invalid InternetAddressType $type");
    }
  }

  void _checkConnectionStatus(DtlsConnection connection) {
    final session = connection._session;
    final context = connection._context;

    connection._connectionTimeout?.cancel();

    final peer = _tinyDtls.dtls_get_peer(context, session);
    if (peer == nullptr) {
      connection.close();
    } else if (!connection._connected &&
        peer.ref.state == dtls_state_t.DTLS_STATE_CONNECTED) {
      connection._connected = true;
      if (!connection._connectCompleter.isCompleted) {
        connection._connectCompleter.complete(connection);
      }
    } else {
      _createTimeout(connection, context);
    }
  }

  void _startListening() {
    _socket.listen((event) async {
      if (event == RawSocketEvent.read) {
        final data = _socket.receive();
        if (data != null) {
          for (final connection in _connections.values) {
            _receive(data.data, connection._context, connection._session);
            _checkConnectionStatus(connection);
          }
        }
      }
    });
  }

  Pointer<session_t> _createSession(InternetAddress address, int port) {
    final addr = _createSockAddr(address, port);
    final addrlen = _getAddrLen(address.type);
    final session = _tinyDtls.dtls_new_session(addr, addrlen);
    malloc.free(addr);

    if (session.address == nullptr.address) {
      throw StateError("Error occurred establishing DTLS session");
    }

    return session;
  }

  /// Establishes a [DtlsConnection] with a peer using the given [address] and
  /// [port].
  ///
  /// Either [pskCredentials] or [ecdsaKeys], or both can be provided (in this
  /// case the peer will be offered both a PSK and an ECC cipher during the
  /// DTLS Handshake).
  /// If neither [pskCredentials] nor [ecdsaKeys] are given, an [ArgumentError]
  /// is thrown.
  ///
  /// If a [DtlsConnection] to a peer with the given [address] and [port]
  /// already exists, that connection will be reused instead of opening a new
  /// one. If you want to establish a connection using different credentials,
  /// then you need to close the old connection first.
  Future<DtlsConnection> connect(InternetAddress address, int port,
      {PskCredentials? pskCredentials,
      EcdsaKeys? ecdsaKeys,
      void Function(DtlsEvent event)? eventListener}) async {
    if (pskCredentials == null && ecdsaKeys == null) {
      throw ArgumentError("No DTLS client credentials have been provided.");
    }

    final key = "${address.host}:$port";
    final existingConnection = _connections[key];
    if (existingConnection != null) {
      return existingConnection;
    }

    final context = _createContext(
        hasPsk: pskCredentials != null, hasEcdsaKey: ecdsaKeys != null);
    final session = _createSession(address, port);

    final connection = DtlsConnection(this, session, context,
        pskCredentials: pskCredentials,
        ecdsaKeys: ecdsaKeys,
        eventListener: eventListener);
    _connections[key] = connection;
    _createTimeout(connection, context);

    final result = _tinyDtls.dtls_connect(context, session);

    if (result == 0) {
      throw StateError("DTLS channel already exists!");
    } else if (result < 0) {
      throw StateError("An error occurred while trying to connect");
    }

    return connection._connectCompleter.future;
  }

  void _completeTimeout(DtlsConnection connection) {
    final completer = connection._connectCompleter;
    if (!completer.isCompleted) {
      completer.completeError(TimeoutException("Connecting to peer failed!"));
    }
  }

  void _createTimeout(
      DtlsConnection connection, Pointer<dtls_context_t> context,
      [int timeoutCount = 0, int timeoutSeconds = 1]) {
    if (timeoutSeconds < _maxTimeoutSeconds) {
      connection._connectionTimeout = Timer(
          Duration(seconds: timeoutSeconds),
          () => _handleTimeout(
              connection, context, timeoutCount, timeoutSeconds));
    } else {
      _completeTimeout(connection);
    }
  }

  void _handleTimeout(DtlsConnection connection,
      Pointer<dtls_context_t> context, int timeoutCount, int timeoutSeconds) {
    if (connection._closed || connection._connected) {
      return _completeTimeout(connection);
    }
    _tinyDtls.dtls_check_retransmit(context, nullptr);
    _createTimeout(connection, context, ++timeoutCount, timeoutSeconds * 2);
  }

  int _send(List<int> data, Pointer<dtls_context_t> context,
      Pointer<session_t> session) {
    _buffer.asTypedList(_bufferSize).setAll(0, data);
    final result = _tinyDtls.dtls_write(context, session, _buffer, data.length);

    if (result == -1) {
      throw StateError("Error sending DTLS message");
    } else if (result == 0) {
      throw StateError("Not connected to DTLS peer");
    }

    return result;
  }

  void _receive(Uint8List data, Pointer<dtls_context_t> context,
      Pointer<session_t> session) {
    _buffer.asTypedList(_bufferSize).setAll(0, data);
    _tinyDtls.dtls_handle_message(context, session, _buffer, _bufferSize);
  }

  /// Closes this [DtlsClient].
  ///
  /// [RawDatagramSocket]s that have been passed in by the user are only closed
  /// if [closeExternalSocket] is set to `true`.
  void close({bool closeExternalSocket = false}) {
    if (_closed) {
      return;
    }

    for (final connection in _connections.values) {
      connection.close();
    }

    _connections.clear();
    if (!_externalSocket || closeExternalSocket) {
      _socket.close();
    }

    _received.close();

    _closed = true;
  }
}

/// Convert [EcdsaKeys] object to a Dart ffi [Pointer].
Pointer<dtls_ecdsa_key_t> _ecdsaKeysToPointer(EcdsaKeys ecdsaKeys) {
  final ecdsaKeyStruct = malloc<dtls_ecdsa_key_t>();
  final structReference = ecdsaKeyStruct.ref
    ..priv_key = malloc<Uint8>(DTLS_EC_KEY_SIZE)
    ..pub_key_x = malloc<Uint8>(DTLS_EC_KEY_SIZE)
    ..pub_key_y = malloc<Uint8>(DTLS_EC_KEY_SIZE);

  switch (ecdsaKeys.ecdsaCurve) {
    case EcdsaCurve.dtlsEcdhCurveSecp256R1:
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

/// Represents a [DtlsClient]'s connection to a peer.
///
/// Can be used to [send] data to the peer.
class DtlsConnection {
  bool _closed = false;

  bool _connected = false;

  /// Whether this [DtlsConnection] is still connected.
  bool get connected => _connected;

  final DtlsClient _dtlsClient;

  final Pointer<dtls_context_t> _context;

  final Pointer<session_t> _session;

  static final Map<int, DtlsConnection> _connections = {};

  final PskCredentials? _pskCredential;

  Timer? _connectionTimeout;

  Pointer<dtls_ecdsa_key_t> _ecdsaKeyStruct = nullptr;

  final _dtlsEvents = StreamController<DtlsEvent>();
  Stream<DtlsEvent> get _eventStream => _dtlsEvents.stream;

  final Completer<DtlsConnection> _connectCompleter = Completer();

  /// Constructor
  DtlsConnection(this._dtlsClient, this._session, this._context,
      {PskCredentials? pskCredentials,
      EcdsaKeys? ecdsaKeys,
      void Function(DtlsEvent event)? eventListener})
      : _pskCredential = pskCredentials {
    _connections[_context.address] = this;

    if (ecdsaKeys != null) {
      _ecdsaKeyStruct = _ecdsaKeysToPointer(ecdsaKeys);
    }

    _eventStream.listen(eventListener);
  }

  void _emitDtlsEvent(DtlsEvent event) {
    _dtlsEvents.sink.add(event);
  }

  /// Sends [data] to the endpoint of this [DtlsConnection].
  ///
  /// Returns the number of bytes written. A [StateError] is thrown if the
  /// [DtlsClient] is not connected to the peer anymore.
  int send(List<int> data) {
    if (!_connected) {
      throw StateError("Sending failed: Not connected!");
    }
    return _dtlsClient._send(data, _context, _session);
  }

  int _sendInternal(List<int> data, InternetAddress address, int port) {
    return _dtlsClient._socket.send(data, address, port);
  }

  void _receive(Datagram data) {
    _dtlsClient._received.sink.add(data);
  }

  void _freeEdcsaStruct() {
    if (_ecdsaKeyStruct != nullptr) {
      final structReference = _ecdsaKeyStruct.ref;
      for (final keyPointer in [
        structReference.priv_key,
        structReference.pub_key_x,
        structReference.pub_key_y
      ]) {
        malloc.free(keyPointer);
      }
      malloc.free(_ecdsaKeyStruct);
    }
  }

  /// Closes this [DtlsConnection].
  void close() {
    if (_closed) {
      return;
    }

    _dtlsClient._tinyDtls
      ..dtls_close(_context, _session)
      ..dtls_free_context(_context)
      ..dtls_free_session(_session);

    _connections.remove(_context.address);

    _freeEdcsaStruct();
    _dtlsEvents.close();

    _closed = true;
    _connected = false;
  }
}
