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

import 'dtls_connection.dart';
import 'dtls_event.dart';
import 'ecdsa_keys.dart';
import 'ffi/generated_bindings.dart';
import 'library.dart';
import 'psk_credentials.dart';
import 'types.dart';
import 'util.dart';

int _handleWrite(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<ffi.Uint8> dataAddress, int dataLength) {
  final data = dataAddress.asTypedList(dataLength).buffer.asUint8List();
  final address = addressFromSession(session);
  final port = portFromSession(session);

  final connection = DtlsClientConnection._connections[context.address];
  return connection?._sendInternal(data, address, port) ?? errorCode;
}

int _handleRead(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<ffi.Uint8> dataAddress, int dataLength) {
  final connection = DtlsClientConnection._connections[context.address];

  if (connection == null) {
    return errorCode;
  }

  final data = dataAddress.asTypedList(dataLength);
  final address = addressFromSession(session);
  final port = portFromSession(session);

  connection._receive(Datagram(data, address, port));

  return dataLength;
}

int _handleEvent(Pointer<dtls_context_t> context, Pointer<session_t> session,
    int level, int code) {
  final connection = DtlsClientConnection._connections[context.address];

  if (connection == null) {
    return errorCode;
  }

  final dtlsEvent = eventFromCode(code);

  if (dtlsEvent != null) {
    connection._emitDtlsEvent(dtlsEvent);
  }

  return success;
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
  final connection = DtlsClientConnection._connections[context.address];

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
        return createFatalError(dtls_alert_t.DTLS_ALERT_INTERNAL_ERROR);
      }
      final identityBytes = utf8.encoder.convert(_identity);
      result.asTypedList(resultLength).setAll(0, identityBytes);
      return identityBytes.lengthInBytes;
    case dtls_credentials_type_t.DTLS_PSK_KEY:
      {
        if (psk == null || identity != idString) {
          return createFatalError(dtls_alert_t.DTLS_ALERT_ILLEGAL_PARAMETER);
        }

        final pskBytes = utf8.encoder.convert(psk);
        result.asTypedList(resultLength).setAll(0, pskBytes);
        return pskBytes.lengthInBytes;
      }
    case dtls_credentials_type_t.DTLS_PSK_HINT:
    default:
      return createFatalError(dtls_alert_t.DTLS_ALERT_INTERNAL_ERROR);
  }
}

int _retrieveEcdsaInfo(
    Pointer<dtls_context_t> context,
    Pointer<session_t> session,
    ffi.Pointer<ffi.Pointer<dtls_ecdsa_key_t>> key) {
  final connection = DtlsClientConnection._connections[context.address];

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

  final Map<String, DtlsClientConnection> _connections = {};

  bool _externalSocket = true;

  /// Creates a new [DtlsClient] that uses a pre-existing [RawDatagramSocket].
  ///
  /// During connection, the client uses a default maximal timeout of 60 seconds
  /// for each handshake exchange and will resend messages during each exchange
  /// with an increasing delay. The total time span used for the timeout of
  /// message exchanges can be set with the [_maxTimeoutSeconds] argument.
  DtlsClient(this._socket, {int maxTimeoutSeconds = 60, TinyDTLS? tinyDTLS})
      : _maxTimeoutSeconds = maxTimeoutSeconds,
        _tinyDtls = initializeTinyDtls(tinyDTLS) {
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

  void _checkConnectionStatus(DtlsClientConnection connection) {
    final session = connection._session;
    final context = connection._context;

    connection._connectionTimeout?.cancel();

    final peer = _tinyDtls.dtls_get_peer(context, session);
    if (peer == nullptr) {
      connection.close(closedByClient: true);
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

  /// Establishes a [DtlsClientConnection] with a peer using the given [address]
  /// and [port].
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
    if (existingConnection != null && !existingConnection._closed) {
      return existingConnection;
    }

    final context = _createContext(
        hasPsk: pskCredentials != null, hasEcdsaKey: ecdsaKeys != null);
    final session = createSession(_tinyDtls, address, port);

    final connection = DtlsClientConnection(
        this, session, context, address, port,
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

  void _completeTimeout(DtlsClientConnection connection) {
    final completer = connection._connectCompleter;
    if (!completer.isCompleted) {
      completer.completeError(TimeoutException("Connecting to peer failed!"));
    }
  }

  void _createTimeout(
      DtlsClientConnection connection, Pointer<dtls_context_t> context,
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

  void _handleTimeout(DtlsClientConnection connection,
      Pointer<dtls_context_t> context, int timeoutCount, int timeoutSeconds) {
    if (connection._closed || connection._connected) {
      return _completeTimeout(connection);
    }
    _tinyDtls.dtls_check_retransmit(context, nullptr);
    _createTimeout(connection, context, ++timeoutCount, timeoutSeconds * 2);
  }

  int _send(List<int> data, Pointer<dtls_context_t> context,
      Pointer<session_t> session) {
    buffer.asTypedList(data.length).setAll(0, data);
    final result = _tinyDtls.dtls_write(context, session, buffer, data.length);

    if (result == -1) {
      throw StateError("Error sending DTLS message");
    } else if (result == 0) {
      throw StateError("Not connected to DTLS peer");
    }

    return result;
  }

  void _receive(Uint8List data, Pointer<dtls_context_t> context,
      Pointer<session_t> session) {
    buffer.asTypedList(data.length).setAll(0, data);
    _tinyDtls.dtls_handle_message(context, session, buffer, data.length);
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
      connection.close(closedByClient: true);
    }

    _connections.clear();
    if (!_externalSocket || closeExternalSocket) {
      _socket.close();
    }

    _closed = true;
  }
}

/// Represents a [DtlsClient]'s connection to a peer.
///
/// Can be used to [send] data to the peer.
class DtlsClientConnection extends Stream<Datagram> implements DtlsConnection {
  bool _closed = false;

  bool _connected = false;

  final InternetAddress _address;

  final int _port;

  /// Whether this [DtlsClientConnection] is still connected.
  @override
  bool get connected => _connected;

  final DtlsClient _dtlsClient;

  final Pointer<dtls_context_t> _context;

  final _received = StreamController<Datagram>();
  Stream<Datagram> get _receivedStream => _received.stream;

  final Pointer<session_t> _session;

  static final Map<int, DtlsClientConnection> _connections = {};

  final PskCredentials? _pskCredential;

  Timer? _connectionTimeout;

  Pointer<dtls_ecdsa_key_t> _ecdsaKeyStruct = nullptr;

  final _dtlsEvents = StreamController<DtlsEvent>();
  Stream<DtlsEvent> get _eventStream => _dtlsEvents.stream;

  final Completer<DtlsClientConnection> _connectCompleter = Completer();

  /// Constructor
  DtlsClientConnection(
      this._dtlsClient, this._session, this._context, this._address, this._port,
      {PskCredentials? pskCredentials,
      EcdsaKeys? ecdsaKeys,
      void Function(DtlsEvent event)? eventListener})
      : _pskCredential = pskCredentials {
    _connections[_context.address] = this;

    if (ecdsaKeys != null) {
      _ecdsaKeyStruct = ecdsaKeysToPointer(ecdsaKeys);
    }

    _eventStream.listen(eventListener);
  }

  void _emitDtlsEvent(DtlsEvent event) {
    _dtlsEvents.sink.add(event);
    if (event == DtlsEvent.dtlsEventCloseNotify) {
      close(freeResources: false);
    }
  }

  /// Sends [data] to the endpoint of this [DtlsClientConnection].
  ///
  /// Returns the number of bytes written. A [StateError] is thrown if the
  /// [DtlsClient] is not connected to the peer anymore.
  @override
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
    _received.sink.add(data);
  }

  /// Closes this [DtlsClientConnection].
  @override
  void close({bool freeResources = true, bool closedByClient = false}) {
    if (_closed) {
      return;
    }

    if (freeResources) {
      // Here, the closing of the connection has been triggered by the user, so
      // the resources need to be cleaned up "manually". Otherwise, the
      // connection has been closed by the peer and this step is handled by
      // tinyDTLS.
      _dtlsClient._tinyDtls
        ..dtls_close(_context, _session)
        ..dtls_free_context(_context)
        ..dtls_free_session(_session);
    }

    _connections.remove(_context.address);

    if (!closedByClient) {
      // This distinction is made to avoid concurrent modification errors.
      _dtlsClient._connections.remove(_context.address);
    }

    freeEdcsaStruct(_ecdsaKeyStruct);
    _dtlsEvents.close();
    _received.close();

    _closed = true;
    _connected = false;
  }

  /// Listens for incoming application data that will be passed to the [onData]
  /// handler as [Datagram]s.
  ///
  /// Data from all receiving connections will be passed to this callback.
  ///
  /// The [onError], [onDone], and [cancelOnError] parameters are passed to the
  /// underlying [Stream], just as the [onData] handler.
  @override
  StreamSubscription<Datagram> listen(void Function(Datagram event)? onData,
      {Function? onError, void Function()? onDone, bool? cancelOnError}) {
    return _receivedStream.listen(onData,
        onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  }
}
