// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'dtls_connection.dart';
import 'dtls_event.dart';
import 'ecdsa_keys.dart';
import 'ffi/generated_bindings.dart';
import 'library.dart';
import 'types.dart';
import 'util.dart';

/// Callback signature for retrieving Pre-Shared Keys from a [DtlsServer]'s
/// keystore.
typedef PskKeyStoreCallback = Uint8List? Function(Uint8List identity);

DtlsServerConnection? _serverConnectionFromSession(Pointer<session_t> session) {
  final address = addressFromSession(session);
  final port = portFromSession(session);
  final connectionKey = getConnectionKey(address, port);
  return DtlsServerConnection._connections[connectionKey];
}

int _handleWrite(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<Uint8> dataAddress, int dataLength) {
  final data = dataAddress.asTypedList(dataLength).buffer.asUint8List();
  final address = addressFromSession(session);
  final port = portFromSession(session);
  final connection = _serverConnectionFromSession(session);

  return connection?._sendInternal(data, address, port) ?? errorCode;
}

int _handleRead(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<Uint8> dataAddress, int dataLength) {
  final address = addressFromSession(session);
  final port = portFromSession(session);
  final connection = _serverConnectionFromSession(session);

  if (connection == null) {
    return errorCode;
  }

  final data = dataAddress.asTypedList(dataLength);

  connection._receive(Datagram(data, address, port));

  return dataLength;
}

int _handleEvent(Pointer<dtls_context_t> context, Pointer<session_t> session,
    int level, int code) {
  final connection = _serverConnectionFromSession(session);

  if (connection == null) {
    return errorCode;
  }

  final dtlsEvent = DtlsEvent.fromCodes(level, code);
  connection._handleDtlsEvent(dtlsEvent);

  return success;
}

int _retrievePskInfo(
  Pointer<dtls_context_t> context,
  Pointer<session_t> session,
  int type,
  Pointer<Uint8> id,
  int idLen,
  Pointer<Uint8> result,
  int resultLength,
) {
  if (type == dtls_credentials_type_t.DTLS_PSK_IDENTITY) {
    return 0;
  }

  final server = DtlsServer._servers[context.address];

  if (server == null) {
    return errorCode;
  }

  if (type == dtls_credentials_type_t.DTLS_PSK_HINT) {
    final pskIdentityHintCallback = server._pskIdentityHintCallback;

    if (pskIdentityHintCallback == null) {
      return 0;
    }

    final address = addressFromSession(session);
    final port = portFromSession(session);

    final pskIdentityHint = pskIdentityHintCallback(address, port);
    result.asTypedList(resultLength).setAll(0, pskIdentityHint);
    return pskIdentityHint.lengthInBytes;
  }

  final psk = server._pskKeyStoreCallback?.call(id.asTypedList(idLen));

  if (psk != null) {
    if (resultLength < psk.length) {
      return createFatalError(dtls_alert_t.DTLS_ALERT_INTERNAL_ERROR);
    }
    result.asTypedList(resultLength).setAll(0, psk);
    return psk.lengthInBytes;
  }

  return createFatalError(dtls_alert_t.DTLS_ALERT_DECRYPT_ERROR);
}

int _retrieveEcdsaInfo(Pointer<dtls_context_t> context,
    Pointer<session_t> session, Pointer<Pointer<dtls_ecdsa_key_t>> key) {
  final server = DtlsServer._servers[context.address];

  if (server == null) {
    return errorCode;
  }

  final ecdsaKey = server._ecdsaKeyStruct;

  key.value = Pointer.fromAddress(ecdsaKey.address);

  return success;
}

int _verifyEcdsaKey(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<Uint8> publicKeyX, Pointer<Uint8> publicKeyY, int keySize) {
  return success;
}

/// Serves as a wrapper to tinyDTLS' server functionality.
///
/// Allows you to [bind] the [DtlsServer] to a UDP port of your choice. Once a
/// connection to a client is established, the server emits
/// [DtlsServerConnection]s you can [listen] for.
///
/// You can define multiple Pre-Shared Keys or an [EcdsaKeys] object that will
/// be used by server to encrypt its communication with DTLS Clients.
class DtlsServer extends Stream<DtlsServerConnection> {
  final TinyDTLS _tinyDtls;

  final RawDatagramSocket _socket;

  static final Map<int, DtlsServer> _servers = {};

  final Map<String, DtlsServerConnection> _connections = {};

  final Map<String, Pointer<session_t>> _sessions = {};

  bool _externalSocket = true;

  final _connectionStream = StreamController<DtlsServerConnection>();

  Stream<DtlsServerConnection> get _receivedStream => _connectionStream.stream;

  bool _closed = false;

  /// Indicates whether this Server is closed.
  bool get closed => _closed;

  Pointer<dtls_ecdsa_key_t> _ecdsaKeyStruct = nullptr;

  late final Pointer<dtls_context_t> _context;

  final PskIdentityHintCallback? _pskIdentityHintCallback;

  /// Constructor
  DtlsServer(
    this._socket, {
    EcdsaKeys? ecdsaKeys,
    PskKeyStoreCallback? pskKeyStoreCallback,
    TinyDTLS? tinyDTLS,
    PskIdentityHintCallback? pskIdentityHintCallback,
  })  : _tinyDtls = initializeTinyDtls(tinyDTLS),
        _pskKeyStoreCallback = pskKeyStoreCallback,
        _pskIdentityHintCallback = pskIdentityHintCallback {
    _context = _tinyDtls.dtls_new_context(nullptr);
    if (_pskKeyStoreCallback == null && ecdsaKeys == null) {
      throw ArgumentError("No DTLS client credentials have been provided.");
    }

    if (ecdsaKeys != null) {
      _ecdsaKeyStruct = ecdsaKeysToPointer(ecdsaKeys);
    }

    _startListening();
  }

  final PskKeyStoreCallback? _pskKeyStoreCallback;

  /// Binds a [DtlsServer] to the given [host] and [port].
  ///
  /// The server will either use the pairs of Identities and Pre-Shared Keys
  /// provided by the [pskKeyStoreCallback] or a set of [EcdsaKeys] to establish
  /// connections with peers. If no credentials are provided, a [StateError]
  /// will be thrown.
  ///
  /// Uses a [RawDatagramSocket] internally and passes the [host], [port],
  /// and [ttl] arguments to it.
  static Future<DtlsServer> bind(
    dynamic host,
    int port, {
    int ttl = 1,
    TinyDTLS? tinyDtls,
    PskKeyStoreCallback? pskKeyStoreCallback,
    EcdsaKeys? ecdsaKeys,
    PskIdentityHintCallback? pskIdentityHintCallback,
  }) async {
    final socket = await RawDatagramSocket.bind(host, port, ttl: ttl);
    return DtlsServer(socket,
        tinyDTLS: tinyDtls,
        pskKeyStoreCallback: pskKeyStoreCallback,
        ecdsaKeys: ecdsaKeys,
        pskIdentityHintCallback: pskIdentityHintCallback)
      .._externalSocket = false;
  }

  void _startListening() {
    _servers[_context.address] = this;

    final Pointer<NativeFunction<NativeReadHandler>> readHandler =
        Pointer.fromFunction(_handleRead, errorCode);
    final Pointer<NativeFunction<NativeWriteHandler>> writeHandler =
        Pointer.fromFunction(_handleWrite, errorCode);
    final Pointer<NativeFunction<NativeEventHandler>> eventHandler =
        Pointer.fromFunction(_handleEvent, errorCode);

    final Pointer<NativeFunction<NativePskHandler>> pskHandler;

    if (_pskKeyStoreCallback != null) {
      pskHandler = Pointer.fromFunction(_retrievePskInfo, errorCode);
    } else {
      pskHandler = nullptr;
    }

    Pointer<NativeFunction<NativeEcdsaHandler>> ecdsaHandler;

    Pointer<NativeFunction<NativeEcdsaVerifyHandler>> verifyEcdsaHandler;

    if (_ecdsaKeyStruct != nullptr) {
      ecdsaHandler = Pointer.fromFunction(_retrieveEcdsaInfo, errorCode);
      verifyEcdsaHandler = Pointer.fromFunction(_verifyEcdsaKey, errorCode);
    } else {
      ecdsaHandler = nullptr;
      verifyEcdsaHandler = nullptr;
    }

    final handlers = malloc<dtls_handler_t>();
    handlers.ref.read = readHandler;
    handlers.ref.write = writeHandler;
    handlers.ref.event = eventHandler;
    handlers.ref.get_psk_info = pskHandler;
    handlers.ref.get_ecdsa_key = ecdsaHandler;
    handlers.ref.verify_ecdsa_key = verifyEcdsaHandler;
    _context.ref.h = handlers;

    _socket.listen((event) async {
      if (event == RawSocketEvent.read) {
        final data = _socket.receive();
        if (data != null) {
          buffer.asTypedList(data.data.length).setAll(0, data.data);
          final address = data.address;
          final port = data.port;
          final connectionKey = getConnectionKey(address, port);

          final Pointer<session_t> session;
          final connection = _connections[connectionKey];

          if (connection != null && !connection._closed) {
            session = connection._session;
          } else {
            session = createSession(_tinyDtls, data.address, port);
            final connection =
                DtlsServerConnection(this, session, _context, address, port);
            _connections[connectionKey] = connection;
            _connectionStream.add(connection);
          }

          _tinyDtls.dtls_handle_message(
              _context, session, buffer, data.data.length);
        }
      }
    });
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

  /// Closes this [DtlsServer].
  ///
  /// [RawDatagramSocket]s that have been passed in by the user are only closed
  /// if [closeExternalSocket] is set to `true`.
  void close({bool closeExternalSocket = false}) {
    if (_closed) {
      return;
    }

    for (final connection in _connections.values) {
      connection.close(closedByServer: true);
    }
    _connections.clear();

    _tinyDtls.dtls_free_context(_context);

    _servers.remove(_context.address);
    freeEdcsaStruct(_ecdsaKeyStruct);
    _connectionStream.close();

    if (!_externalSocket || closeExternalSocket) {
      _socket.close();
    }

    _closed = true;
  }

  /// Listens for incoming [DtlsConnection]s.
  ///
  /// The [onError], [onDone], and [cancelOnError] parameters are passed to the
  /// underlying [Stream], just as the [onData] handler.
  @override
  StreamSubscription<DtlsServerConnection> listen(
      void Function(DtlsServerConnection event)? onData,
      {Function? onError,
      void Function()? onDone,
      bool? cancelOnError}) {
    return _receivedStream.listen(onData,
        onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  }
}

/// This Event is emitted if a [DtlsServer] receives application data.
class DtlsServerConnection extends Stream<Datagram> implements DtlsConnection {
  bool _connected = false;

  bool _closed = false;

  /// Whether this [DtlsServerConnection] is still connected.
  @override
  bool get connected => _connected;

  final DtlsServer _server;

  final Pointer<dtls_context_t> _context;

  final Pointer<session_t> _session;

  final _received = StreamController<Datagram>();
  Stream<Datagram> get _receivedStream => _received.stream;

  final InternetAddress _address;

  final int _port;

  static final Map<String, DtlsServerConnection> _connections = {};

  /// Constructor
  DtlsServerConnection(
      this._server, this._session, this._context, this._address, this._port) {
    _connected = true;
    final connectionKey = getConnectionKey(_address, _port);
    _connections[connectionKey] = this;
  }

  void _handleDtlsEvent(DtlsEvent event) {
    if (event.requiresClosing) {
      close(freeResources: false);
    }
  }

  /// Sends [data] to the peer of the [DtlsServer] where this
  /// [DtlsServerConnection] originated from.
  @override
  int send(List<int> data) {
    if (!_connected) {
      throw StateError("Sending failed: Not connected!");
    }
    return _server._send(data, _context, _session);
  }

  @override
  void close({bool freeResources = true, bool closedByServer = false}) {
    if (_closed) {
      return;
    }

    if (freeResources) {
      // Here, the closing of the connection has been triggered by the user, so
      // the resources need to be cleaned up "manually". Otherwise, the
      // connection has been closed by the peer and this step is handled by
      // tinyDTLS.
      _server._tinyDtls
        ..dtls_close(_context, _session)
        ..dtls_free_session(_session);
    }

    _server._sessions.remove(_session.address);

    if (!closedByServer) {
      // This distinction is made to avoid concurrent modification errors.
      final connectionKey = getConnectionKey(_address, _port);
      _server._connections.remove(connectionKey);
    }

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

  void _receive(Datagram data) {
    _received.sink.add(data);
  }

  int _sendInternal(List<int> data, InternetAddress address, int port) {
    return _server._socket.send(data, address, port);
  }
}
