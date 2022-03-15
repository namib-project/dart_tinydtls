// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'ecdsa_keys.dart';
import 'ffi/generated_bindings.dart';
import 'library.dart';
import 'types.dart';
import 'util.dart';

int _handleWrite(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<Uint8> dataAddress, int dataLength) {
  final data = dataAddress.asTypedList(dataLength).buffer.asUint8List();
  final address = addressFromSession(session);
  final port = portFromSession(session);

  final server = DtlsServer._servers[context.address];
  return server?._sendInternal(data, address, port) ?? errorCode;
}

int _handleRead(Pointer<dtls_context_t> context, Pointer<session_t> session,
    Pointer<Uint8> dataAddress, int dataLength) {
  final server = DtlsServer._servers[context.address];

  if (server == null) {
    return errorCode;
  }

  final data = dataAddress.asTypedList(dataLength);
  final address = addressFromSession(session);
  final port = portFromSession(session);

  server._receive(Datagram(data, address, port), context, session);

  return dataLength;
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
  if (type != dtls_credentials_type_t.DTLS_PSK_KEY) {
    return 0;
  }

  final server = DtlsServer._servers[context.address];

  if (server == null) {
    return errorCode;
  }

  final idString = utf8.decode(id.asTypedList(idLen));

  final psk = server._keyStore[idString];

  if (psk != null) {
    if (resultLength < psk.length) {
      return createFatalError(dtls_alert_t.DTLS_ALERT_INTERNAL_ERROR);
    }
    final pskBytes = utf8.encoder.convert(psk);
    result.asTypedList(resultLength).setAll(0, pskBytes);
    return pskBytes.lengthInBytes;
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
/// connection to a client is established, the server emits [DtlsServerEvent]s
/// you can [listen] for.
///
/// You can define multiple Pre-Shared Keys or an [EcdsaKeys] object that will be
/// used by server to encrypt its communication with DTLS Clients.
class DtlsServer extends Stream<DtlsServerEvent> {
  final TinyDTLS _tinyDtls;

  final RawDatagramSocket _socket;

  static final Map<int, DtlsServer> _servers = {};

  final Map<String, Pointer<session_t>> _sessions = {};

  bool _externalSocket = true;

  final _received = StreamController<DtlsServerEvent>();
  Stream<DtlsServerEvent> get _receivedStream => _received.stream;

  final Map<String, String> _keyStore = {};

  Pointer<dtls_ecdsa_key_t> _ecdsaKeyStruct = nullptr;

  late final Pointer<dtls_context_t> _context;

  /// Constructor
  DtlsServer(this._socket,
      {EcdsaKeys? ecdsaKeys, Map<String, String>? keyStore, TinyDTLS? tinyDTLS})
      : _tinyDtls = initializeTinyDtls(tinyDTLS) {
    _context = _tinyDtls.dtls_new_context(nullptr);
    _keyStore.addAll(keyStore ?? {});
    if (_keyStore.isEmpty && ecdsaKeys == null) {
      throw ArgumentError("No DTLS client credentials have been provided.");
    }

    if (ecdsaKeys != null) {
      _ecdsaKeyStruct = ecdsaKeysToPointer(ecdsaKeys);
    }

    _startListening();
  }

  /// Adds a new [preSharedKey] to this [DtlsServer] and associates it with an
  /// [identity].
  void addPskCredential(String identity, String preSharedKey) {
    _keyStore[identity] = preSharedKey;
  }

  /// Removes a Pre-Shared Key for a given [identity].
  ///
  /// Returns the key if the removal was successful. Otherwise, `null` is
  /// returned.
  ///
  /// Throws a [StateError] if no credentials (no Pre-Shared Key and no
  /// ECDSA Key) are left for the server to use.
  String? removePskCredential(String identity) {
    final removedValue = _keyStore.remove(identity);
    if (_keyStore.isEmpty && _ecdsaKeyStruct == nullptr) {
      throw StateError("DtlsServer must have at least one PSK or ECDSA Key!");
    }
    return removedValue;
  }

  /// Binds a [DtlsServer] to the given [host] and [port].
  ///
  /// The server will either use the pairs of Identities and Pre-Shared Keys
  /// provided in the [keyStore] Map or a set of [EcdsaKeys] to establish
  /// connections with peers. If no credentials are provided, a [StateError]
  /// will be thrown.
  ///
  /// Uses a [RawDatagramSocket] internally and passes the [host], [port],
  /// and [ttl] arguments to it.
  static Future<DtlsServer> bind(dynamic host, int port,
      {int ttl = 1,
      TinyDTLS? tinyDtls,
      Map<String, String>? keyStore,
      EcdsaKeys? ecdsaKeys}) async {
    final socket = await RawDatagramSocket.bind(host, port, ttl: ttl);
    return DtlsServer(socket,
        tinyDTLS: tinyDtls, keyStore: keyStore, ecdsaKeys: ecdsaKeys)
      .._externalSocket = false;
  }

  void _receive(Datagram data, Pointer<dtls_context_t> context,
      Pointer<session_t> session) {
    _received.sink.add(DtlsServerEvent(data, this, context, session));
  }

  void _startListening() {
    _servers[_context.address] = this;

    final Pointer<NativeFunction<NativeReadHandler>> readHandler =
        Pointer.fromFunction(_handleRead, errorCode);
    final Pointer<NativeFunction<NativeWriteHandler>> writeHandler =
        Pointer.fromFunction(_handleWrite, errorCode);

    final Pointer<NativeFunction<NativePskHandler>> pskHandler;

    if (_keyStore.isNotEmpty) {
      pskHandler = Pointer.fromFunction(_retrievePskInfo, errorCode);
    } else {
      pskHandler = nullptr;
    }

    Pointer<NativeFunction<NativeEcdsaHandler>> ecdsaHandler;

    Pointer<NativeFunction<NativeEcdsaVerifyHandler>> verifyEcdsaHandler;

    if (_ecdsaKeyStruct == nullptr) {
      ecdsaHandler = Pointer.fromFunction(_retrieveEcdsaInfo, errorCode);
      verifyEcdsaHandler = Pointer.fromFunction(_verifyEcdsaKey, errorCode);
    } else {
      ecdsaHandler = nullptr;
      verifyEcdsaHandler = nullptr;
    }

    final handlers = malloc<dtls_handler_t>();
    handlers.ref.read = readHandler;
    handlers.ref.write = writeHandler;
    handlers.ref.event = nullptr;
    handlers.ref.get_psk_info = pskHandler;
    handlers.ref.get_ecdsa_key = ecdsaHandler;
    handlers.ref.verify_ecdsa_key = verifyEcdsaHandler;
    _context.ref.h = handlers;

    _socket.listen((event) async {
      if (event == RawSocketEvent.read) {
        final data = _socket.receive();
        if (data != null) {
          buffer.asTypedList(data.data.length).setAll(0, data.data);
          final Pointer<session_t> session;
          final address = data.address.address;
          final storedSession = _sessions[address];
          if (storedSession != null) {
            session = storedSession;
          } else {
            session =
                createSession(_tinyDtls, InternetAddress(address), data.port);
            _sessions[address] = session;
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
    _sessions
      ..forEach((key, value) {
        _tinyDtls
          ..dtls_close(_context, value)
          ..dtls_free_session(value);
      })
      ..clear();

    _tinyDtls.dtls_free_context(_context);

    _servers.remove(_context.address);
    freeEdcsaStruct(_ecdsaKeyStruct);
    _received.close();

    if (!_externalSocket || closeExternalSocket) {
      _socket.close();
    }
  }

  @override
  StreamSubscription<DtlsServerEvent> listen(
      void Function(DtlsServerEvent event)? onData,
      {Function? onError,
      void Function()? onDone,
      bool? cancelOnError}) {
    return _receivedStream.listen(onData,
        onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  }

  int _sendInternal(Uint8List data, InternetAddress address, int port) {
    return _socket.send(data, address, port);
  }
}

/// This Event is emitted if a [DtlsServer] receives application data.
class DtlsServerEvent {
  /// The received [Datagram] that triggered this [DtlsServerEvent].
  final Datagram data;

  final DtlsServer _server;

  final Pointer<dtls_context_t> _context;

  final Pointer<session_t> _session;

  /// Constructor
  DtlsServerEvent(this.data, this._server, this._context, this._session);

  /// Sends [data] to the peer of the [DtlsServer] where this [DtlsServerEvent]
  /// originated from.
  int respond(List<int> data) {
    return _server._send(data, _context, _session);
  }
}
