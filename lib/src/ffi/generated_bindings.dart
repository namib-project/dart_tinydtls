// ignore_for_file: camel_case_types, non_constant_identifier_names
// ignore_for_file: constant_identifier_names, public_member_api_docs
// ignore_for_file: unused_field, lines_longer_than_80_chars

// AUTO GENERATED FILE, DO NOT EDIT.
//
// Generated by `package:ffigen`.
import 'dart:ffi' as ffi;

/// ffi binding to the tinydtls library.
class TinyDTLS {
  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  TinyDTLS(ffi.DynamicLibrary dynamicLibrary) : _lookup = dynamicLibrary.lookup;

  /// The symbols are looked up with [lookup].
  TinyDTLS.fromLookup(
      ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
          lookup)
      : _lookup = lookup;

  /// Resets the given session_t object @p sess to its default
  /// values.  In particular, the member rlen must be initialized to the
  /// available size for storing addresses.
  ///
  /// @param sess The session_t object to initialize.
  void dtls_session_init(
    ffi.Pointer<session_t> sess,
  ) {
    return _dtls_session_init(
      sess,
    );
  }

  late final _dtls_session_initPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<session_t>)>>(
          'dtls_session_init');
  late final _dtls_session_init =
      _dtls_session_initPtr.asFunction<void Function(ffi.Pointer<session_t>)>();

  /// Creates a new ::session_t for the given address.
  ///
  /// @param addr Address which should be stored in the ::session_t.
  /// @param addrlen Length of the @p addr.
  /// @return The new session or @c NULL on error.
  ffi.Pointer<session_t> dtls_new_session(
    ffi.Pointer<sockaddr> addr,
    int addrlen,
  ) {
    return _dtls_new_session(
      addr,
      addrlen,
    );
  }

  late final _dtls_new_sessionPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<session_t> Function(
              ffi.Pointer<sockaddr>, socklen_t)>>('dtls_new_session');
  late final _dtls_new_session = _dtls_new_sessionPtr.asFunction<
      ffi.Pointer<session_t> Function(ffi.Pointer<sockaddr>, int)>();

  /// Frees memory allocated for a session using ::dtls_new_session.
  ///
  /// @param sess Pointer to a session for which allocated memory should be
  /// freed.
  void dtls_free_session(
    ffi.Pointer<session_t> sess,
  ) {
    return _dtls_free_session(
      sess,
    );
  }

  late final _dtls_free_sessionPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<session_t>)>>(
          'dtls_free_session');
  late final _dtls_free_session =
      _dtls_free_sessionPtr.asFunction<void Function(ffi.Pointer<session_t>)>();

  /// Extracts the address of the given ::session_t.
  ///
  /// @param sess Session to extract address for.
  /// @param addrlen Pointer to memory location where the address
  /// length should be stored.
  /// @return The address or @c NULL if @p sess was @c NULL.
  ffi.Pointer<sockaddr> dtls_session_addr(
    ffi.Pointer<session_t> sess,
    ffi.Pointer<socklen_t> addrlen,
  ) {
    return _dtls_session_addr(
      sess,
      addrlen,
    );
  }

  late final _dtls_session_addrPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<sockaddr> Function(ffi.Pointer<session_t>,
              ffi.Pointer<socklen_t>)>>('dtls_session_addr');
  late final _dtls_session_addr = _dtls_session_addrPtr.asFunction<
      ffi.Pointer<sockaddr> Function(
          ffi.Pointer<session_t>, ffi.Pointer<socklen_t>)>();

  /// Compares the given session objects. This function returns @c 0
  /// when @p a and @p b differ, @c 1 otherwise.
  int dtls_session_equals(
    ffi.Pointer<session_t> a,
    ffi.Pointer<session_t> b,
  ) {
    return _dtls_session_equals(
      a,
      b,
    );
  }

  late final _dtls_session_equalsPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int32 Function(ffi.Pointer<session_t>,
              ffi.Pointer<session_t>)>>('dtls_session_equals');
  late final _dtls_session_equals = _dtls_session_equalsPtr.asFunction<
      int Function(ffi.Pointer<session_t>, ffi.Pointer<session_t>)>();

  /// This function initializes the tinyDTLS memory management and must
  /// be called first.
  void dtls_init() {
    return _dtls_init();
  }

  late final _dtls_initPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function()>>('dtls_init');
  late final _dtls_init = _dtls_initPtr.asFunction<void Function()>();

  /// Creates a new context object. The storage allocated for the new
  /// object must be released with dtls_free_context().
  ffi.Pointer<dtls_context_t> dtls_new_context(
    ffi.Pointer<ffi.Void> app_data,
  ) {
    return _dtls_new_context(
      app_data,
    );
  }

  late final _dtls_new_contextPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<dtls_context_t> Function(
              ffi.Pointer<ffi.Void>)>>('dtls_new_context');
  late final _dtls_new_context = _dtls_new_contextPtr.asFunction<
      ffi.Pointer<dtls_context_t> Function(ffi.Pointer<ffi.Void>)>();

  /// Releases any storage that has been allocated for \p ctx.
  void dtls_free_context(
    ffi.Pointer<dtls_context_t> ctx,
  ) {
    return _dtls_free_context(
      ctx,
    );
  }

  late final _dtls_free_contextPtr = _lookup<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<dtls_context_t>)>>(
      'dtls_free_context');
  late final _dtls_free_context = _dtls_free_contextPtr
      .asFunction<void Function(ffi.Pointer<dtls_context_t>)>();

  /// Establishes a DTLS channel with the specified remote peer @p dst.
  /// This function returns @c 0 if that channel already exists, a value
  /// greater than zero when a new ClientHello message was sent, and
  /// a value less than zero on error.
  ///
  /// @param ctx    The DTLS context to use.
  /// @param dst    The remote party to connect to.
  /// @return A value less than zero on error, greater or equal otherwise.
  int dtls_connect(
    ffi.Pointer<dtls_context_t> ctx,
    ffi.Pointer<session_t> dst,
  ) {
    return _dtls_connect(
      ctx,
      dst,
    );
  }

  late final _dtls_connectPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int32 Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>)>>('dtls_connect');
  late final _dtls_connect = _dtls_connectPtr.asFunction<
      int Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<session_t>)>();

  /// Establishes a DTLS channel with the specified remote peer.
  /// This function returns @c 0 if that channel already exists and a renegotiate
  /// was initiated, a value greater than zero when a new ClientHello message was
  /// sent, and a value less than zero on error.
  ///
  /// @param ctx    The DTLS context to use.
  /// @param peer   The peer object that describes the session.
  /// @return A value less than zero on error, greater or equal otherwise.
  int dtls_connect_peer(
    ffi.Pointer<dtls_context_t> ctx,
    ffi.Pointer<dtls_peer_t> peer,
  ) {
    return _dtls_connect_peer(
      ctx,
      peer,
    );
  }

  late final _dtls_connect_peerPtr = _lookup<
      ffi.NativeFunction<
          ffi.Int32 Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<dtls_peer_t>)>>('dtls_connect_peer');
  late final _dtls_connect_peer = _dtls_connect_peerPtr.asFunction<
      int Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<dtls_peer_t>)>();

  /// Closes the DTLS connection associated with @p remote. This function
  /// returns zero on success, and a value less than zero on error.
  int dtls_close(
    ffi.Pointer<dtls_context_t> ctx,
    ffi.Pointer<session_t> remote,
  ) {
    return _dtls_close(
      ctx,
      remote,
    );
  }

  late final _dtls_closePtr = _lookup<
      ffi.NativeFunction<
          ffi.Int32 Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>)>>('dtls_close');
  late final _dtls_close = _dtls_closePtr.asFunction<
      int Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<session_t>)>();

  /// Renegotiates a DTLS channel based on the specified session.
  /// This function returns a value greater than zero when a new ClientHello
  /// message was sent, and a value less than zero on error.
  ///
  /// @param ctx    The DTLS context to use.
  /// @param dst    The session object that describes the existing session.
  /// @return A value less than zero on error, greater otherwise.
  int dtls_renegotiate(
    ffi.Pointer<dtls_context_t> ctx,
    ffi.Pointer<session_t> dst,
  ) {
    return _dtls_renegotiate(
      ctx,
      dst,
    );
  }

  late final _dtls_renegotiatePtr = _lookup<
      ffi.NativeFunction<
          ffi.Int32 Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>)>>('dtls_renegotiate');
  late final _dtls_renegotiate = _dtls_renegotiatePtr.asFunction<
      int Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<session_t>)>();

  /// Writes the application data given in @p buf to the peer specified
  /// by @p session.
  ///
  /// @param ctx      The DTLS context to use.
  /// @param session  The remote transport address and local interface.
  /// @param buf      The data to write.
  /// @param len      The actual length of @p data.
  ///
  /// @return The number of bytes written, @c -1 on error or @c 0
  /// if the peer already exists but is not connected yet.
  int dtls_write(
    ffi.Pointer<dtls_context_t> ctx,
    ffi.Pointer<session_t> session,
    ffi.Pointer<uint8> buf,
    int len,
  ) {
    return _dtls_write(
      ctx,
      session,
      buf,
      len,
    );
  }

  late final _dtls_writePtr = _lookup<
      ffi.NativeFunction<
          ffi.Int32 Function(
              ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>,
              ffi.Pointer<uint8>,
              size_t)>>('dtls_write');
  late final _dtls_write = _dtls_writePtr.asFunction<
      int Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<session_t>,
          ffi.Pointer<uint8>, int)>();

  /// Checks sendqueue of given DTLS context object for any outstanding
  /// packets to be transmitted.
  ///
  /// @param context The DTLS context object to use.
  /// @param next    If not NULL, @p next is filled with the timestamp
  /// of the next scheduled retransmission, or @c 0 when no packets are
  /// waiting.
  void dtls_check_retransmit(
    ffi.Pointer<dtls_context_t> context,
    ffi.Pointer<clock_time_t> next,
  ) {
    return _dtls_check_retransmit(
      context,
      next,
    );
  }

  late final _dtls_check_retransmitPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<clock_time_t>)>>('dtls_check_retransmit');
  late final _dtls_check_retransmit = _dtls_check_retransmitPtr.asFunction<
      void Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<clock_time_t>)>();

  /// Handles incoming data as DTLS message from given peer.
  ///
  /// @param ctx     The dtls context to use.
  /// @param session The current session
  /// @param msg     The received data
  /// @param msglen  The actual length of @p msg.
  /// @return A value less than zero on error, zero on success.
  int dtls_handle_message(
    ffi.Pointer<dtls_context_t> ctx,
    ffi.Pointer<session_t> session,
    ffi.Pointer<uint8> msg,
    int msglen,
  ) {
    return _dtls_handle_message(
      ctx,
      session,
      msg,
      msglen,
    );
  }

  late final _dtls_handle_messagePtr = _lookup<
      ffi.NativeFunction<
          ffi.Int32 Function(
              ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>,
              ffi.Pointer<uint8>,
              ffi.Int32)>>('dtls_handle_message');
  late final _dtls_handle_message = _dtls_handle_messagePtr.asFunction<
      int Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<session_t>,
          ffi.Pointer<uint8>, int)>();

  /// Check if @p session is associated with a peer object in @p context.
  /// This function returns a pointer to the peer if found, NULL otherwise.
  ///
  /// @param context  The DTLS context to search.
  /// @param session  The remote address and local interface
  /// @return A pointer to the peer associated with @p session or NULL if
  /// none exists.
  ffi.Pointer<dtls_peer_t> dtls_get_peer(
    ffi.Pointer<dtls_context_t> context,
    ffi.Pointer<session_t> session,
  ) {
    return _dtls_get_peer(
      context,
      session,
    );
  }

  late final _dtls_get_peerPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<dtls_peer_t> Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>)>>('dtls_get_peer');
  late final _dtls_get_peer = _dtls_get_peerPtr.asFunction<
      ffi.Pointer<dtls_peer_t> Function(
          ffi.Pointer<dtls_context_t>, ffi.Pointer<session_t>)>();

  /// Resets all connections with @p peer.
  ///
  /// @param context  The active DTLS context.
  /// @param peer     The peer to reset.
  void dtls_reset_peer(
    ffi.Pointer<dtls_context_t> context,
    ffi.Pointer<dtls_peer_t> peer,
  ) {
    return _dtls_reset_peer(
      context,
      peer,
    );
  }

  late final _dtls_reset_peerPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<dtls_peer_t>)>>('dtls_reset_peer');
  late final _dtls_reset_peer = _dtls_reset_peerPtr.asFunction<
      void Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<dtls_peer_t>)>();

  void dtls_set_handler(
    ffi.Pointer<dtls_context_t> ctx,
    ffi.Pointer<dtls_handler_t> h,
  ) {
    return _dtls_set_handler(
      ctx,
      h,
    );
  }

  late final _dtls_set_handlerPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<dtls_handler_t>)>>('dtls_set_handler_helper');
  late final _dtls_set_handler = _dtls_set_handlerPtr.asFunction<
      void Function(
          ffi.Pointer<dtls_context_t>, ffi.Pointer<dtls_handler_t>)>();
}

class session_t extends ffi.Struct {
  /// < size of addr
  @socklen_t()
  external int size;

  external UnnamedUnion1 addr;

  @ffi.Int32()
  external int ifindex;
}

typedef socklen_t = __socklen_t;
typedef __socklen_t = ffi.Uint32;

class UnnamedUnion1 extends ffi.Union {
  external sockaddr sa;

  external sockaddr_storage st;

  external sockaddr_in sin;

  external sockaddr_in6 sin6;
}

class sockaddr extends ffi.Struct {
  @sa_family_t()
  external int sa_family;

  @ffi.Array.multi([14])
  external ffi.Array<ffi.Int8> sa_data;
}

typedef sa_family_t = ffi.Uint16;

class sockaddr_storage extends ffi.Struct {
  @sa_family_t()
  external int ss_family;

  @ffi.Array.multi([118])
  external ffi.Array<ffi.Int8> __ss_padding;

  @ffi.Uint64()
  external int __ss_align;
}

class sockaddr_in extends ffi.Struct {
  @sa_family_t()
  external int sin_family;

  @in_port_t()
  external int sin_port;

  external in_addr sin_addr;

  @ffi.Array.multi([8])
  external ffi.Array<ffi.Uint8> sin_zero;
}

typedef in_port_t = ffi.Uint16;

class in_addr extends ffi.Struct {
  @in_addr_t()
  external int s_addr;
}

typedef in_addr_t = ffi.Uint32;

class sockaddr_in6 extends ffi.Struct {
  @sa_family_t()
  external int sin6_family;

  @in_port_t()
  external int sin6_port;

  @ffi.Uint32()
  external int sin6_flowinfo;

  external in6_addr sin6_addr;

  @ffi.Uint32()
  external int sin6_scope_id;
}

class in6_addr extends ffi.Struct {
  external UnnamedUnion2 __in6_u;
}

class UnnamedUnion2 extends ffi.Union {
  @ffi.Array.multi([16])
  external ffi.Array<ffi.Uint8> __u6_addr8;

  @ffi.Array.multi([8])
  external ffi.Array<ffi.Uint16> __u6_addr16;

  @ffi.Array.multi([4])
  external ffi.Array<ffi.Uint32> __u6_addr32;
}

abstract class dtls_credentials_type_t {
  static const int DTLS_PSK_HINT = 0;
  static const int DTLS_PSK_IDENTITY = 1;
  static const int DTLS_PSK_KEY = 2;
}

class dtls_ecdsa_key_t extends ffi.Struct {
  @ffi.Int32()
  external int curve;

  external ffi.Pointer<ffi.Uint8> priv_key;

  /// < private key as bytes >
  external ffi.Pointer<ffi.Uint8> pub_key_x;

  /// < x part of the public key for the given private key >
  external ffi.Pointer<ffi.Uint8> pub_key_y;
}

abstract class dtls_ecdh_curve {
  static const int DTLS_ECDH_CURVE_SECP256R1 = 0;
}

/// Holds global information of the DTLS engine.
class dtls_context_t extends ffi.Struct {
  @ffi.Array.multi([12])
  external ffi.Array<ffi.Uint8> cookie_secret;

  /// < the time the secret has been generated
  @clock_time_t()
  external int cookie_secret_age;

  /// < peer hash map
  external ffi.Pointer<dtls_peer_t> peers;

  /// < the packets to send
  external ffi.Pointer<netq_t> sendqueue;

  /// < application-specific data
  external ffi.Pointer<ffi.Void> app;

  /// < callback handlers
  external ffi.Pointer<dtls_handler_t> h;
}

typedef clock_time_t = ffi.Uint32;

/// Holds security parameters, local state and the transport address
/// for each peer.
class dtls_peer_t extends ffi.Struct {
  external UT_hash_handle hh;

  /// < peer address and local interface
  external session_t session;

  /// < denotes if this host is DTLS_CLIENT or DTLS_SERVER
  @ffi.Int32()
  external int role;

  /// < DTLS engine state
  @ffi.Int32()
  external int state;

  /// < optional next handshake message, DTLS_HT_NO_OPTIONAL_MESSAGE, if no optional message is expected.
  @ffi.Int16()
  external int optional_handshake_message;

  @ffi.Array.multi([2])
  external ffi.Array<ffi.Pointer<dtls_security_parameters_t>> security_params;

  external ffi.Pointer<dtls_handshake_parameters_t> handshake_params;
}

class UT_hash_handle extends ffi.Struct {
  external ffi.Pointer<UT_hash_table> tbl;

  external ffi.Pointer<ffi.Void> prev;

  external ffi.Pointer<ffi.Void> next;

  external ffi.Pointer<UT_hash_handle> hh_prev;

  external ffi.Pointer<UT_hash_handle> hh_next;

  external ffi.Pointer<ffi.Void> key;

  @ffi.Uint32()
  external int keylen;

  @ffi.Uint32()
  external int hashv;
}

class UT_hash_table extends ffi.Struct {
  external ffi.Pointer<UT_hash_bucket> buckets;

  @ffi.Uint32()
  external int num_buckets;

  @ffi.Uint32()
  external int log2_num_buckets;

  @ffi.Uint32()
  external int num_items;

  external ffi.Pointer<UT_hash_handle> tail;

  @ptrdiff_t()
  external int hho;

  @ffi.Uint32()
  external int ideal_chain_maxlen;

  @ffi.Uint32()
  external int nonideal_items;

  @ffi.Uint32()
  external int ineff_expands;

  @ffi.Uint32()
  external int noexpand;

  @ffi.Uint32()
  external int signature;
}

class UT_hash_bucket extends ffi.Struct {
  external ffi.Pointer<UT_hash_handle> hh_head;

  @ffi.Uint32()
  external int count;

  @ffi.Uint32()
  external int expand_mult;
}

typedef ptrdiff_t = ffi.Int64;

abstract class dtls_peer_type {
  static const int DTLS_CLIENT = 0;
  static const int DTLS_SERVER = 1;
}

abstract class dtls_state_t {
  static const int DTLS_STATE_INIT = 0;
  static const int DTLS_STATE_WAIT_CLIENTHELLO = 1;
  static const int DTLS_STATE_WAIT_CLIENTCERTIFICATE = 2;
  static const int DTLS_STATE_WAIT_CLIENTKEYEXCHANGE = 3;
  static const int DTLS_STATE_WAIT_CERTIFICATEVERIFY = 4;
  static const int DTLS_STATE_WAIT_CHANGECIPHERSPEC = 5;
  static const int DTLS_STATE_WAIT_FINISHED = 6;
  static const int DTLS_STATE_FINISHED = 7;
  static const int DTLS_STATE_CLIENTHELLO = 8;
  static const int DTLS_STATE_WAIT_SERVERCERTIFICATE = 9;
  static const int DTLS_STATE_WAIT_SERVERKEYEXCHANGE = 10;
  static const int DTLS_STATE_WAIT_SERVERHELLODONE = 11;
  static const int DTLS_STATE_CONNECTED = 12;
  static const int DTLS_STATE_CLOSING = 13;
  static const int DTLS_STATE_CLOSED = 14;
}

class dtls_security_parameters_t extends ffi.Struct {
  /// < compression method
  @ffi.Int32()
  external int compression;

  /// < cipher type
  @ffi.Int32()
  external int cipher;

  /// < counter for cipher state changes
  @ffi.Uint16()
  external int epoch;

  /// < sequence number of last record sent
  @ffi.Uint64()
  external int rseq;

  @ffi.Array.multi([40])
  external ffi.Array<uint8> key_block;

  /// <sequence number of last record received
  external seqnum_t cseq;
}

/// Known compression suites.
abstract class dtls_compression_t {
  static const int TLS_COMPRESSION_NULL = 0;
}

/// Known cipher suites.
abstract class dtls_cipher_t {
  /// < NULL cipher
  static const int TLS_NULL_WITH_NULL_NULL = 0;

  /// < see RFC 6655
  static const int TLS_PSK_WITH_AES_128_CCM_8 = 49320;

  /// < see RFC 7251
  static const int TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 49326;
}

typedef uint8 = ffi.Uint8;

class seqnum_t extends ffi.Struct {
  @ffi.Uint64()
  external int cseq;

  @ffi.Uint64()
  external int bitfield;
}

class dtls_handshake_parameters_t extends ffi.Opaque {}

class netq_t extends ffi.Opaque {}

/// This structure contains callback functions used by tinydtls to
/// communicate with the application. At least the write function must
/// be provided. It is called by the DTLS state machine to send packets
/// over the network. The read function is invoked to deliver decrypted
/// and verfified application data. The third callback is an event
/// handler function that is called when alert messages are encountered
/// or events generated by the library have occured.
class dtls_handler_t extends ffi.Struct {
  /// Called from dtls_handle_message() to send DTLS packets over the
  /// network. The callback function must use the network interface
  /// denoted by session->ifindex to send the data.
  ///
  /// @param ctx  The current DTLS context.
  /// @param session The session object, including the address of the
  /// remote peer where the data shall be sent.
  /// @param buf  The data to send.
  /// @param len  The actual length of @p buf.
  /// @return The callback function must return the number of bytes
  /// that were sent, or a value less than zero to indicate an
  /// error.
  external ffi.Pointer<
      ffi.NativeFunction<
          ffi.Int32 Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>, ffi.Pointer<uint8>, size_t)>> write;

  /// Called from dtls_handle_message() deliver application data that was
  /// received on the given session. The data is delivered only after
  /// decryption and verification have succeeded.
  ///
  /// @param ctx  The current DTLS context.
  /// @param session The session object, including the address of the
  /// data's origin.
  /// @param buf  The received data packet.
  /// @param len  The actual length of @p buf.
  /// @return ignored
  external ffi.Pointer<
      ffi.NativeFunction<
          ffi.Int32 Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>, ffi.Pointer<uint8>, size_t)>> read;

  /// The event handler is called when a message from the alert
  /// protocol is received or the state of the DTLS session changes.
  ///
  /// @param ctx     The current dtls context.
  /// @param session The session object that was affected.
  /// @param level   The alert level or @c 0 when an event ocurred that
  /// is not an alert.
  /// @param code    Values less than @c 256 indicate alerts, while
  /// @c 256 or greater indicate internal DTLS session changes.
  /// @return ignored
  external ffi.Pointer<
      ffi.NativeFunction<
          ffi.Int32 Function(ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>, ffi.Int32, ffi.Uint16)>> event;

  /// Called during handshake to get information related to the
  /// psk key exchange. The type of information requested is
  /// indicated by @p type which will be one of DTLS_PSK_HINT,
  /// DTLS_PSK_IDENTITY, or DTLS_PSK_KEY. The called function
  /// must store the requested item in the buffer @p result of
  /// size @p result_length. On success, the function must return
  /// the actual number of bytes written to @p result, of a
  /// value less than zero on error. The parameter @p desc may
  /// contain additional request information (e.g. the psk_identity
  /// for which a key is requested when @p type == @c DTLS_PSK_KEY.
  ///
  /// @param ctx     The current dtls context.
  /// @param session The session where the key will be used.
  /// @param type    The type of the requested information.
  /// @param desc    Additional request information
  /// @param desc_len The actual length of desc.
  /// @param result  Must be filled with the requested information.
  /// @param result_length  Maximum size of @p result.
  /// @return The number of bytes written to @p result or a value
  /// less than zero on error.
  external ffi.Pointer<
      ffi.NativeFunction<
          ffi.Int32 Function(
              ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>,
              ffi.Int32,
              ffi.Pointer<ffi.Uint8>,
              size_t,
              ffi.Pointer<ffi.Uint8>,
              size_t)>> get_psk_info;

  /// Called during handshake to get the server's or client's ecdsa
  /// key used to authenticate this server or client in this
  /// session. If found, the key must be stored in @p result and
  /// the return value must be @c 0. If not found, @p result is
  /// undefined and the return value must be less than zero.
  ///
  /// If ECDSA should not be supported, set this pointer to NULL.
  ///
  /// Implement this if you want to provide your own certificate to
  /// the other peer. This is mandatory for a server providing ECDSA
  /// support and optional for a client. A client doing DTLS client
  /// authentication has to implementing this callback.
  ///
  /// @param ctx     The current dtls context.
  /// @param session The session where the key will be used.
  /// @param result  Must be set to the key object to used for the given
  /// session.
  /// @return @c 0 if result is set, or less than zero on error.
  external ffi.Pointer<
      ffi.NativeFunction<
          ffi.Int32 Function(
              ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>,
              ffi.Pointer<ffi.Pointer<dtls_ecdsa_key_t>>)>> get_ecdsa_key;

  /// Called during handshake to check the peer's pubic key in this
  /// session. If the public key matches the session and should be
  /// considerated valid the return value must be @c 0. If not valid,
  /// the return value must be less than zero.
  ///
  /// If ECDSA should not be supported, set this pointer to NULL.
  ///
  /// Implement this if you want to verify the other peers public key.
  /// This is mandatory for a DTLS client doing based ECDSA
  /// authentication. A server implementing this will request the
  /// client to do DTLS client authentication.
  ///
  /// @param ctx          The current dtls context.
  /// @param session      The session where the key will be used.
  /// @param other_pub_x  x component of the public key.
  /// @param other_pub_y  y component of the public key.
  /// @return @c 0 if public key matches, or less than zero on error.
  /// error codes:
  /// return dtls_alert_fatal_create(DTLS_ALERT_BAD_CERTIFICATE);
  /// return dtls_alert_fatal_create(DTLS_ALERT_UNSUPPORTED_CERTIFICATE);
  /// return dtls_alert_fatal_create(DTLS_ALERT_CERTIFICATE_REVOKED);
  /// return dtls_alert_fatal_create(DTLS_ALERT_CERTIFICATE_EXPIRED);
  /// return dtls_alert_fatal_create(DTLS_ALERT_CERTIFICATE_UNKNOWN);
  /// return dtls_alert_fatal_create(DTLS_ALERT_UNKNOWN_CA);
  external ffi.Pointer<
      ffi.NativeFunction<
          ffi.Int32 Function(
              ffi.Pointer<dtls_context_t>,
              ffi.Pointer<session_t>,
              ffi.Pointer<ffi.Uint8>,
              ffi.Pointer<ffi.Uint8>,
              size_t)>> verify_ecdsa_key;
}

typedef size_t = ffi.Uint64;

abstract class dtls_alert_level_t {
  static const int DTLS_ALERT_LEVEL_WARNING = 1;
  static const int DTLS_ALERT_LEVEL_FATAL = 2;
}

/// Generic header structure of the DTLS record layer.
@ffi.Packed(1)
class dtls_record_header_t extends ffi.Struct {
  /// < content type of the included message
  @uint8()
  external int content_type;

  @ffi.Array.multi([2])
  external ffi.Array<ffi.Uint8> version;

  @ffi.Array.multi([2])
  external ffi.Array<ffi.Uint8> epoch;

  @ffi.Array.multi([6])
  external ffi.Array<ffi.Uint8> sequence_number;

  @ffi.Array.multi([2])
  external ffi.Array<ffi.Uint8> length;
}

/// Header structure for the DTLS handshake protocol.
@ffi.Packed(1)
class dtls_handshake_header_t extends ffi.Struct {
  /// < Type of handshake message  (one of DTLS_HT_)
  @uint8()
  external int msg_type;

  @ffi.Array.multi([3])
  external ffi.Array<ffi.Uint8> length;

  @ffi.Array.multi([2])
  external ffi.Array<ffi.Uint8> message_seq;

  @ffi.Array.multi([3])
  external ffi.Array<ffi.Uint8> fragment_offset;

  @ffi.Array.multi([3])
  external ffi.Array<ffi.Uint8> fragment_length;
}

/// Structure of the Client Hello message.
@ffi.Packed(1)
class dtls_client_hello_t extends ffi.Struct {
  @ffi.Array.multi([2])
  external ffi.Array<ffi.Uint8> version;

  @ffi.Array.multi([4])
  external ffi.Array<ffi.Uint8> gmt_random;

  @ffi.Array.multi([28])
  external ffi.Array<ffi.Uint8> random;
}

/// Structure of the Hello Verify Request.
@ffi.Packed(1)
class dtls_hello_verify_t extends ffi.Struct {
  @ffi.Array.multi([2])
  external ffi.Array<ffi.Uint8> version;

  /// < Length of the included cookie
  @uint8()
  external int cookie_length;

  @ffi.Array.multi([32])
  external ffi.Array<uint8> cookie;
}

const int WITH_POSIX = 1;

const int DTLS_ECC = 1;

const int DTLS_PSK = 1;

const int HAVE_ARPA_INET_H = 1;

const int HAVE_ASSERT_H = 1;

const int HAVE_FCNTL_H = 1;

const int HAVE_INTTYPES_H = 1;

const int HAVE_MEMSET = 1;

const int HAVE_NETDB_H = 1;

const int HAVE_NETINET_IN_H = 1;

const int HAVE_SELECT = 1;

const int HAVE_SOCKET = 1;

const int HAVE_STDDEF_H = 1;

const int HAVE_STDINT_H = 1;

const int HAVE_STDIO_H = 1;

const int HAVE_STDLIB_H = 1;

const int HAVE_STRDUP = 1;

const int HAVE_STRERROR = 1;

const int HAVE_STRINGS_H = 1;

const int HAVE_STRING_H = 1;

const int HAVE_STRNLEN = 1;

const int HAVE_SYS_PARAM_H = 1;

const int HAVE_SYS_SOCKET_H = 1;

const int HAVE_SYS_STAT_H = 1;

const int HAVE_SYS_TIME_H = 1;

const int HAVE_SYS_TYPES_H = 1;

const int HAVE_TIME_H = 1;

const int HAVE_UNISTD_H = 1;

const int HAVE_VPRINTF = 1;

const String PACKAGE_BUGREPORT = '';

const String PACKAGE_NAME = 'tinydtls';

const String PACKAGE_STRING = 'tinydtls 0.8.6';

const String PACKAGE_TARNAME = 'tinydtls';

const String PACKAGE_URL = '';

const String PACKAGE_VERSION = '0.8.6';

const int STDC_HEADERS = 1;

const int DTLS_VERSION = 65277;

const int DTLS_COOKIE_SECRET_LENGTH = 12;

const int DTLS_COOKIE_LENGTH = 16;

const int DTLS_CT_CHANGE_CIPHER_SPEC = 20;

const int DTLS_CT_ALERT = 21;

const int DTLS_CT_HANDSHAKE = 22;

const int DTLS_CT_APPLICATION_DATA = 23;

const int DTLS_HT_HELLO_REQUEST = 0;

const int DTLS_HT_CLIENT_HELLO = 1;

const int DTLS_HT_SERVER_HELLO = 2;

const int DTLS_HT_HELLO_VERIFY_REQUEST = 3;

const int DTLS_HT_CERTIFICATE = 11;

const int DTLS_HT_SERVER_KEY_EXCHANGE = 12;

const int DTLS_HT_CERTIFICATE_REQUEST = 13;

const int DTLS_HT_SERVER_HELLO_DONE = 14;

const int DTLS_HT_CERTIFICATE_VERIFY = 15;

const int DTLS_HT_CLIENT_KEY_EXCHANGE = 16;

const int DTLS_HT_FINISHED = 20;

const int DTLS_HT_NO_OPTIONAL_MESSAGE = -1;
