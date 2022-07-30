// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:collection';

import 'ffi/generated_bindings.dart';

/// The possible levels of events and alerts emitted by [TinyDTLS].
///
/// Can describe be a DTLS [warning] or [fatal] error, or a tinydtls-specific
/// [event].
enum AlertLevel {
  /// Corresponds to a Event defined by [TinyDTLS].
  event(0, "Event"),

  /// Describes a warning. Only requires a connection to be closed in the case
  /// of a [AlertDescription.closeNotify] alert.
  warning(dtls_alert_level_t.DTLS_ALERT_LEVEL_WARNING, "Warning"),

  /// Describes a fatal error, which always causes a connection to be closed.
  fatal(dtls_alert_level_t.DTLS_ALERT_LEVEL_FATAL, "Fatal Error");

  /// Constuctor.
  const AlertLevel(this._code, this._stringValue);

  final int _code;

  final String _stringValue;

  static final _registry =
      HashMap.fromEntries(values.map((value) => MapEntry(value._code, value)));

  /// Creates an [AlertDescription] from a numeric [code].
  static AlertLevel? fromCode(int code) => _registry[code];

  @override
  String toString() => "Alert Level '$_stringValue'";
}

/// The description component of a [DtlsEvent].
///
/// Can either be the description of a warning or a fatal error.
enum AlertDescription {
  /// Occurs when the Client is trying to connect to the peer.
  connect(
    DTLS_EVENT_CONNECT,
    "connect (tinydtls event)",
  ),

  /// Occurs when the connection has been successfully established.
  connected(
    DTLS_EVENT_CONNECTED,
    "connected (tinydtls event)",
  ),

  /// Occurs if the Client is trying to re-connect to an endpoint.
  renegotiate(
    DTLS_EVENT_RENEGOTIATE,
    "renegotiate (tinydtls event)",
  ),

  /// Indicates that the peer has closed their connection.
  ///
  /// This type of alert always causes a DTLS connection to be closed.
  closeNotify(
    dtls_alert_t.DTLS_ALERT_CLOSE_NOTIFY,
    "close_notify",
  ),

  /// An inappropriate message was received.
  ///
  /// This alert is always fatal and should never be observed in communication
  /// between proper implementations.
  unexceptedMessage(
    dtls_alert_t.DTLS_ALERT_UNEXPECTED_MESSAGE,
    "unexpected_message",
  ),

  /// This alert is returned if a record is received with an incorrect MAC.
  ///
  /// This message is always fatal and should
  /// never be observed in communication between proper implementations
  /// (except when messages were corrupted in the network).
  badRecordMac(
    dtls_alert_t.DTLS_ALERT_BAD_RECORD_MAC,
    "bad_record_mac",
  ),

  /// A TLSCiphertext record was received that had a length more than 2^14+2048
  /// bytes, or a record decrypted to a TLSCompressed record with more than
  /// 2^14+1024 bytes.
  ///
  /// This message is always fatal and should never be observed in communication
  /// between proper implementations (except when messages were corrupted in the
  /// network).
  recordOverflow(
    dtls_alert_t.DTLS_ALERT_RECORD_OVERFLOW,
    "record_overflow",
  ),

  /// The decompression function received improper input (e.g., data that would
  /// expand to excessive length).
  ///
  /// This message is always fatal and should never be observed in communication
  /// between proper implementations.
  decompressionFailure(
    dtls_alert_t.DTLS_ALERT_DECOMPRESSION_FAILURE,
    "decompression_failure",
  ),

  /// Indicates that the sender was unable to negotiate an acceptable set of
  /// security parameters given the options available.
  ///
  /// This is a fatal error.
  handshakeFailure(
    dtls_alert_t.DTLS_ALERT_HANDSHAKE_FAILURE,
    "handshake_failure",
  ),

  /// A certificate was corrupt, contained signatures that did not
  /// verify correctly, etc.
  badCertificate(
    dtls_alert_t.DTLS_ALERT_BAD_CERTIFICATE,
    "bad_certificate",
  ),

  /// A certificate was of an unsupported type.
  unsupportedCertificate(
    dtls_alert_t.DTLS_ALERT_UNSUPPORTED_CERTIFICATE,
    "unsupported_certificate",
  ),

  /// A certificate was revoked by its signer.
  certificateRevoked(
    dtls_alert_t.DTLS_ALERT_CERTIFICATE_REVOKED,
    "certificate_revoked",
  ),

  /// A certificate has expired or is not currently valid.
  certificateExpired(
    dtls_alert_t.DTLS_ALERT_CERTIFICATE_EXPIRED,
    "certificate_expired",
  ),

  /// Some other (unspecified) issue arose in processing the certificate,
  /// rendering it unacceptable.
  certificateUnknown(
    dtls_alert_t.DTLS_ALERT_CERTIFICATE_UNKNOWN,
    "certificate_unknown",
  ),

  /// A field in the handshake was out of range or inconsistent with other
  /// fields.
  ///
  /// This message is always fatal.
  illegalParameter(
    dtls_alert_t.DTLS_ALERT_ILLEGAL_PARAMETER,
    "illegal_parameter",
  ),

  /// A valid certificate chain or partial chain was received, but the
  /// certificate was not accepted because the CA certificate could not
  /// be located or couldn't be matched with a known, trusted CA.
  ///
  /// This message is always fatal.
  unknownCa(
    dtls_alert_t.DTLS_ALERT_UNKNOWN_CA,
    "unknown_ca",
  ),

  /// A valid certificate was received, but when access control was
  /// applied, the sender decided not to proceed with negotiation.  This
  /// message is always fatal.
  accessDenied(
    dtls_alert_t.DTLS_ALERT_ACCESS_DENIED,
    "access_denied",
  ),

  /// A message could not be decoded because some field was out of the
  /// specified range or the length of the message was incorrect.
  ///
  /// This message is always fatal and should never be observed in
  /// communication between proper implementations (except when messages
  /// were corrupted in the network).
  decodeError(
    dtls_alert_t.DTLS_ALERT_DECODE_ERROR,
    "decode_error",
  ),

  /// A handshake cryptographic operation failed, including being unable
  /// to correctly verify a signature or validate a Finished message.
  ///
  /// This message is always fatal.
  decryptError(
    dtls_alert_t.DTLS_ALERT_DECRYPT_ERROR,
    "decrypt_error",
  ),

  /// The protocol version the client has attempted to negotiate is recognized
  /// but not supported. (For example, old protocol versions might be avoided
  /// for security reasons.)
  ///
  /// This message is always fatal.
  protocolVersion(
    dtls_alert_t.DTLS_ALERT_PROTOCOL_VERSION,
    "protocol_version",
  ),

  /// Returned instead of handshake_failure when a negotiation has failed
  /// specifically because the server requires ciphers more secure than those
  /// supported by the client.
  ///
  /// This message is always fatal.
  insufficientSecurity(
    dtls_alert_t.DTLS_ALERT_INSUFFICIENT_SECURITY,
    "insufficient_security",
  ),

  /// An internal error unrelated to the peer or the correctness of the protocol
  /// (such as a memory allocation failure) makes it impossible to continue.
  ///
  /// This message is always fatal.
  internalError(
    dtls_alert_t.DTLS_ALERT_INTERNAL_ERROR,
    "internal_error",
  ),

  /// This handshake is being canceled for some reason unrelated to a protocol
  /// failure.
  ///
  /// This alert should be followed by a [closeNotify].
  ///
  /// This message is generally a warning.
  userCanceled(
    dtls_alert_t.DTLS_ALERT_USER_CANCELED,
    "user_canceled",
  ),

  /// Sent by the client in response to a hello request or by the server in
  /// response to a client hello after initial handshaking.
  ///
  /// This message is always a warning.
  noRenegotiation(
    dtls_alert_t.DTLS_ALERT_NO_RENEGOTIATION,
    "no_renegotiation",
  ),

  /// Sent by clients that receive an extended server hello containing an
  /// extension that they did not put in the corresponding client
  /// hello.
  ///
  /// This message is always fatal.
  unsupportedExtension(
    dtls_alert_t.DTLS_ALERT_UNSUPPORTED_EXTENSION,
    "unsupported_extension",
  );

  /// Constructor.
  const AlertDescription(
    this._code,
    this._identifier,
  );

  final int _code;

  final String _identifier;

  static final _registry =
      HashMap.fromEntries(values.map((value) => MapEntry(value._code, value)));

  /// Creates an [AlertDescription] from a numeric [code].
  static AlertDescription? fromCode(int code) => _registry[code];

  @override
  String toString() {
    return _identifier;
  }
}

/// Describes an alert as specified by the DTLS specification or an event
/// defined by [TinyDTLS].
///
/// Consists of an [alertLevel] and a [alertDescription].
class DtlsEvent {
  /// The alert level of this alert.
  final AlertLevel? alertLevel;

  /// The description of this alert.
  final AlertDescription? alertDescription;

  /// Constructor.
  DtlsEvent(this.alertLevel, this.alertDescription);

  /// Constructor.
  factory DtlsEvent.fromCodes(int level, int code) {
    final alertLevel = AlertLevel.fromCode(level);
    final alertDescription = AlertDescription.fromCode(code);
    return DtlsEvent(alertLevel, alertDescription);
  }

  /// Indicates if this [DtlsEvent] demands closing the connection.
  ///
  /// Connections are closed automatically if a DTLS alert occurs which requires
  /// closing the connection. However, you can also use this information to
  /// clean up a DTLS client or server once a connection is closed.
  bool get requiresClosing =>
      alertLevel == AlertLevel.fatal ||
      alertDescription == AlertDescription.closeNotify;

  @override
  String toString() {
    final levelString = alertLevel?.toString() ?? "unknown Alert Level";
    final descriptionString =
        alertDescription?.toString() ?? "unknown Description";

    return "DtlsEvent with $levelString and description '$descriptionString'.";
  }
}
