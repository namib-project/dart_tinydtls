// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'ffi/generated_bindings.dart';

/// Events that are being signalled by tinyDTLS during and after the
/// connection establishment.
enum DtlsEvent {
  /// Occurs when the peer has closed the connection.
  dtlsEventCloseNotify,

  /// Occurs when the Client is trying to connect to the peer.
  dtlsEventConnect,

  /// Occurs when the connection has been successfully established.
  dtlsEventConnected,

  /// Occurs if the Client is trying to re-connect to an endpoint.
  dtlsEventRenegotiate
}

/// Converts a numeric DTLS [eventCode] to a [DtlsEvent].
///
/// Returns `null` if the [eventCode] is unknown.
DtlsEvent? eventFromCode(int eventCode) {
  switch (eventCode) {
    case dtls_alert_t.DTLS_ALERT_CLOSE_NOTIFY:
      return DtlsEvent.dtlsEventCloseNotify;
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
