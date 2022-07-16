// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:typed_data';

/// Credentials used for PSK Cipher Suites consisting of an [identity]
/// and a [preSharedKey].
class PskCredentials {
  /// The identity used with the [preSharedKey].
  Uint8List identity;

  /// The actual pre-shared key.
  Uint8List preSharedKey;

  /// Constructor
  PskCredentials({required this.identity, required this.preSharedKey});
}
