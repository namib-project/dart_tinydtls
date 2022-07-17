// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

/// This [Exception] is thrown when an error occurs within dart_tinydtls.
class DtlsException implements Exception {
  /// Constructor.
  DtlsException(this.message);

  /// The error message of this [DtlsException].
  final String message;

  @override
  String toString() => "DtlsException: $message";
}
