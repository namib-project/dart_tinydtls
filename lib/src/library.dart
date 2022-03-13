// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:ffi';
import 'dart:io';

import 'ffi/generated_bindings.dart';

/// This [Exception] is thrown if there is an error loading
/// the shared tinyDTLS library.
///
/// Using an [Exception] instead of an [Error] allows users
/// to provide a fallback or throw their own [Exception]s
/// if tinyDTLS should not be available.
class TinyDtlsLoadException implements Exception {
  /// The actual error message.
  final String message;

  /// Constructor.
  TinyDtlsLoadException(this.message);
}

DynamicLibrary _loadTinyDtlsLibrary() {
  // TODO(JKRhb): Check if paths should be adjusted
  if (Platform.isAndroid) {
    return DynamicLibrary.open("libtinydtls.so");
  }

  if (Platform.isLinux) {
    final paths = ["./libtinydtls.so", "/usr/local/lib/libtinydtls.so"];

    for (final path in paths) {
      final fileExists = File(path).existsSync();
      if (fileExists) {
        return DynamicLibrary.open(path);
      }
    }

    throw TinyDtlsLoadException("Couldn't find libtinydtls.so.");
  }

  if (Platform.isWindows) {
    return DynamicLibrary.open("libtinydtls.dll");
  }

  if (Platform.isMacOS) {
    return DynamicLibrary.open("libtinydtls.dylib");
  }

  if (Platform.isIOS) {
    return DynamicLibrary.executable();
  }

  throw TinyDtlsLoadException("Couldn't find a shared tinyDTLS library.");
}

TinyDTLS _loadTinyDtls() {
  return TinyDTLS(_loadTinyDtlsLibrary());
}

/// Represents the loaded tinyDTLS library.
late final TinyDTLS globalTinyDtls = _loadTinyDtls();
