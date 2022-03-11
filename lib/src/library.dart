// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:ffi';
import 'dart:io';

import 'ffi/generated_bindings.dart';

DynamicLibrary _loadTinyDtlsLibrary() {
  // TODO(JKRhb): Check if paths should be adjusted
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open("./libtinydtls.so");
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

  throw StateError("There is currently no tinyDTLS support on "
      "${Platform.operatingSystem}!");
}

TinyDTLS _loadTinyDtls() {
  return TinyDTLS(_loadTinyDtlsLibrary());
}

/// Represents the loaded tinyDTLS library.
final TinyDTLS globalTinyDtls = _loadTinyDtls();
