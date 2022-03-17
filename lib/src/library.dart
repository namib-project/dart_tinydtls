// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import 'ffi/generated_bindings.dart';

const _linuxFileName = "libtinydtls.so";
const _windowsFileName = "libtinydtls.dll";
const _macosFileName = "libtinydtls.dylib";

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

String _findTinyDtlsLibrary(List<String> paths, String fileName) {
  for (final path in paths) {
    final fileExists = File(path).existsSync();
    if (fileExists) {
      return path;
    }
  }

  throw TinyDtlsLoadException("Couldn't find $fileName.");
}

DynamicLibrary _loadTinyDtlsLibrary() {
  // TODO(JKRhb): Check if paths should be adjusted
  if (Platform.isAndroid) {
    return DynamicLibrary.open(_linuxFileName);
  }

  if (Platform.isLinux) {
    const paths = ["./$_linuxFileName", "/usr/local/lib/$_linuxFileName"];
    final path = _findTinyDtlsLibrary(paths, _linuxFileName);
    return DynamicLibrary.open(path);
  }

  if (Platform.isWindows) {
    const paths = [_windowsFileName];
    final path = _findTinyDtlsLibrary(paths, _windowsFileName);
    return DynamicLibrary.open(path);
  }

  if (Platform.isMacOS) {
    const paths = [_macosFileName];
    final path = _findTinyDtlsLibrary(paths, _macosFileName);
    return DynamicLibrary.open(path);
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

const _bufferSize = (1 << 16);

/// Buffer used by tinyDTLS for reading and writing.
late final Pointer<Uint8> buffer = malloc.call<Uint8>(_bufferSize);
