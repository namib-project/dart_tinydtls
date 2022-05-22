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

const _errorMessage = "Couldn't find a shared tinyDTLS library.";

/// This [Exception] is thrown if there is an error loading
/// the shared tinyDTLS library.
///
/// Using an [Exception] instead of an [Error] allows users
/// to provide a fallback or throw their own [Exception]s
/// if tinyDTLS should not be available.
class TinyDtlsLoadException implements Exception {
  /// The actual error message.
  final String message;

  /// The original [Error] that caused this [Exception].
  final Error? originalError;

  /// Constructor.
  TinyDtlsLoadException(this.message, [this.originalError]);

  @override
  String toString() {
    return "$runtimeType: $message";
  }
}

/// Checks if a file exists under one of the given [paths] and tries to load it
/// as a [DynamicLibrary].
///
/// If no file can be found under one of the [paths], `null` is returned.
DynamicLibrary? _findTinyDtlsOnFileSystem(List<String> paths) {
  for (final path in paths) {
    final fileExists = File(path).existsSync();
    if (fileExists) {
      return DynamicLibrary.open(path);
    }
  }

  return null;
}

/// Checks first if tinyDTLS exists under one of the given file [paths], before
/// trying to use the [defaultFileName] for the current platform.
///
/// The [defaultFileName] will be the one used in Flutter apps in most cases.
DynamicLibrary _findTinyDtlsLibrary(
    List<String> paths, String defaultFileName) {
  final tinyDtls = _findTinyDtlsOnFileSystem(paths);

  return tinyDtls ?? DynamicLibrary.open(defaultFileName);
}

DynamicLibrary _loadTinyDtlsLibrary() {
  // TODO(JKRhb): Check if there are default installation paths for MacOS and
  //              Windows

  if (Platform.isAndroid) {
    return DynamicLibrary.open(_linuxFileName);
  }

  if (Platform.isLinux) {
    const paths = ["./$_linuxFileName", "/usr/local/lib/$_linuxFileName"];
    return _findTinyDtlsLibrary(paths, _linuxFileName);
  }

  if (Platform.isWindows) {
    const paths = [_windowsFileName];
    return _findTinyDtlsLibrary(paths, _windowsFileName);
  }

  if (Platform.isMacOS) {
    const paths = ["./$_macosFileName"];
    return _findTinyDtlsLibrary(paths, _macosFileName);
  }

  if (Platform.isIOS) {
    return DynamicLibrary.executable();
  }

  throw TinyDtlsLoadException(_errorMessage);
}

TinyDTLS _loadTinyDtls() {
  final DynamicLibrary tinyDtls;
  try {
    tinyDtls = _loadTinyDtlsLibrary();
  }
  // ignore: avoid_catching_errors
  on ArgumentError catch (error) {
    // We catch the error here contrary to the recommended behavior in order to
    // allow library users to offer DTLS functionality in their own libraries
    // with the possibility that no tinyDTLS is available on the given platform.
    throw TinyDtlsLoadException(_errorMessage, error);
  }
  return TinyDTLS(tinyDtls);
}

/// Represents the loaded tinyDTLS library.
late final TinyDTLS globalTinyDtls = _loadTinyDtls();

const _bufferSize = (1 << 16);

/// Buffer used by tinyDTLS for reading and writing.
late final Pointer<Uint8> buffer = malloc.call<Uint8>(_bufferSize);
