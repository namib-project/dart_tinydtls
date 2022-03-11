// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:io';

import 'package:dart_tinydtls/dart_tinydtls.dart';
import 'package:test/test.dart';

void main() {
  group('Client Tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    /// Tests if the dynamic library can be loaded from within a DtlsClient.
    test('Client Instantiation Test', () async {
      final client = await DtlsClient.bind(InternetAddress.anyIPv6, 0);
      client.close();
    });

    /// Asserts that a user has to provide client credentials in order to
    /// connect.
    test('Connect Credentials Test', () async {
      final client = await DtlsClient.bind(InternetAddress.anyIPv6, 0);
      expect(client.connect(InternetAddress.anyIPv6, 5684),
          throwsA(TypeMatcher<ArgumentError>()));
      client.close();
    });
  });
}
