// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

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

    /// Performs a very basic client server exchange.
    test('Client Server Exchange Test', () async {
      final bindAddress = InternetAddress.anyIPv4;
      const address = "127.0.0.1";
      const port = 5684;

      const identity = "Client_identity";
      const preSharedKey = "secretPSK";

      const clientMessage = "Hello World!";
      const serverMessage = "Goodbye World!";

      final client = await DtlsClient.bind(bindAddress, 0);
      final server = await DtlsServer.bind(bindAddress, port,
          keyStore: {identity: preSharedKey});

      server.listen(((event) {
        expect(utf8.decode(event.data.data), clientMessage);
        event.respond(utf8.encode(serverMessage));
      }));

      client.listen((event) {
        expect(utf8.decode(event.data), serverMessage);

        server.close();
        client.close();
      });

      final connection = await client.connect(InternetAddress(address), port,
          pskCredentials: PskCredentials(identity, preSharedKey));

      connection.send(Uint8List.fromList(utf8.encode(clientMessage)));
    });
  });
}
