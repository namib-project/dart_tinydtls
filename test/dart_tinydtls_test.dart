// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:async';
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
      expect(client.closed, false);
      client.close();
      expect(client.closed, true);
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
      final completer = Completer<void>();
      final bindAddress = InternetAddress.anyIPv4;
      const address = "127.0.0.1";
      const port = 5684;

      const identity = "Client_identity";
      const preSharedKey = "secretPSK";

      const clientMessage = "Hello World!";
      const serverMessage = "Goodbye World!";

      final client = await DtlsClient.bind(bindAddress, 0);
      expect(client.closed, false);
      final server = await DtlsServer.bind(bindAddress, port,
          keyStore: {identity: preSharedKey});
      expect(server.closed, false);

      server.listen(((connection) {
        connection.listen((event) {
          expect(utf8.decode(event.data), clientMessage);
          connection.send(utf8.encode(serverMessage));
        });
      }));

      final connection = await client.connect(InternetAddress(address), port,
          pskCredentials: PskCredentials(identity, preSharedKey));

      connection
        ..listen((event) {
          expect(utf8.decode(event.data), serverMessage);

          server.close();
          expect(server.closed, true);
          client.close();
          expect(client.closed, true);
          completer.complete();
        })
        ..send(utf8.encode(clientMessage));

      return completer.future;
    });
  });

  group('ECDSA Key Tests', () {
    /// Tests if invalid ECDSA keys are rejected and valid keys are accepted.
    test('ECDSA Key Validation Test', () async {
      const validLength = 32;
      const invalidLength = validLength - 1;

      final validArgument =
          Uint8List.fromList(List<int>.filled(validLength, 0));
      final invalidArgument =
          Uint8List.fromList(List<int>.filled(invalidLength, 0));

      expect(
          () => EcdsaKeys(EcdsaCurve.secp256r1, invalidArgument, validArgument,
              validArgument),
          throwsA(predicate((e) =>
              e is ArgumentError &&
              e.message ==
                  "Expected a length of 32 bytes (256 bits) for the private "
                      "key of the curve secp256r1, but found 31 bytes "
                      "instead!")));

      expect(
          () => EcdsaKeys(EcdsaCurve.secp256r1, validArgument, invalidArgument,
              validArgument),
          throwsA(predicate((e) =>
              e is ArgumentError &&
              e.message ==
                  "Expected a length of 32 bytes (256 bits) for the x "
                      "coordinate of the public key of the curve secp256r1, "
                      "but found 31 bytes instead!")));

      expect(
          () => EcdsaKeys(EcdsaCurve.secp256r1, validArgument, validArgument,
              invalidArgument),
          throwsA(predicate((e) =>
              e is ArgumentError &&
              e.message ==
                  "Expected a length of 32 bytes (256 bits) for the y "
                      "coordinate of the public key of the curve secp256r1, "
                      "but found 31 bytes instead!")));

      final validKeys = EcdsaKeys(
          EcdsaCurve.secp256r1, validArgument, validArgument, validArgument);
      expect(validKeys.privateKey.length, validLength);
      expect(validKeys.publicKeyX.length, validLength);
      expect(validKeys.privateKey.length, validLength);
    });
  });
}
