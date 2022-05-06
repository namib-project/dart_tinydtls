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

      final pskCredentials =
          PskCredentials(identity: identity, preSharedKey: preSharedKey);

      final connection = await client.connect(InternetAddress(address), port,
          pskCallback: (identityHint) => pskCredentials);

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
          () => EcdsaKeys(
                EcdsaCurve.secp256r1,
                privateKey: invalidArgument,
                publicKeyX: validArgument,
                publicKeyY: validArgument,
              ),
          throwsA(predicate((e) =>
              e is ArgumentError &&
              e.message ==
                  "Expected a length of 32 bytes (256 bits) for the private "
                      "key of the curve secp256r1, but found 31 bytes "
                      "instead!")));

      expect(
          () => EcdsaKeys(
                EcdsaCurve.secp256r1,
                privateKey: validArgument,
                publicKeyX: invalidArgument,
                publicKeyY: validArgument,
              ),
          throwsA(predicate((e) =>
              e is ArgumentError &&
              e.message ==
                  "Expected a length of 32 bytes (256 bits) for the x "
                      "coordinate of the public key of the curve secp256r1, "
                      "but found 31 bytes instead!")));

      expect(
          () => EcdsaKeys(
                EcdsaCurve.secp256r1,
                privateKey: validArgument,
                publicKeyX: validArgument,
                publicKeyY: invalidArgument,
              ),
          throwsA(predicate((e) =>
              e is ArgumentError &&
              e.message ==
                  "Expected a length of 32 bytes (256 bits) for the y "
                      "coordinate of the public key of the curve secp256r1, "
                      "but found 31 bytes instead!")));

      final validKeys = EcdsaKeys(
        EcdsaCurve.secp256r1,
        privateKey: validArgument,
        publicKeyX: validArgument,
        publicKeyY: validArgument,
      );
      expect(validKeys.privateKey.length, validLength);
      expect(validKeys.publicKeyX.length, validLength);
      expect(validKeys.privateKey.length, validLength);
    });
  });

  /// Performs a very basic client server exchange.
  test('Client Server Exchange Test', () async {
    final completer = Completer<void>();
    final bindAddress = InternetAddress.anyIPv4;
    const address = "127.0.0.1";
    const port = 5684;

    final ecdsaKeys = _getKeys();

    const clientMessage = "Hello World!";
    const serverMessage = "Goodbye World!";

    final client = await DtlsClient.bind(bindAddress, 0);
    expect(client.closed, false);
    final server =
        await DtlsServer.bind(bindAddress, port, ecdsaKeys: ecdsaKeys);
    expect(server.closed, false);

    server.listen(((connection) {
      connection.listen((event) {
        expect(utf8.decode(event.data), clientMessage);
        connection.send(utf8.encode(serverMessage));
      });
    }));

    final connection = await client.connect(InternetAddress(address), port,
        ecdsaKeys: ecdsaKeys);

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
}

EcdsaKeys _getKeys() {
  final privateKey = Uint8List.fromList(privateKeyList);
  final publicKeyX = Uint8List.fromList(publicKeyXList);
  final publicKeyY = Uint8List.fromList(publicKeyYList);

  return EcdsaKeys(EcdsaCurve.secp256r1,
      privateKey: privateKey, publicKeyX: publicKeyX, publicKeyY: publicKeyY);
}

const privateKeyList = [
  0x41,
  0xC1,
  0xCB,
  0x6B,
  0x51,
  0x24,
  0x7A,
  0x14,
  0x43,
  0x21,
  0x43,
  0x5B,
  0x7A,
  0x80,
  0xE7,
  0x14,
  0x89,
  0x6A,
  0x33,
  0xBB,
  0xAD,
  0x72,
  0x94,
  0xCA,
  0x40,
  0x14,
  0x55,
  0xA1,
  0x94,
  0xA9,
  0x49,
  0xFA
];

const publicKeyXList = [
  0x36,
  0xDF,
  0xE2,
  0xC6,
  0xF9,
  0xF2,
  0xED,
  0x29,
  0xDA,
  0x0A,
  0x9A,
  0x8F,
  0x62,
  0x68,
  0x4E,
  0x91,
  0x63,
  0x75,
  0xBA,
  0x10,
  0x30,
  0x0C,
  0x28,
  0xC5,
  0xE4,
  0x7C,
  0xFB,
  0xF2,
  0x5F,
  0xA5,
  0x8F,
  0x52
];

const publicKeyYList = [
  0x71,
  0xA0,
  0xD4,
  0xFC,
  0xDE,
  0x1A,
  0xB8,
  0x78,
  0x5A,
  0x3C,
  0x78,
  0x69,
  0x35,
  0xA7,
  0xCF,
  0xAB,
  0xE9,
  0x3F,
  0x98,
  0x72,
  0x09,
  0xDA,
  0xED,
  0x0B,
  0x4F,
  0xAB,
  0xC3,
  0x6F,
  0xC7,
  0x72,
  0xF8,
  0x29
];
