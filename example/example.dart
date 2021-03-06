// Copyright 2022 The NAMIB Project Developers. All rights reserved.
// See the README as well as the LICENSE file for more information.
//
// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_tinydtls/dart_tinydtls.dart';

EcdsaKeys _getKeys() {
  final privateKey = Uint8List.fromList(privateKeyList);
  final publicKeyX = Uint8List.fromList(publicKeyXList);
  final publicKeyY = Uint8List.fromList(publicKeyYList);

  return EcdsaKeys(EcdsaCurve.secp256r1,
      privateKey: privateKey, publicKeyX: publicKeyX, publicKeyY: publicKeyY);
}

final serverKeyStore = {"Client_identity": "secretPSK"};

Uint8List? _serverPskCallback(Uint8List identity) {
  final identityString = utf8.decode(identity.toList());

  final psk = serverKeyStore[identityString];

  if (psk == null) {
    return null;
  }

  return Uint8List.fromList(utf8.encode(psk));
}

PskCredentials _pskCallback(Uint8List identityHint) {
  return PskCredentials(
      identity: identityHint,
      preSharedKey: Uint8List.fromList("secretPSK".codeUnits));
}

Uint8List _pskIdentityHintCallback(InternetAddress address, int port) {
  return Uint8List.fromList("Client_identity".codeUnits);
}

// Insert your test server address and port here
const address = "::1";
const port = 5684;

Future<void> main() async {
  final server = await DtlsServer.bind(InternetAddress.anyIPv6, 5684,
      pskKeyStoreCallback: _serverPskCallback,
      ecdsaKeys: _getKeys(),
      pskIdentityHintCallback: _pskIdentityHintCallback);
  server.listen((connection) {
    connection.listen(
      (event) {
        print(utf8.decode(event.data));
        connection.send(utf8.encode("Hello from world!"));
      },
      onDone: () {
        print("Server connection closed.");
      },
    );
  });
  final client = await DtlsClient.bind(InternetAddress.anyIPv6, 0);

  int responses = 0;

  final connection = await client.connect(InternetAddress(address), port,
      pskCallback: _pskCallback, ecdsaKeys: _getKeys(), eventListener: (event) {
    print(event);
    if (event.requiresClosing) {
      print("Closing the client");
      client.close();
    }
  });
  connection
    ..listen((event) {
      print(utf8.decode(event.data));
      if (++responses >= 2) {
        server.close();
      }
    })
    ..send(utf8.encode('Hello World!'))
    ..send(utf8.encode('Goodbye World!'));
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
