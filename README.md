# dart_tinydtls

Dart ffi bindings to the tinydtls library.

## Generating the bindings

1. Clone the repository and initialize its submodules
   (i.e. `git submodule update --init --recursive`).
2. Generate the bindings using `dart run ffigen`.
   - You may need to change the `compiler-opts` option in `pubspec.yaml` to match your system's
     location of corresponding header files for `stddef.h` and so on.
3. There are exactly two warnings which can be ignored:
    1. `Removed All Struct Members from dtls_handshake_parameters_t(dtls_handshake_parameters_t), Bit Field members not supported.`
       - The struct `dtls_handshake_parameters_t` won't be used by library clients, so the 
         fact that it's opaque in the bindings can safely be ignored.
    2. `Generated declaration '__socklen_t' start's with '_' and therefore will be private.`
        - Similarly, it won't cause any problems for `__socklen_t` to be private.

In `helper.c`, two "overrides" are defined for C members which would otherwise cause problems:
- `dtls_set_handler` is an inline function, which `ffigen` doesn't support.
  - The function is rewritten as a "normal" C function.
- `dtls_hello_verify_t` contains bit field members, which `ffigen` doesn't support.
    - The members are rewritten as "normal" unsigned integers. 
      Callers need to make sure to still respect the original bit field boundary!

## License

Matching the license of the tinydtls C library, this library is made available both under
the terms of the Eclipse Public License v1.0 and 3-Clause BSD License (which the
Eclipse Distribution License v1.0 that is used for tinydtls is based on).
Additionally, the tinydtls C library contains third party code that might be included
in compiled binaries that link to tinydtls.
For information on third-party code and its licenses, see
https://github.com/eclipse/tinydtls/blob/develop/ABOUT.md.
See https://github.com/eclipse/tinydtls/blob/develop/LICENSE for more information on the
tinydtls licensing terms and https://www.eclipse.org/legal/eplfaq.php for more information
on the EPL 1.0.

Note: This binding is neither supported nor endorsed by the Eclipse Foundation.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Maintainers

This project is currently maintained by the following developers:

|      Name      |      Email Address       |            GitHub Username            |
|:--------------:|:------------------------:|:-------------------------------------:|
|   Jan Romann   | jan.romann@uni-bremen.de |   [JKRhb](https://github.com/JKRhb)   |
| Falko Galperin |   falko1@uni-bremen.de   | [falko17](https://github.com/falko17) |
