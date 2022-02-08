// TODO: Put public facing types in this file.

import 'ffi/generated_bindings.dart';
import 'dart:ffi' as ffi;

late ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName) _lookup;

void dtls_set_handler(ffi.Pointer<dtls_context_t> ctx, ffi.Pointer<dtls_handler_t> h) {
    _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<dtls_handler_t>)>>('dtls_set_handler').asFunction<void Function(ffi.Pointer<dtls_context_t>, ffi.Pointer<dtls_handler_t>)>()(ctx, h);
}
