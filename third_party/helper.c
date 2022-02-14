// This contains some small helper functions for the tinydtls bindings.
// Copyright of the original structures redefined in this file belongs to the original authors of tinydtls.

#include "tinydtls/dtls.h"

void dtls_set_handler_helper(dtls_context_t *ctx, dtls_handler_t *h) {
    ctx->h = h;
}

/** Structure of the Hello Verify Request. */
typedef struct __attribute__((__packed__)) {
  uint16 version;       /**< Server version */
  uint8 cookie_length;  /**< Length of the included cookie */
  uint8 cookie[32];     /**< up to 32 bytes making up the cookie */
} dtls_hello_verify_t_helper;
