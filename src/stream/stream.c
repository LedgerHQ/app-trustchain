#include "stream.h"
#include "cx.h"
#include <string.h>

void stream_init(stream_ctx_t *ctx) {
    // Initialize the stream context
    memset(ctx, 0, sizeof(stream_ctx_t));

    // Trusted nonce will be used to sign trusted params
    cx_trng_get_random_data(ctx->trusted_nonce, sizeof(ctx->trusted_nonce));

    // Expect the next item to be a block header
    ctx->parsing_state = STREAM_PARSING_STATE_BLOCK_HEADER;
}

int stream_parse_block_header(stream_ctx_t *ctx, buffer_t *data) {
    (void) data;
    (void) ctx;
    return 0;
}

int stream_parse_command(stream_ctx_t *ctx, buffer_t *data, buffer_t *trusted_data) {
    (void) trusted_data;
    (void) data;
    (void) ctx;

    return 0;
}

int stream_parse_signature(stream_ctx_t *ctx, buffer_t *data) {
    (void) data;
    (void) ctx;

    return 0;
}