#pragma once

#include "../stream/stream.h"
#include "types.h"

typedef enum {
    BS_INVALID_PARENT_HASH = -16,
    BS_INVALID_ISSUER = -17,
} signer_state_t;

int signer_init(signer_ctx_t *signer, const uint32_t *bip32_path, size_t bip32_path_len);

/**
 * Parse block header and start computing the digest
 */
int signer_parse_block_header(signer_ctx_t *signer, stream_ctx_t *stream, buffer_t *data);

/**
 * Parse command and compute digest. Once parsed the command the command
 * asks for validation and output of trusted params
 */
int signer_parse_command(signer_ctx_t *signer,
                         stream_ctx_t *stream,
                         buffer_t *data,
                         buffer_t *trusted_data);

/**
 * Approve the last command with a trusted params previously computed
 */
int signer_approve_command(stream_ctx_t *stream, buffer_t *trusted_data);

/**
 * Sign the block
 */
int signer_sign_block(signer_ctx_t *signer);