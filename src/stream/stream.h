#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../constants.h"
#include "../common/buffer.h"

#ifdef HAVE_SHA256  // Disabled for unit tests
#include "cx.h"
#endif

typedef enum {
    STREAM_PARSING_STATE_NONE = 0x00,
    STREAM_PARSING_STATE_BLOCK_HEADER = 0x01,
    STREAM_PARSING_STATE_COMMAND = 0x02,
    STREAM_PARSING_STATE_SIGNATURE = 0x03,
} stream_parsing_state_t;

typedef struct {
    // Informations about the state of the stream
    uint8_t trusted_nonce[TRUSTED_PARSER_NONCE_LEN];  // Nonce used parse and sign the chain
    uint8_t topic[MAX_TOPIC_LEN];                     // Topic of the chain
    uint8_t topic_len;                                // Length of the topic
    uint8_t last_block_hash[HASH_LEN];                // Hash of the last block of the chain
    bool is_created;                                  // Stream contains a create group command
    uint8_t shared_secret[MAX_ENCRYPTED_KEY_LEN];     // Shared secret between members of the chain
    uint8_t
        shared_secret_len;  // Length of the shared secret (0 means we don't have a shared secret)

    // Informations about the current block being parsed
    uint8_t current_block_issuer[MEMBER_KEY_LEN];  // Issuer of the current block
    uint8_t current_block_length;                  // Number of instruction in the current block
    uint8_t parsed_command_count;                  // Number of command parsed in the current block
    stream_parsing_state_t parsing_state;          // Current state of the stream parser

#ifdef HAVE_SHA256
    cx_sha256_t digest;  // Current block digest
#endif
} stream_ctx_t;

/**
 * Initialize a stream context.
 */
void stream_init(stream_ctx_t *ctx);

/**
 * Parse a block header and add it to the stream.
 */
int stream_parse_block_header(stream_ctx_t *ctx, buffer_t *data);

/**
 * Parse a command and output trusted param
 * @param ctx Stream context
 * @param data Data to parse
 * @param trusted_data Trusted data to output (NULL if we don't want to output trusted data)
 */
int stream_parse_command(stream_ctx_t *ctx, buffer_t *data, buffer_t *trusted_data);

/**
 * Parse a signature and verifies if the stream has not been tampered with.
 */
int stream_parse_signature(stream_ctx_t *ctx, buffer_t *data);
