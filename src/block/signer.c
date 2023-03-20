#include "signer.h"
#include "block_parser.h"
#include <string.h>
#include "cx.h"
#include "crypto.h"

int signer_init(signer_ctx_t *signer, const uint32_t *bip32_path, size_t bip32_path_len) {
    cx_sha256_init(&signer->digest);
    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key = {0};
    uint8_t derivation_buffer[64] = {0};
    int error;

    error = crypto_derive_private_key(&private_key, derivation_buffer, bip32_path, bip32_path_len);
    if (error != 0) {
        return error;
    }
    crypto_init_public_key(&private_key, &public_key, derivation_buffer);
    error = crypto_compress_public_key(derivation_buffer, signer->issuer_pk);

    explicit_bzero(&private_key, sizeof(private_key));
    return error;
}

// TODO REMOVE STATIC PATH

static bool signer_verify_parent_hash(stream_ctx_t *stream, uint8_t *parent_hash) {
    uint8_t hash[HASH_LEN];
    cx_hash_final((cx_hash_t *) &stream->digest, hash);
    return memcmp(hash, parent_hash, sizeof(hash)) == 0;
}

static bool signer_verify_issuer(signer_ctx_t *signer, uint8_t *issuer) {
    // Initialize issuer public key
    return memcmp(issuer, signer->issuer_pk, 33) == 0;
}

int signer_parse_block_header(signer_ctx_t *signer, stream_ctx_t *stream, buffer_t *data) {
    // Parse the block header
    block_header_t block_header;
    int err = parse_block_header(data, &block_header);

    if (!err) {
        return err;
    }

    // Verify the parent is set to the current block hash (if stream is created)

    if (stream->is_created && !signer_verify_parent_hash(stream, block_header.parent)) {
        return BS_INVALID_PARENT_HASH;
    }

    // Verify the issuer is set to the device public key
    if (!signer_verify_issuer(signer, block_header.issuer)) {
        return BS_INVALID_ISSUER;
    }

    // Digest block header

    cx_hash((cx_hash_t *) &signer->digest, 0, data->ptr, data->size, NULL, 0);

    return 0;
}

int signer_parse_command(signer_ctx_t *signer,
                         stream_ctx_t *stream,
                         buffer_t *data,
                         buffer_t *trusted_data) {
    (void) signer;
    (void) stream;
    (void) data;
    (void) trusted_data;

    block_command_t command;

    int err = parse_block_command(data, &command);

    if (err < 0) {
        return err;
    }

    if (command.type == COMMAND_CREATE_GROUP) {
        // Creating a group should not require an approval
        if (stream->is_created) {
            return BS_INVALID_STATE;
        }
        stream->is_created = true;
        stream->topic_len = command.command.create_group.topic_len;
        memcpy(stream->topic,
               command.command.create_group.topic,
               command.command.create_group.topic_len);
    } else {
        return BP_ERROR_UNKNOWN_COMMAND;
    }

    // Digest command
    cx_hash((cx_hash_t *) &signer->digest, 0, data->ptr, data->size, NULL, 0);

    return 0;
}

int signer_approve_command(stream_ctx_t *stream, buffer_t *trusted_data) {
    (void) stream;
    (void) trusted_data;

    return 0;
}

int signer_sign_block(signer_ctx_t *signer, stream_ctx_t *stream) {
    (void) signer;

    // Finalize hashing and put it in stream last block hash
    cx_hash((cx_hash_t *) &signer->digest,
            CX_LAST,
            NULL,
            0,
            stream->last_block_hash,
            sizeof(stream->last_block_hash));

    // Sign the block
    return crypto_sign_block();
}