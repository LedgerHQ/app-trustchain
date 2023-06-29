#include "signer.h"
#include "block_parser.h"
#include <string.h>
#include "cx.h"
#include "crypto.h"
#include "debug.h"
#include "../io.h"
#include "block_hasher.h"
#include "../trusted_properties.h"
#include "../globals.h"

int signer_init(signer_ctx_t *signer, const uint32_t *bip32_path, size_t bip32_path_len) {
    cx_sha256_init(&signer->digest);
    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key = {0};
    uint8_t derivation_buffer[65] = {0};
    int error;

    error = crypto_derive_private_key(&private_key, derivation_buffer, bip32_path, bip32_path_len);
    if (error != 0) {
        return error;
    }

    // SeedID initialization

    crypto_init_public_key(&private_key, &public_key, derivation_buffer + 1);
    error = crypto_compress_public_key(derivation_buffer, signer->issuer_public_key);

    explicit_bzero(&private_key, sizeof(private_key));
    return error;
}

void signer_reset() {
    explicit_bzero(&G_context.signer_info, sizeof(G_context.signer_info));
    explicit_bzero(&G_context.stream, sizeof(G_context.stream));
}

// TODO REMOVE STATIC PATH

static bool signer_verify_parent_hash(stream_ctx_t *stream, uint8_t *parent_hash) {
    uint8_t hash[HASH_LEN];

    cx_hash_final((cx_hash_t *) &stream->digest, hash);
    return memcmp(hash, parent_hash, sizeof(hash)) == 0;
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

    // Set the block issuer
    memcpy(block_header.issuer, signer->issuer_public_key, MEMBER_KEY_LEN);

    // Digest block header
    block_hash_header(&block_header, (cx_hash_t *) &signer->digest);
    return 0;
}

static int signer_inject_seed(signer_ctx_t *signer, block_command_t *command) {
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t public_key;
    uint8_t xpriv[64];
    cx_aes_key_t key;
    uint8_t secret[32];
    buffer_t buffer;
    int ret = 0;
    
    // Generate private key
    ret = cx_ecfp_generate_pair(CX_CURVE_256K1, &public_key, &private_key, 0);
    if (ret != 0)
        return ret;

    // Generate chain code
    cx_trng_get_random_data(xpriv + 32, 32);

    // Create ephemeral ECDH
    ret = crypto_ephemeral_ecdh(signer->issuer_public_key, command->command.seed.ephemeral_public_key, secret);
    if (ret != 0)
        return ret;

    // Generate IV
    cx_trng_get_random_data(command->command.seed.initialization_vector, sizeof(command->command.seed.initialization_vector));

    // Write private key in xpriv buffer
    memcpy(xpriv, private_key.d, sizeof(private_key.d));

    // Encrypt xpriv
    ret = cx_aes_init_key(secret, sizeof(secret), &key);
    if (ret < 0)
        return ret;
    cx_aes_iv(
        &key, 
        CX_ENCRYPT | CX_CHAIN_CBC | CX_LAST, 
        command->command.seed.initialization_vector,
        sizeof(command->command.seed.initialization_vector),
        xpriv, 
        sizeof(xpriv), 
        command->command.seed.encrypted_xpriv,
        sizeof(command->command.seed.encrypted_xpriv)
    );

    command->command.seed.encrypted_xpriv_size = sizeof(command->command.seed.encrypted_xpriv);

    // Compress and save group key
    crypto_compress_public_key(public_key.W, command->command.seed.group_public_key);

    // Push trusted properties
    // - push encrypted xpriv
    buffer.ptr = command->command.seed.encrypted_xpriv;
    buffer.size = sizeof(command->command.seed.encrypted_xpriv);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_XPRIV, &buffer);
    if (ret != 0)
        return ret;
    // - push ephemeral public key
    buffer.ptr = command->command.seed.ephemeral_public_key;
    buffer.size = sizeof(command->command.seed.ephemeral_public_key);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_EPHEMERAL_PUBLIC_KEY, &buffer);
    if (ret != 0)
        return ret;

    // - push initialization vector
    buffer.ptr = command->command.seed.initialization_vector;
    buffer.size = sizeof(command->command.seed.initialization_vector);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_COMMAND_IV, &buffer);
    if (ret != 0)
        return ret;

    // - push group key
    buffer.ptr = command->command.seed.group_public_key;
    buffer.size = sizeof(command->command.seed.group_public_key);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_GROUPKEY, &buffer);
    if (ret != 0)
        return ret;

    explicit_bzero(&private_key, sizeof(private_key));

    // User approval
    // TODO implement user approval

    return ret < 0 ? ret : 0;
}

int signer_parse_command(signer_ctx_t *signer,
                         stream_ctx_t *stream,
                         buffer_t *data) {
    block_command_t command;

    int err = parse_block_command(data, &command);

    if (err < 0) {
        return err;
    }

    // First pass: inject data in command buffer
    io_init_trusted_property();
    if (command.type == COMMAND_SEED) {
        // Creating a group should not require an approval
        if (stream->is_created) {
            return BS_INVALID_STATE;
        }
        stream->is_created = true;
        stream->topic_len = command.command.seed.topic_len;
        memcpy(stream->topic,
               command.command.seed.topic,
               command.command.seed.topic_len);
        err = signer_inject_seed(signer, &command);
    } else {
        return BP_ERROR_UNKNOWN_COMMAND;
    }
    
    if (err != 0) {
        explicit_bzero(&G_context.signer_info, sizeof(G_context.signer_info));
        explicit_bzero(&G_context.stream, sizeof(G_context.stream));
        return err;
    }

    // Digest command
    //cx_sha256_init(&signer->digest);
    block_hash_command(&command, (cx_hash_t *) &signer->digest);
    return 0;
}

int signer_approve_command(stream_ctx_t *stream, buffer_t *trusted_data) {
    (void) stream;
    (void) trusted_data;

    return 0;
}

int signer_sign_block(signer_ctx_t *signer, stream_ctx_t *stream) {
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