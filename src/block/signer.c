#include "signer.h"
#include "block_parser.h"
#include <string.h>
#include "cx.h"
#include "crypto.h"
#include "debug.h"
#include "../io.h"
#include "block_hasher.h"
#include "../trusted_properties.h"

int signer_init(signer_ctx_t *signer, const uint32_t *bip32_path, size_t bip32_path_len) {
    cx_sha256_init(&signer->digest);
    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key = {0};
    uint8_t derivation_buffer[65] = {0};
    int error;

    DEBUG_LOG_BUF("INIT DERIVATION ON ", bip32_path, sizeof(SEED_ID_PATH));
    error = crypto_derive_private_key(&private_key, derivation_buffer, bip32_path, bip32_path_len);
    DEBUG_LOG_BUF("ISSUER PRIVATE KEY", private_key.d, private_key.d_len);
    if (error != 0) {
        return error;
    }

    // SeedID initialization

    crypto_init_public_key(&private_key, &public_key, derivation_buffer + 1);
    error = crypto_compress_public_key(derivation_buffer, signer->issuer_public_key);

    DEBUG_PRINT("ISSUER PUBLIC KEY: ")
    DEBUG_PRINT_BUF(signer->issuer_public_key, MEMBER_KEY_LEN);

    explicit_bzero(&private_key, sizeof(private_key));
    return error;
}

// TODO REMOVE STATIC PATH

static bool signer_verify_parent_hash(stream_ctx_t *stream, uint8_t *parent_hash) {
    uint8_t hash[HASH_LEN];
    DEBUG_PRINT("HASH FINALIZE");
    cx_hash_final((cx_hash_t *) &stream->digest, hash);
    return memcmp(hash, parent_hash, sizeof(hash)) == 0;
}

int signer_parse_block_header(signer_ctx_t *signer, stream_ctx_t *stream, buffer_t *data) {
    DEBUG_PRINT("ISSUER PUBLIC KEY parse header: ")
    DEBUG_PRINT_BUF(signer->issuer_public_key, MEMBER_KEY_LEN);
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
    DEBUG_PRINT("ISSUER PUBLIC KEY seed: ")
    DEBUG_PRINT_BUF(signer->issuer_public_key, MEMBER_KEY_LEN);
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t public_key;
    uint8_t xpriv[64];
    cx_aes_key_t key;
    uint8_t secret[32];
    buffer_t buffer;
    int ret = 0;
    
    DEBUG_PRINT("SIGNER INJECT SEED 1\n")
    // Generate private key
    ret = cx_ecfp_generate_pair(CX_CURVE_256K1, &public_key, &private_key, 0);
    if (ret != 0)
        return ret;

    DEBUG_PRINT("SIGNER INJECT SEED 2\n")
    // Generate chain code
    cx_trng_get_random_data(xpriv + 32, 32);

    DEBUG_PRINT("ISSUER PUBLIC KEY 3: ")
    DEBUG_PRINT_BUF(signer->issuer_public_key, MEMBER_KEY_LEN);
    // Create ephemeral ECDH
    ret = crypto_ephemeral_ecdh(signer->issuer_public_key, command->command.seed.ephemeral_public_key, secret);
    if (ret != 0)
        return ret;

    DEBUG_PRINT("SIGNER INJECT SEED 3\n")
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
    DEBUG_PRINT("SIGNER INJECT SEED 4\n")

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
    DEBUG_PRINT("SIGNER INJECT SEED 5\n")
    // - push ephemeral public key
    buffer.ptr = command->command.seed.ephemeral_public_key;
    buffer.size = sizeof(command->command.seed.ephemeral_public_key);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_EPHEMERAL_PUBLIC_KEY, &buffer);
    if (ret != 0)
        return ret;
    DEBUG_PRINT("SIGNER INJECT SEED 6\n")
    // - push initialization vector
    buffer.ptr = command->command.seed.initialization_vector;
    buffer.size = sizeof(command->command.seed.initialization_vector);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_COMMAND_IV, &buffer);
    if (ret != 0)
        return ret;
    DEBUG_PRINT("SIGNER INJECT SEED 7\n")
    // - push group key
    buffer.ptr = command->command.seed.group_public_key;
    buffer.size = sizeof(command->command.seed.group_public_key);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_GROUPKEY, &buffer);
    if (ret != 0)
        return ret;

    explicit_bzero(&private_key, sizeof(private_key));
    return ret < 0 ? ret : 0;
}

int signer_parse_command(signer_ctx_t *signer,
                         stream_ctx_t *stream,
                         buffer_t *data) {
                            DEBUG_PRINT("ISSUER PUBLIC KEY 2: ")
    DEBUG_PRINT_BUF(signer->issuer_public_key, MEMBER_KEY_LEN);
    DEBUG_PRINT("Signer parse command 1\n");
    block_command_t command;

    int err = parse_block_command(data, &command);

    if (err < 0) {
        return err;
    }
    DEBUG_PRINT("Signer parse command 2\n");

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
        if (err != 0) {
            return err;
        }
    } else {
        DEBUG_PRINT("Signer parse command 3\n");
        return BP_ERROR_UNKNOWN_COMMAND;
    }
    DEBUG_PRINT("Signer parse command 4\n");
    
    // Digest command
    //cx_sha256_init(&signer->digest);
    block_hash_command(&command, (cx_hash_t *) &signer->digest);
    DEBUG_PRINT("Signer parse command 5\n");
    return 0;
}

int signer_approve_command(stream_ctx_t *stream, buffer_t *trusted_data) {
    (void) stream;
    (void) trusted_data;

    return 0;
}

int signer_sign_block(signer_ctx_t *signer, stream_ctx_t *stream) {
    (void) signer;
    DEBUG_PRINT("ISSUER PUBLIC KEY 3: ")
    DEBUG_PRINT_BUF(signer->issuer_public_key, MEMBER_KEY_LEN);

    // Finalize hashing and put it in stream last block hash
    DEBUG_PRINT("SIGN BLOCK (hash finalize)\n");
    
    cx_hash((cx_hash_t *) &signer->digest,
            CX_LAST,
            NULL,
            0,
            stream->last_block_hash,
            sizeof(stream->last_block_hash));
    DEBUG_PRINT("HASH TO SIGN: ");
    DEBUG_PRINT_BUF(stream->last_block_hash, sizeof(stream->last_block_hash));

    // Sign the block
    return crypto_sign_block();
}