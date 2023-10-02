#define WEAK 
#include "signer.h"
#include "block_parser.h"
#include <string.h>
#include "cx.h"
#include "crypto.h"
#include "../debug.h"
#include "io.h"
#include "../trusted_io.h"
#include "block_hasher.h"
#include "trusted_properties.h"
#include "../globals.h"
#include "bip32.h"
#include "../common/bip32_derivation.h"
#include "sw.h"

int signer_init(signer_ctx_t *signer) {
    crypto_digest_init(&signer->digest);
    return SP_OK;
}

void signer_reset() {
    DEBUG_PRINT("RESET SIGNER\n");
    explicit_bzero(&G_context.signer_info, sizeof(G_context.signer_info));
    explicit_bzero(&G_context.stream, sizeof(G_context.stream));
}

static bool signer_verify_parent_hash(stream_ctx_t *stream, uint8_t *parent_hash) {
    return memcmp(stream->last_block_hash, parent_hash, HASH_LEN) == 0;
}

int signer_parse_block_header(signer_ctx_t *signer, stream_ctx_t *stream, buffer_t *data) {
    (void) signer;
    // Parse the block header
    block_header_t block_header;
    int err = parse_block_header(data, &block_header);

    if (!err) {
        return err;
    }
    if (block_header.length == 0) {
        signer_reset();
        return BS_EMPTY_BLOCK;
    }

    // Verify the parent is set to the current block hash (if stream is created)

    if (stream->is_created && !signer_verify_parent_hash(stream, block_header.parent)) {
        DEBUG_PRINT("INVALID PARENT HASH\n");
        DEBUG_LOG_BUF("EXPECTED HASH: ", stream->last_block_hash, HASH_LEN);
        DEBUG_LOG_BUF("RECEIVED HASH: ", block_header.parent, HASH_LEN);
        return BS_INVALID_PARENT_HASH;
    }

    // Set the block issuer
    memcpy(block_header.issuer, stream->device_public_key, MEMBER_KEY_LEN);

    // Set block count in the signer
    signer->command_count = block_header.length;

    // Digest block header
    block_hash_header(&block_header, &signer->digest);
    return 0;
}

static int signer_inject_seed(signer_ctx_t *signer, block_command_t *command) {
    (void) signer;
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t public_key;
    uint8_t xpriv[64];
    uint8_t secret[32];
    buffer_t buffer;
    int ret = 0;

    // Generate private key
    ret = crypto_generate_pair(&public_key, &private_key);
    if (ret != 0) {
        signer_reset();
        return ret;
    }

    // Generate chain code
    cx_trng_get_random_data(xpriv + 32, 32);

    // Create ephemeral ECDH
    ret = crypto_ephemeral_ecdh(G_context.stream.device_public_key,
                                command->command.seed.ephemeral_public_key,
                                secret);
    if (ret != 0) {
        signer_reset();
        return ret;
    }

    // Generate IV
    cx_trng_get_random_data(command->command.seed.initialization_vector,
                            sizeof(command->command.seed.initialization_vector));

    // Write private key in xpriv buffer
    memcpy(xpriv, private_key.d, sizeof(private_key.d));

    explicit_bzero(&private_key, sizeof(private_key));
    // Encrypt xpriv
    DEBUG_LOG_BUF("XPRIV (SEED): ", xpriv, sizeof(xpriv));
    ret = crypto_encrypt(secret,
                         sizeof(secret),
                         xpriv,
                         sizeof(xpriv),
                         command->command.seed.initialization_vector,
                         command->command.seed.encrypted_xpriv,
                         sizeof(command->command.seed.encrypted_xpriv),
                         false);
    if (ret < 0) {
        signer_reset();
        explicit_bzero(&xpriv, sizeof(xpriv));
        return ret;
    }
    command->command.seed.encrypted_xpriv_size = sizeof(command->command.seed.encrypted_xpriv);

    // Compress and save group key
    crypto_compress_public_key(public_key.W, command->command.seed.group_public_key);

    // Push trusted properties
    // - push encrypted xpriv
    buffer.ptr = command->command.seed.encrypted_xpriv;
    buffer.size = sizeof(command->command.seed.encrypted_xpriv);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_XPRIV, &buffer);
    if (ret != 0) {
        signer_reset();
        explicit_bzero(&xpriv, sizeof(xpriv));
        return ret;
    }

    // - push ephemeral public key
    buffer.ptr = command->command.seed.ephemeral_public_key;
    buffer.size = sizeof(command->command.seed.ephemeral_public_key);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_EPHEMERAL_PUBLIC_KEY, &buffer);
    if (ret != 0) {
        signer_reset();
        explicit_bzero(&xpriv, sizeof(xpriv));
        return ret;
    }

    // - push initialization vector
    buffer.ptr = command->command.seed.initialization_vector;
    buffer.size = sizeof(command->command.seed.initialization_vector);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_COMMAND_IV, &buffer);
    if (ret != 0) {
        signer_reset();
        explicit_bzero(&xpriv, sizeof(xpriv));
        return ret;
    }

    // - push group key
    buffer.ptr = command->command.seed.group_public_key;
    buffer.size = sizeof(command->command.seed.group_public_key);
    buffer.offset = 0;
    ret = io_push_trusted_property(TP_GROUPKEY, &buffer);
    if (ret != 0) {
        signer_reset();
        explicit_bzero(&xpriv, sizeof(xpriv));
        return ret;
    }

    // Set the shared secret in the stream
    memcpy(G_context.stream.shared_secret, xpriv, sizeof(xpriv));
    G_context.stream.shared_secret_len = sizeof(xpriv);

    explicit_bzero(&xpriv, sizeof(xpriv));

    // User approval
    ui_display_add_seed_command();

    return ret < 0 ? ret : 0;
}

int add_seed_callback(bool confirm) {
    if (confirm) {
        io_send_trusted_property(SW_OK);
    }
    else {
        io_send_sw(SW_DENY);
    }
    explicit_bzero(G_context.stream.shared_secret, G_context.stream.shared_secret_len);

    return 0;
}

static int signer_inject_derive(signer_ctx_t *signer, block_command_t *command) {
    (void) signer;
    int err = SP_OK;
    uint8_t xpriv[64];
    uint8_t secret[32];
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t public_key;
    uint8_t raw_public_key[65];
    buffer_t buffer;
    
    DEBUG_PRINT("INJECT DERIVE\n");
    // If the shared secret is not set, return an error
    if (G_context.stream.shared_secret_len == 0) {
        return SP_ERR_INVALID_STATE;
    }
    DEBUG_PRINT("INJECT DERIVE 1\n");
    // Check the derivation path is valid
    if (!bip32_path_is_hardened(command->command.derive.path, command->command.derive.path_len)) {
        // Only accept hardened derivations
        return SP_ERR_INVALID_STREAM;
    }
    DEBUG_PRINT("INJECT DERIVE 2\n");
    // Derive the xpriv with the derivation path
    err = bip32_derive_xpriv_to_path(G_context.stream.shared_secret,
                                     G_context.stream.shared_secret + PRIVATE_KEY_LEN,
                                     command->command.derive.path,
                                     command->command.derive.path_len,
                                     xpriv,
                                     xpriv + PRIVATE_KEY_LEN);
    if (err != SP_OK) {
        return err;
    }
    DEBUG_PRINT("INJECT DERIVE 3\n");
    // Generate IV
    cx_trng_get_random_data(command->command.derive.initialization_vector, IV_LEN);

    // Perform ECDHE
    err = crypto_ephemeral_ecdh(G_context.stream.device_public_key,
                                command->command.derive.ephemeral_public_key,
                                secret);
    if (err != 0)
        return err;
    DEBUG_PRINT("INJECT DERIVE 4\n");
    // Encrypt the xpriv with the shared secret
    err = crypto_encrypt(secret,
                         sizeof(secret),
                         xpriv,
                         sizeof(xpriv),
                         command->command.derive.initialization_vector,
                         command->command.derive.encrypted_xpriv,
                         sizeof(command->command.derive.encrypted_xpriv),
                         false);
    if (err < 0) return err;
    command->command.derive.encrypted_xpriv_size = sizeof(command->command.derive.encrypted_xpriv);
    DEBUG_PRINT("INJECT DERIVE 5\n");
    // Compute public key from xpriv
    crypto_init_private_key(xpriv, &private_key);
    crypto_init_public_key(&private_key, &public_key, raw_public_key + 1);
    raw_public_key[0] = 0x04;
    crypto_compress_public_key(raw_public_key, command->command.derive.group_public_key);

    // User approval
    // TODO implement user approval

    // Set the derived xpriv in the stream
    memcpy(G_context.stream.shared_secret, xpriv, sizeof(xpriv));
    G_context.stream.shared_secret_len = sizeof(xpriv);

    explicit_bzero(xpriv, sizeof(xpriv));
    explicit_bzero(&private_key, sizeof(private_key));
    DEBUG_PRINT("INJECT DERIVE 6\n");
    // Push trusted properties
    // - push encrypted xpriv
    buffer.ptr = command->command.derive.encrypted_xpriv;
    buffer.size = sizeof(command->command.derive.encrypted_xpriv);
    buffer.offset = 0;
    err = io_push_trusted_property(TP_XPRIV, &buffer);
    if (err != 0) return err;
    // - push ephemeral public key
    buffer.ptr = command->command.derive.ephemeral_public_key;
    buffer.size = sizeof(command->command.derive.ephemeral_public_key);
    buffer.offset = 0;
    err = io_push_trusted_property(TP_EPHEMERAL_PUBLIC_KEY, &buffer);
    if (err != 0) return err;
    DEBUG_PRINT("INJECT DERIVE 7\n");
    // - push initialization vector
    buffer.ptr = command->command.derive.initialization_vector;
    buffer.size = sizeof(command->command.derive.initialization_vector);
    buffer.offset = 0;
    err = io_push_trusted_property(TP_COMMAND_IV, &buffer);
    if (err != 0) return err;
    DEBUG_PRINT("INJECT DERIVE 8\n");
    // - push group key
    buffer.ptr = command->command.derive.group_public_key;
    buffer.size = sizeof(command->command.derive.group_public_key);
    buffer.offset = 0;
    err = io_push_trusted_property(TP_GROUPKEY, &buffer);
    if (err != 0) return err;

    return SP_OK;
}

static int signer_inject_add_member(signer_ctx_t *signer, block_command_t *command) {
    (void) signer;
    uint8_t buffer[TP_BUFFER_SIZE_NEW_MEMBER];
    buffer_t trusted_property = {.ptr = buffer, .size = sizeof(buffer), .offset = 0};

    // Ask user approval and return the command as trusted property

    // User approval
    // TODO implement user approval

    // Push trusted property

    memcpy(G_context.stream.trusted_member.member_key,
           command->command.add_member.public_key,
           MEMBER_KEY_LEN);
    G_context.stream.trusted_member.owns_key = 0;
    G_context.stream.trusted_member.permissions = command->command.add_member.permissions;
    serialize_trusted_member(&G_context.stream.trusted_member, buffer, sizeof(buffer));
    return io_push_trusted_property(TP_NEW_MEMBER, &trusted_property);
}

static int signer_inject_publish_key(signer_ctx_t *signer, block_command_t *command) {
    (void) signer;
    uint8_t buffer[TP_BUFFER_SIZE_NEW_MEMBER];
    buffer_t trusted_property = {.ptr = buffer, .size = sizeof(buffer), .offset = 0};
    int err;
    uint8_t secret[32];

    // If trusted member don't match the an error
    if (memcmp(G_context.stream.trusted_member.member_key,
               command->command.publish_key.recipient,
               MEMBER_KEY_LEN) != 0) {
        DEBUG_PRINT("Trusted member don't match\n");
        return BS_INVALID_STATE;
    }

    // If we don't have the xpriv, return an error
    if (G_context.stream.shared_secret_len == 0) {
        DEBUG_PRINT("No shared secret\n");
        return BS_INVALID_STATE;
    }

    // Generate IV
    cx_trng_get_random_data(command->command.publish_key.initialization_vector, IV_LEN);

    // Perform ECDHE
    err = crypto_ephemeral_ecdh(command->command.publish_key.recipient,
                                command->command.publish_key.ephemeral_public_key,
                                secret);
    if (err != 0) {
        DEBUG_PRINT("ECDHE failed\n");
        return err;
    }

    // Encrypt xpriv
    DEBUG_LOG_BUF("XPRIV (PUBLISH KEY): ",
                  G_context.stream.shared_secret,
                  G_context.stream.shared_secret_len);
    err = crypto_encrypt(secret,
                         sizeof(secret),
                         G_context.stream.shared_secret,
                         G_context.stream.shared_secret_len,
                         command->command.publish_key.initialization_vector,
                         command->command.publish_key.encrypted_xpriv,
                         sizeof(command->command.publish_key.encrypted_xpriv),
                         false);
    if (err < 0) {
        DEBUG_PRINT("Encryption failed\n");
        return err;
    }
    command->command.publish_key.encrypted_xpriv_size =
        sizeof(command->command.publish_key.encrypted_xpriv);

    // DEBUG
    DEBUG_LOG_BUF("[] ENCR XPRIV: ",
                  command->command.publish_key.encrypted_xpriv,
                  command->command.publish_key.encrypted_xpriv_size);
    DEBUG_LOG_BUF("[] EPHEMERAL PUBLIC KEY: ",
                  command->command.publish_key.ephemeral_public_key,
                  sizeof(command->command.publish_key.ephemeral_public_key));
    DEBUG_LOG_BUF("[] INITIALIZATION VECTOR: ",
                  command->command.publish_key.initialization_vector,
                  sizeof(command->command.publish_key.initialization_vector));

    // Push trusted properties
    // - push encrypted xpriv
    trusted_property.ptr = command->command.publish_key.encrypted_xpriv;
    trusted_property.size = sizeof(command->command.publish_key.encrypted_xpriv);
    trusted_property.offset = 0;
    err = io_push_trusted_property(TP_XPRIV, &trusted_property);
    if (err != 0) return err;

    // - push ephemeral public key
    trusted_property.ptr = command->command.publish_key.ephemeral_public_key;
    trusted_property.size = sizeof(command->command.publish_key.ephemeral_public_key);
    trusted_property.offset = 0;
    err = io_push_trusted_property(TP_EPHEMERAL_PUBLIC_KEY, &trusted_property);
    if (err != 0) return err;

    // - push initialization vector
    trusted_property.ptr = command->command.publish_key.initialization_vector;
    trusted_property.size = sizeof(command->command.publish_key.initialization_vector);
    trusted_property.offset = 0;
    err = io_push_trusted_property(TP_COMMAND_IV, &trusted_property);
    if (err != 0) return err;

    // Update the trusted member
    G_context.stream.trusted_member.owns_key = 1;
    serialize_trusted_member(&G_context.stream.trusted_member, buffer, sizeof(buffer));
    return io_push_trusted_property(TP_NEW_MEMBER, &trusted_property);
}

int signer_inject_close_stream(signer_ctx_t *signer, block_command_t *command) {
    (void) signer;
    (void) command;

    G_context.stream.is_closed = true;
    return 0;
}

int signer_parse_command(signer_ctx_t *signer, stream_ctx_t *stream, buffer_t *data) {
    block_command_t command;
    DEBUG_PRINT("SIGNER PARSE COMMAND\n");
    if (signer->command_count <= SIGNER_EMPTY_BLOCK) {
        signer_reset();
        return BS_EMPTY_BLOCK;
    }

    int err = parse_block_command(data, &command);

    if (err < 0) {
        DEBUG_PRINT("PARSE COMMAND FAILED\n");
        signer_reset();
        return err;
    }

    // First pass: inject data in command buffer
    io_init_trusted_property();
    switch (command.type) {
        case COMMAND_SEED:
            if (stream->is_created) {
                return BS_INVALID_STATE;
            }
            stream->is_created = true;
            stream->topic_len = command.command.seed.topic_len;
            memcpy(stream->topic, command.command.seed.topic, command.command.seed.topic_len);
            err = signer_inject_seed(signer, &command);
            if (err) {
                signer_reset();
                return err;
            }

            // Digest command
            block_hash_command(&command, &signer->digest);

            signer->parsed_command += 1;
            return 0;
        case COMMAND_ADD_MEMBER:
            if (!stream->is_created) {
                return BS_INVALID_STATE;
            }
            err = signer_inject_add_member(signer, &command);
            break;
        case COMMAND_PUBLISH_KEY:
            err = signer_inject_publish_key(signer, &command);
            break;
        case COMMAND_DERIVE:
            err = signer_inject_derive(signer, &command);
            break;
        case COMMAND_CLOSE_STREAM:
            err = signer_inject_close_stream(signer, &command);
            break;
        default:
            // Force fail if we don't know the command
            err = BP_ERROR_UNKNOWN_COMMAND;
            DEBUG_LOG_BUF("Unknown command: ", (uint8_t *) &command.type, sizeof(command.type));
            break;
    }

    if (err != 0) {
        signer_reset();
        return err;
    }

    // Digest command
    block_hash_command(&command, &signer->digest);

    signer->parsed_command += 1;
    return io_send_trusted_property(SW_OK);
}

int signer_sign_block(signer_ctx_t *signer, stream_ctx_t *stream) {
    // Finalize hashing and put it in stream last block hash

    if (signer->command_count <= SIGNER_EMPTY_BLOCK) {
        signer_reset();
        return BS_EMPTY_BLOCK;
    }

    if (signer->command_count != signer->parsed_command) {
        signer_reset();
        return BS_COMMAND_COUNT_MISMATCH;
    }

    crypto_digest_finalize(&signer->digest,
                           stream->last_block_hash,
                           sizeof(stream->last_block_hash));
    // Sign the block
    return crypto_sign_block();
}