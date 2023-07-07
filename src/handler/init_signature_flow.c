#include "init_signature_flow.h"
#include "../globals.h"
#include "sw.h"
#include "../crypto.h"
#include "debug.h"

int handler_init_signature_flow(buffer_t *cdata) {
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t session_key;
    uint8_t derivation_buffer[65] = {0};
    int ret;

    // Reset the context
    signer_reset();

    // Create session key

    explicit_bzero(&G_context.signer_info, sizeof(G_context.signer_info));

    if (cx_ecfp_generate_pair(CX_CURVE_256K1, &session_key, &private_key, 0) != 0) {
        return io_send_sw(SW_BAD_STATE);
    }
    DEBUG_PRINT("SESSION PRIVATE KEY: ")
    DEBUG_PRINT_BUF(private_key.d, 32)
    if ((ret = crypto_ecdh(&private_key, cdata->ptr + cdata->offset,  G_context.signer_info.session_encryption_key)) != 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(ret);
    }
    ret = crypto_compress_public_key(session_key.W, G_context.signer_info.session_key);

    if (ret != 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(SW_BAD_STATE);
    }

    DEBUG_PRINT("SESSION PUBLIC KEY: ")
    DEBUG_PRINT_BUF(G_context.signer_info.session_key, 33);
    DEBUG_PRINT("SESSION ENCRYPTION KEY: ")
    DEBUG_PRINT_BUF(G_context.signer_info.session_encryption_key, 32);

    // SeedID initialization

    ret = crypto_derive_private_key(&private_key, derivation_buffer, SEED_ID_PATH, SEED_ID_PATH_LEN);
    if (ret != 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(SW_BAD_STATE);
    }

    crypto_init_public_key(&private_key, &session_key, derivation_buffer + 1);
    ret = crypto_compress_public_key(derivation_buffer, G_context.stream.device_public_key);
    if (ret != 0) {
        explicit_bzero(&private_key, sizeof(private_key));
        return io_send_sw(SW_BAD_STATE);
    }
    DEBUG_LOG_BUF("DEVICE PUBLIC KEY: ", G_context.stream.device_public_key, 33);

    explicit_bzero(&private_key, sizeof(private_key));

    G_context.req_type = CONFIRM_BLOCK;

    return io_send_sw(SW_OK);
}