#include "init_signature_flow.h"
#include "../globals.h"
#include "sw.h"
#include "../crypto.h"
#include "debug.h"

int handler_init_signature_flow(buffer_t *cdata) {
    // Reset the context
    explicit_bzero(&G_context.signer_info, sizeof(G_context.signer_info));
    explicit_bzero(&G_context.stream, sizeof(G_context.stream));

    // Create session key
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t session_key;

    explicit_bzero(&G_context.signer_info, sizeof(G_context.signer_info));

    if (cx_ecfp_generate_pair(CX_CURVE_256K1, &session_key, &private_key, 0) != 0) {
        return io_send_sw(SW_BAD_STATE);
    }
    DEBUG_PRINT("SESSION PRIVATE KEY: ")
    DEBUG_PRINT_BUF(private_key.d, 32)
    int ret;
    if ((ret = crypto_ecdh(&private_key, cdata->ptr + cdata->offset,  G_context.signer_info.session_encryption_key)) != 0) {
        return io_send_sw(ret);
    }
    crypto_compress_public_key(session_key.W, G_context.signer_info.session_key);

    DEBUG_PRINT("SESSION PUBLIC KEY: ")
    DEBUG_PRINT_BUF(G_context.signer_info.session_key, 33);
    DEBUG_PRINT("SESSION ENCRYPTION KEY: ")
    DEBUG_PRINT_BUF(G_context.signer_info.session_encryption_key, 32);

    G_context.req_type = CONFIRM_BLOCK;

    return io_send_sw(SW_OK);
}