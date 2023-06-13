#include "init_signature_flow.h"
#include "../globals.h"
#include "sw.h"
#include "../crypto.h"

int handler_init_signature_flow(buffer_t *cdata) {
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t session_key;

    if (cx_ecfp_generate_pair(CX_CURVE_256K1, &session_key, &private_key, 1) == 0) {
        return io_send_sw(SW_BAD_STATE);
    }
    if (crypto_ecdh(&private_key, cdata->ptr + cdata->offset,  G_context.signer_info.session_encryption_key) < 0) {
        return io_send_sw(SW_BAD_STATE);
    }
    crypto_compress_public_key(&session_key, G_context.signer_info.session_key);
    return io_send_sw(SW_OK);
}