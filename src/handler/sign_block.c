#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"


#include "../sw.h"
#include "../globals.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../common/buffer.h"
#include "../block/block_parser.h"
#include "../block/signer.h"
#include "../helper/send_response.h"

#include "sign_block.h"

int handler_sign_block(buffer_t *cdata, uint8_t mode, bool more) {
    (void) cdata;
    (void) mode;
    (void) more;
    int error;
    G_context.req_type = CONFIRM_BLOCK;

    if (mode == MODE_BLOCK_START) {
        // Initialize the signer
        error = signer_init(&G_context.signer_info, TO_REMOVE_BIP32_PATH, TO_REMOVE_BIP32_PATH_LEN);

        if (error != 0) {
            return io_send_sw(SW_BAD_STATE);
        }

        // Expects to read a block header (version, issuer, parent...)
        error = signer_parse_block_header(&G_context.signer_info, &G_context.stream, cdata);

        if (error != 0) {
            return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
        }

    } else if (mode == MODE_COMMAND_PARSE) {
        error = signer_parse_command(&G_context.signer_info, &G_context.stream, cdata, NULL);
        if (error != 0) {
            return io_send_sw(error);
        }
    } else if (mode == MODE_BLOCK_FINALIZE) {
        error = signer_sign_block(&G_context.signer_info, &G_context.stream);
        if (error != 0) {
            return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
        }
        return helper_send_response_block_signature();
    }

    return io_send_sw(SW_OK);

    /*if (mode == 0) {
        // We start hashing
        cx_keccak_init((cx_sha3_t *)&G_context.keccak256, 256);
    }
    if (mode != 2) {
        cx_hash((cx_hash_t *)&G_context.keccak256,
                0,
                cdata->ptr,
                cdata->size,
                NULL,
                0
        );
        return io_send_sw(SW_OK);
    } else {
        cx_hash((cx_hash_t *)&G_context.keccak256,
                CX_LAST,
                cdata->ptr,
                cdata->size,
                G_context.tx_info.m_hash,
                sizeof(G_context.tx_info.m_hash)
        );
        return io_send_response(&(const buffer_t){.ptr = G_context.tx_info.m_hash, .size = 32,
    .offset = 0}, SW_OK);
    }*/
    // return 0;
}