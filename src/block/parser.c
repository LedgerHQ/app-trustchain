#include "parser.h"
#include "../common/tlv.h"

int parse_block_header(buffer_t *data, block_header_t *out) {
    tlv_t tlv;
    size_t offset = data->offset;

    // Read version (1 byte)
    if (!tlv_read_next(data, &tlv) || !tlv_read_varint_u8(&tlv, &out->version)) {
        return -1;
    }

    // Read parent hash
    if (!tlv_read_next(data, &tlv) || !tlv_read_hash(&tlv, out->parent)) {
        return -1;
    }

    // Read issuer public key
    if (!tlv_read_next(data, &tlv) || !tlv_read_pubkey(&tlv, out->issuer)) {
        return -1;
    }

    // Read command length (1 byte)
    if (!tlv_read_next(data, &tlv) || !tlv_read_varint_u8(&tlv, &out->length)) {
        return -1;
    }

    return data->offset - offset;
}