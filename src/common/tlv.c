#include "tlv.h"
#include "constants.h"
#include <string.h>

bool tlv_read_next(buffer_t *buffer, tlv_t *tlv) {
    if (!buffer_can_read(buffer, 2)) {
        return false;
    }

    buffer_read_u8(buffer, &tlv->type);
    buffer_read_u8(buffer, &tlv->length);

    if (!buffer_can_read(buffer, tlv->length)) {
        return false;
    }
    tlv->value = buffer->ptr + buffer->offset;
    buffer_seek_cur(buffer, tlv->length);
    return true;
}

bool tlv_read_varint_u8(tlv_t *tlv, uint8_t *out) {
    if (tlv->type != TLV_TYPE_VARINT || tlv->length != 1) {
        return false;
    }
    *out = tlv->value[0];
    return true;
}

bool tlv_read_hash(tlv_t *tlv, uint8_t *out) {
    if (tlv->type != TLV_TYPE_HASH || tlv->length != HASH_LEN) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}

bool tlv_read_pubkey(tlv_t *tlv, uint8_t *out) {
    if (tlv->type != TLV_TYPE_PUBKEY || tlv->length != MEMBER_KEY_LEN) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}