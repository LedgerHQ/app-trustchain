#include "tlv.h"
#include "constants.h"
#include <string.h>
#include <stdio.h>
#include "../debug.h"

bool tlv_read_next(buffer_t *buffer, tlv_t *tlv) {
    if (!buffer_can_read(buffer, 2)) {
        DEBUG_PRINT("Cannot read TLV header\n");
        return false;
    }

    buffer_read_u8(buffer, &tlv->type);
    buffer_read_u8(buffer, &tlv->length);

    if (!buffer_can_read(buffer, tlv->length)) {
        DEBUG_PRINT("Cannot read TLV value\n");
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

bool tlv_read_varint_u16(tlv_t *tlv, uint16_t *out) {
    if (tlv->type != TLV_TYPE_VARINT || tlv->length != sizeof(uint16_t)) {
        return false;
    }
    buffer_t buffer = {.ptr = tlv->value, .size = tlv->length, .offset = 0};
    return buffer_read_u16(&buffer, out, BE);
}

bool tlv_read_varint_u32(tlv_t *tlv, uint32_t *out) {
    if (tlv->type != TLV_TYPE_VARINT || tlv->length != sizeof(uint32_t)) {
        return false;
    }
    buffer_t buffer = {.ptr = tlv->value, .size = tlv->length, .offset = 0};
    return buffer_read_u32(&buffer, out, BE);
}

bool tlv_read_hash(tlv_t *tlv, uint8_t *out) {
    if (tlv->type != TLV_TYPE_HASH || tlv->length > HASH_LEN) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}

bool tlv_read_pubkey(tlv_t *tlv, uint8_t *out) {
    if (tlv->type != TLV_TYPE_PUBKEY || tlv->length > MEMBER_KEY_LEN) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}

bool tlv_read_bytes(tlv_t *tlv, uint8_t *out, size_t out_size) {
    if (tlv->type != TLV_TYPE_BYTES || tlv->length > out_size) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}

bool tlv_read_string(tlv_t *tlv, char *out, size_t out_size) {
    if (tlv->type != TLV_TYPE_STRING || tlv->length >= out_size) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    out[tlv->length] = '\0';
    return true;
}

bool tlv_read_signature(tlv_t *tlv, uint8_t *out, size_t out_size) {
    if (tlv->type != TLV_TYPE_SIG || tlv->length > out_size) {
        return false;
    }
    memcpy(out, tlv->value, tlv->length);
    return true;
}