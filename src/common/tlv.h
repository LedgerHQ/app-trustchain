#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

#include "buffer.h"

typedef struct {
    uint8_t type;
    uint8_t length;
    const uint8_t *value;
} tlv_t;

typedef enum {
    // General purpose types
    TLV_TYPE_NULL = 0x00,
    TLV_TYPE_VARINT = 0x01,
    TLV_TYPE_HASH = 0x02,
    TLV_TYPE_SIG = 0x03,
    TLV_TYPE_STRING = 0x04,
    TLV_TYPE_BYTES = 0x05,
    TLV_TYPE_PUBKEY = 0x06,

    // Command types
    TLV_TYPE_CREATE_GROUP = 0x10,
    TLV_TYPE_ADD_MEMBER = 0x11,
    TLV_TYPE_PUBLISH_KEY = 0x12,
    TLV_TYPE_EDIT_MEMBER = 0x14,
    TLV_TYPE_REVOKE_KEY = 0x15,

    // Aggreement protocols
    TLV_TYPE_DEFAULT_AGGREEMENT = 0x60,

    // Key descriptions
    TLV_TYPE_DEFAULT_KEY_DESC = 0x40,

} tlv_type_t;

/**
 * Read next TLV from buffer.
*/
bool tlv_read_next(buffer_t *buffer, tlv_t *tlv);

bool tlv_read_varint_u8(tlv_t *tlv, uint8_t *out);

bool tlv_read_varint_u32(tlv_t *tlv, uint32_t *out);

bool tlv_read_hash(tlv_t *tlv, uint8_t *out);

bool tlv_read_pubkey(tlv_t *tlv, uint8_t *out);

bool tlv_read_bytes(tlv_t *tlv, uint8_t *out, size_t out_size);

bool tlv_read_string(tlv_t *tlv, char *out, size_t out_size);

bool tlv_read_signature(tlv_t *tlv, uint8_t *out, size_t out_size);