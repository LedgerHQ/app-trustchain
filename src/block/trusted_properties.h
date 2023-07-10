#pragma once

typedef enum {
    TP_IV = 0x00,
    TP_ISSUER_PUBLIC_KEY = 0x01,
    TP_XPRIV = 0x02,
    TP_EPHEMERAL_PUBLIC_KEY = 0x03,
    TP_COMMAND_IV = 0x04,
    TP_GROUPKEY = 0x05,
    TP_NEW_MEMBER = 0x06
} tp_type_t;

typedef enum {
    TP_SUCCESS = 0x00,
    TP_UNKNOWN_COMMAND = -1,
    TP_BUFFER_OVERFLOW = -2,
    TP_FAILED_TO_HASH = -3,
    TP_INVALID_CHECKSUM = -4,
} tp_error_t;

#include "types.h"
#include "../stream/stream.h"
#include "../constants.h"

#define TP_CHECKSUM_LEN 4
#define TP_NONCE_SIZE 4
#define TP_BUFFER_SIZE_NEW_MEMBER (TP_NONCE_SIZE + sizeof(stream_trusted_member_t) + TP_CHECKSUM_LEN)

int serialize_trusted_member(stream_trusted_member_t *member, uint8_t *buffer, size_t buffer_size);
int deserialize_trusted_member(uint8_t *buffer, size_t buffer_size, stream_trusted_member_t *out);

/**
 * Set the trusted member in global context and serialize it in the given buffer
 * 
 * @param[in] member The trusted member to set
 * @param[out] buffer The buffer to serialize the trusted member in (NULL to only set the global context)
 * @param[in] buffer_size The size of the buffer
 * 
 * @return The length of the serialized trusted member or an error code
*/
int set_trusted_member(stream_trusted_member_t *member, uint8_t *buffer, size_t buffer_size);

/**
 * Read the trusted member from the given buffer and set it in global context.
 * 
 * @param[in] buffer The buffer to read the trusted member from
 * @param[in] buffer_size The size of the buffer
 * @param[out] out The trusted member to set (NULL to only set the global context)
 * 
 * @return The length of the serialized trusted member or an error code
*/
int read_and_set_trusted_member(uint8_t *buffer, size_t buffer_size, stream_trusted_member_t *out);