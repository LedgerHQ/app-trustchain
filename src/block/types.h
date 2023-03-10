#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "../constants.h"

typedef struct {
    uint8_t version;                // Protocol version of the block
    uint8_t parent[HASH_LEN];       // Hash of the parent block
    uint8_t issuer[MEMBER_KEY_LEN]; // Issuer of the block
    uint8_t length;                 // Number of instruction in the block
} block_header_t;