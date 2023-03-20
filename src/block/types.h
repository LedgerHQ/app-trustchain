#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../constants.h"

#ifdef HAVE_SHA256
#include "cx.h"
#endif

typedef struct {
    uint8_t version;                 // Protocol version of the block
    uint8_t parent[HASH_LEN];        // Hash of the parent block
    uint8_t issuer[MEMBER_KEY_LEN];  // Issuer of the block
    uint8_t length;                  // Number of instruction in the block
} block_header_t;

typedef enum {
    COMMAND_CREATE_GROUP = 0x10,
    COMMAND_ADD_MEMBER = 0x11,
    COMMAND_PUBLISH_KEY = 0x12,
    COMMAND_REMOVE_MEMBER = 0x13,
    COMMAND_EDIT_MEMBER = 0x14,
    COMMAND_REVOKE_KEY = 0x15,
    COMMAND_MIGRATE_KEY = 0x16,

    COMMAND_NONE = 0xFF
} block_command_type_t;

typedef enum {
    XSALSA20POLY305 = 0x40,
} encryption_description_type_t;

typedef enum {
    SECP256K1_AES = 0x60,
} agreement_description_type_t;

typedef enum {
    KEY_READER = 0x01,
    KEY_CREATOR = 0x02,
    KEY_REVOKER = 0x04,
    ADD_MEMBER = 0x08,
    REMOVE_MEMBER = 0x16,
    CHANGE_MEMBER_PERMISSIONS = 0x32,
    CHANGE_MEMBER_NAME = 0x64,

    OWNER = (int) 0xFFFFFFFF,
} member_permission_t;

typedef struct {
    uint8_t key_size;
    uint8_t nonce_size;
} encryption_description_xsalsa20poly305_t;

typedef struct {
    encryption_description_type_t type;
    union {
        encryption_description_xsalsa20poly305_t xsalsa20poly305;
    } description;
} encryption_description_t;

typedef struct {
    agreement_description_type_t type;
} agreement_description_t;

typedef struct {
    uint8_t topic[MAX_TOPIC_LEN];
    uint8_t topic_len;
    encryption_description_t encryption;
    agreement_description_t agreement;
} block_command_create_group_t;

typedef struct {
    uint8_t public_key[MEMBER_KEY_LEN];
    uint32_t permissions;
    char name[MAX_NAME_LEN + 1];
} block_command_add_member_t;

typedef struct {
    uint8_t key_size;
    uint8_t key[MAX_ENCRYPTED_KEY_LEN];
    bool null_version;
    uint8_t version[HASH_LEN];
    uint8_t recipient[MEMBER_KEY_LEN];
} block_command_publish_key_t;

typedef struct {
    block_command_type_t type;
    union {
        block_command_create_group_t create_group;
        block_command_add_member_t add_member;
        block_command_publish_key_t publish_key;
    } command;
} block_command_t;

typedef struct {
#ifdef HAVE_SHA256
    cx_sha256_t digest;  // Current block digest
#endif
    uint8_t issuer_pk[MEMBER_KEY_LEN];   // Issuer public key
    uint8_t signature[MAX_DER_SIG_LEN];  /// transaction signature encoded in DER
    uint8_t signature_len;               /// length of transaction signature
    uint8_t v;                           /// parity of y-coordinate of R in ECDSA signature

} signer_ctx_t;