#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "constants.h"
#include "transaction/types.h"
#include "common/bip32.h"

#include "stream/stream.h"
#include "block/signer.h"

#ifdef HAVE_SHA3
#include <cx.h>
#endif

#define ENABLE_DEBUG_COMMANDS

/**
 * Enumeration for the status of IO.
 */
typedef enum {
    READY,     /// ready for new event
    RECEIVED,  /// data received
    WAITING    /// waiting
} io_state_e;

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,     /// version of the application
    GET_APP_NAME = 0x04,    /// name of the application
    GET_PUBLIC_KEY = 0x05,  /// public key of corresponding BIP32 path
    SIGN_TX = 0x06,         /// sign transaction with BIP32 path
    SIGN_BLOCK = 0x07,      /// sign block of a parsed stream
    PARSE_STREAM = 0x08,    /// parse a stream

#ifdef ENABLE_DEBUG_COMMANDS
    GET_SECRET = 0xe8,         /// Get the secret symmetric key of a chain
    GET_SHARED_SECRET = 0xe9,  /// Get the shared secret between the device and another member
#endif
} command_e;

/**
 * Structure with fields of APDU command.
 */
typedef struct {
    uint8_t cla;    /// Instruction class
    command_e ins;  /// Instruction code
    uint8_t p1;     /// Instruction parameter 1
    uint8_t p2;     /// Instruction parameter 2
    uint8_t lc;     /// Length of command data
    uint8_t *data;  /// Command data
} command_t;

/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,     /// No state
    STATE_PARSED,   /// Transaction data parsed
    STATE_APPROVED  /// Transaction data approved
} state_e;

/**
 * Enumeration with user request type.
 */
typedef enum {
    CONFIRM_ADDRESS,      /// confirm address derived from public key
    CONFIRM_TRANSACTION,  /// confirm transaction information
    CONFIRM_BLOCK         /// confirm block signature
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[64];  /// x-coordinate (32), y-coodinate (32)
    uint8_t chain_code[33];      /// for public key derivation
    uint8_t compressed_pk[33];   /// compressed public key
} pubkey_ctx_t;

/**
 * Structure for transaction information context.
 */
typedef struct {
    uint8_t raw_tx[MAX_TRANSACTION_LEN];  /// raw transaction serialized
    size_t raw_tx_len;                    /// length of raw transaction
    transaction_t transaction;            /// structured transaction
    uint8_t m_hash[32];                   /// message hash digest
    uint8_t signature[MAX_DER_SIG_LEN];   /// transaction signature encoded in DER
    uint8_t signature_len;                /// length of transaction signature
    uint8_t v;                            /// parity of y-coordinate of R in ECDSA signature
} transaction_ctx_t;

#define TRUSTCHAIN_PATH_SIZE 4
#define NONCE_SIZE           8

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        pubkey_ctx_t pk_info;       /// public key context
        transaction_ctx_t tx_info;  /// transaction context
        signer_ctx_t signer_info;   /// signer context
    };
    request_type_e req_type;              /// user request
    uint32_t bip32_path[MAX_BIP32_PATH];  /// BIP32 path
    uint8_t bip32_path_len;               /// length of BIP32 path

    stream_ctx_t stream;  /// Stream context

} global_ctx_t;
