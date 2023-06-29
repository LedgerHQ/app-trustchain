#include "block_hasher.h"
#include "../common/write.h"
#include "../common/tlv.h"
#include "../debug.h"

static int write_tl(const uint8_t type, const uint8_t length, uint8_t *out) {
    out[0] = type;
    out[1] = length;
    return 2;
}

static int write_u8(const uint8_t value, uint8_t *out) {
    out[0] = value;
    return sizeof(value);
}

static int write_u16(const uint16_t value, uint8_t *out) {
    out[0] = (value >> 8) & 0xFF;
    out[1] = value & 0xFF;
    return sizeof(value);
}

static int write_bytes(const uint8_t *bytes, const uint8_t length, uint8_t *out) {
    for (int i = 0; i < length; i++) {
        out[i] = bytes[i];
    }
    return length;
}

static void write_command_seed(const block_command_t *command, cx_hash_t *digest) {
    uint8_t buffer[2 + 32 + 16 + 32 + 33 + 2 * 6 + 32 + 64];
    int offset = 0;
    
    // Compute encoded data length
    // Topic(16 max) + ProtocolVersion(2) + GroupKey(32) + IV(16) + EncryptedSeed(32) + EphemeralPublicKey(33) + 2 * NumberOfFields
    uint8_t length = command->command.seed.topic_len + 2 + 32 + 16 + 32 + 33 + 2 * 6;

    // Command type and length
    offset += write_tl(command->type, length, buffer + offset);

    // Topic
    offset += write_tl(TLV_TYPE_BYTES, command->command.seed.topic_len, buffer + offset);
    offset += write_bytes(command->command.seed.topic, command->command.seed.topic_len, buffer + offset);

    // Protocol version
    offset += write_tl(TLV_TYPE_VARINT, 2, buffer + offset);
    offset += write_u16(command->command.seed.protocol_version, buffer + offset);

    // Group key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset += write_bytes(command->command.seed.group_public_key, MEMBER_KEY_LEN, buffer + offset);

    // IV
    offset += write_tl(TLV_TYPE_BYTES, sizeof(command->command.seed.initialization_vector), buffer + offset);
    offset += write_bytes(command->command.seed.initialization_vector, sizeof(command->command.seed.initialization_vector), buffer + offset);

    // Encrypted xpriv
    offset += write_tl(TLV_TYPE_BYTES, sizeof(command->command.seed.encrypted_xpriv), buffer + offset);
    offset += write_bytes(command->command.seed.encrypted_xpriv, sizeof(command->command.seed.encrypted_xpriv), buffer + offset);
 
    // Ephemeral public key
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset += write_bytes(command->command.seed.ephemeral_public_key, MEMBER_KEY_LEN, buffer + offset);
    
    buffer[1] = offset - 2; // Set actual length (offset - 2 because offset includes type and length bytes)
    cx_hash(digest, 0, buffer, offset, NULL, 0);
}

int block_hash_header(const block_header_t *header, cx_hash_t *digest) {
    int ret = 0;
    uint8_t buffer[1 + HASH_LEN + MEMBER_KEY_LEN + 1 + 4 * 2];
    int offset = 0;

     // Version
    offset += write_tl(TLV_TYPE_VARINT, 1, buffer + offset);
    offset += write_u8(header->version, buffer + offset);

    // Parent
    offset += write_tl(TLV_TYPE_HASH, HASH_LEN, buffer + offset);
    offset += write_bytes(header->parent, HASH_LEN, buffer + offset);

    // Issuer
    offset += write_tl(TLV_TYPE_PUBKEY, MEMBER_KEY_LEN, buffer + offset);
    offset += write_bytes(header->issuer, MEMBER_KEY_LEN, buffer + offset);

    // Length
    offset += write_tl(TLV_TYPE_VARINT, 1, buffer + offset);
    offset += write_u8(header->length, buffer + offset);
    BEGIN_TRY {
        TRY {
           cx_hash(digest, 0, buffer, offset, NULL, 0);
        }
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
            return ret;
        }
    } END_TRY;
}

int block_hash_command(const block_command_t *command, cx_hash_t *digest) {
    int ret = 0;
    BEGIN_TRY {
        TRY {
        switch (command->type)
            {
                case COMMAND_SEED:
                    write_command_seed(command, digest);
                    break;
            }
        } 
        CATCH_OTHER(e) {
            ret = e;
        }
        FINALLY {
            
        }
    } END_TRY;
    return ret;
}