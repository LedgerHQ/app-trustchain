#include "block_parser.h"
#include "../common/tlv.h"

int parse_block_header(buffer_t *data, block_header_t *out) {
    tlv_t tlv;
    size_t offset = data->offset;

    // Read version (1 byte)
    if (!tlv_read_next(data, &tlv) || !tlv_read_varint_u8(&tlv, &out->version)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read parent hash
    if (!tlv_read_next(data, &tlv) || !tlv_read_hash(&tlv, out->parent)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read issuer public key
    if (!tlv_read_next(data, &tlv) || !tlv_read_pubkey(&tlv, out->issuer)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read command length (1 byte)
    if (!tlv_read_next(data, &tlv) || !tlv_read_varint_u8(&tlv, &out->length)) {
        return BP_UNEXPECTED_TLV;
    }

    return data->offset - offset;
}

static int parse_encryption_description(tlv_t *data, encryption_description_t *out) {
    tlv_t tlv;
    out->type = data->type;
    buffer_t buffer = {.ptr = data->value, .size = data->length, .offset = 0};
    switch (data->type) {
        case XSALSA20POLY305:
            if (!tlv_read_next(&buffer, &tlv) ||
                !tlv_read_varint_u8(&tlv, &out->description.xsalsa20poly305.key_size)) {
                return BP_UNEXPECTED_TLV;
            }
            if (!tlv_read_next(&buffer, &tlv) ||
                !tlv_read_varint_u8(&tlv, &out->description.xsalsa20poly305.nonce_size)) {
                return BP_UNEXPECTED_TLV;
            }
            break;
        default:
            return BP_UNKNOWN_ENCRYPTION_DESCRIPTION;
    }
    return 0;
}

static int parse_agreement_description(tlv_t *data, agreement_description_t *out) {
    out->type = data->type;
    switch (data->type) {
        case SECP256K1_AES:
            return 0;
        default:
            return BP_UNKNOWN_AGREEMENT_DESCRIPTION;
    }
}

static int parse_create_group_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv;
    int status;

    // Read the topic
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MAX_TOPIC_LEN) {
        return BP_OVERSIZED_FIELD;
    }
    tlv_read_bytes(&tlv, out->command.create_group.topic, MAX_TOPIC_LEN);

    // Read encryption description
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    status = parse_encryption_description(&tlv, &(out->command.create_group.encryption));
    if (status < 0) {
        return status;
    }
    // Read aggreement description
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    status = parse_agreement_description(&tlv, &(out->command.create_group.agreement));
    return status;
}

static int parse_add_member_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv;

    // Read member name
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MAX_NAME_LEN) {
        return BP_OVERSIZED_FIELD;
    }

    tlv_read_string(&tlv, out->command.add_member.name, sizeof(out->command.add_member.name));

    // Read member public key
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    if (tlv.length > MEMBER_KEY_LEN) {
        return BP_OVERSIZED_FIELD;
    }
    tlv_read_pubkey(&tlv, out->command.add_member.public_key);

    // Read member permissions
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_varint_u32(&tlv, &out->command.add_member.permissions)) {
        return BP_UNEXPECTED_TLV;
    }

    return 0;
}

static int parse_publish_key_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv;

    // Read encrypted key
    if (!tlv_read_next(data, &tlv) ||
        !tlv_read_bytes(&tlv, out->command.publish_key.key, MAX_ENCRYPTED_KEY_LEN)) {
        return BP_UNEXPECTED_TLV;
    }

    out->command.publish_key.key_size = tlv.length;

    // Read recipient public key
    if (!tlv_read_next(data, &tlv) || !tlv_read_pubkey(&tlv, out->command.publish_key.recipient)) {
        return BP_UNEXPECTED_TLV;
    }

    // Read key version
    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }
    out->command.publish_key.null_version = tlv.type == TLV_TYPE_NULL;
    if (!out->command.publish_key.null_version) {
        tlv_read_hash(&tlv, out->command.publish_key.version);
    }

    return 0;
}

int parse_block_command(buffer_t *data, block_command_t *out) {
    tlv_t tlv;
    size_t offset = data->offset;
    int read = 0;

    if (!tlv_read_next(data, &tlv)) {
        return -1;
    }

    buffer_t commandBuffer = {.ptr = tlv.value, .offset = 0, .size = tlv.length};

    out->type = tlv.type;
    switch (tlv.type) {
        case COMMAND_CREATE_GROUP:
            read = parse_create_group_command(&commandBuffer, out);
            break;
        case COMMAND_ADD_MEMBER:
            read = parse_add_member_command(&commandBuffer, out);
            break;
        case COMMAND_PUBLISH_KEY:
            read = parse_publish_key_command(&commandBuffer, out);
            break;
        default:
            return BP_ERROR_UNKNOWN_COMMAND;
            break;
    }
    return read < 0 ? read : data->offset - offset;
}

int parse_block_signature(buffer_t *data, uint8_t *out, size_t out_len) {
    tlv_t tlv;
    size_t offset = data->offset;
    int status;

    if (!tlv_read_next(data, &tlv)) {
        return BP_UNEXPECTED_TLV;
    }

    if (tlv.length > MAX_DER_SIG_LEN) {
        return BP_OVERSIZED_FIELD;
    }

    status = tlv_read_signature(&tlv, out, out_len) ? 0 : BP_UNEXPECTED_TLV;
    return status >= 0 ? data->offset - offset : status;
}