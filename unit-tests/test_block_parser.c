#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>

#include "block/types.h"
#include "block/parser.h"
#include "common/buffer.h"

#include "block/parser.h"

static void hex_to_buffer(const char* hex, buffer_t* buffer) {
    // Transform hex string to uint8_t array
    size_t len = strlen(hex);
    uint8_t* bytes = malloc(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex + i, "%2hhx", &bytes[i / 2]);
    }
    buffer->offset = 0;
    buffer->ptr = bytes;
    buffer->size = len / 2;
}

static void atohex(const uint8_t* bytes, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

static void test_block_header_parse(void** state) {
    (void) state;

    const char* stream =
        "01010102207c6062fa815ae0f1ad57927347888d8d6b7bbf39e76d86a2fab585"
        "17c34ba0100621027fc9b623ad66b548bd139ba2c672f0dad0274edb034a9aa7"
        "d3a3bcb976b23bec010101102c0520c96d450545ff2836204c29af291428a5bf"
        "740304978f5dfb0b4a2614741928514006010118010120600003463044022029"
        "f505efb0cc04f019774eb0f78137b6eb41230b367aae6088150e970bcd62a902"
        "201ab799f400b33c2c2ac0634ec6a00e257be514b7acd646957e38cd371f6ecf"
        "a6";

    const char* expected_parent_hash =
        "7c6062fa815ae0f1ad57927347888d8d6b7bbf39e76d86a2fab58517c34ba010";

    const char* expected_issuer =
        "027fc9b623ad66b548bd139ba2c672f0dad0274edb034a9aa7d3a3bcb976b23bec";

    const int expect_length = 1;

    buffer_t buffer;
    hex_to_buffer(stream, &buffer);

    block_header_t header;
    parse_block_header(&buffer, &header);

    char parent_hash[65];
    atohex(header.parent, 32, parent_hash);

    assert_int_equal(header.version, 1);
    assert_string_equal(parent_hash, expected_parent_hash);

    char issuer[67];
    atohex(header.issuer, 33, issuer);
    assert_string_equal(issuer, expected_issuer);

    assert_int_equal(header.length, expect_length);

    free((void*) buffer.ptr);
}

static void test_block_commands_parse(void** state) {
    (void) state;

    const char* stream =
        "01010102207c6062fa815ae0f1ad57927347888d8d6b7bbf39e76d86a2fab585"
        "17c34ba0100621027fc9b623ad66b548bd139ba2c672f0dad0274edb034a9aa7"
        "d3a3bcb976b23bec010101102c0520c96d450545ff2836204c29af291428a5bf"
        "740304978f5dfb0b4a2614741928514006010118010120600003463044022029"
        "f505efb0cc04f019774eb0f78137b6eb41230b367aae6088150e970bcd62a902"
        "201ab799f400b33c2c2ac0634ec6a00e257be514b7acd646957e38cd371f6ecf"
        "a6";

    const char* expected_topic = "c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a261474192851";

    const char* expected_signature =
        "3044022029f505efb0cc04f019774eb0f78137b6eb41230b367aae6088150e97"
        "0bcd62a902201ab799f400b33c2c2ac0634ec6a00e257be514b7acd646957e38"
        "cd371f6ecfa6";

    buffer_t buffer;
    hex_to_buffer(stream, &buffer);

    // Parse the block header
    block_header_t header;
    int offset = 0;
    offset = parse_block_header(&buffer, &header);
    buffer.offset = offset;  // Offset should be at the begining of a command

    // Parse the command
    block_command_t command;
    parse_block_command(&buffer, &command);

    assert_int_equal(command.type, COMMAND_CREATE_GROUP);
    char topic[65];
    atohex(command.command.create_group.topic, 32, topic);
    assert_string_equal(expected_topic, topic);

    assert_int_equal(command.command.create_group.encryption.type, XSALSA20POLY305);
    assert_int_equal(command.command.create_group.encryption.description.xsalsa20poly305.key_size,
                     0x18);
    assert_int_equal(command.command.create_group.encryption.description.xsalsa20poly305.nonce_size,
                     0x20);

    assert_int_equal(command.command.create_group.agreement.type, SECP256K1_AES);

    // Parse signature
    uint8_t signature[70];
    char sig_hex[140];
    memset((void*) signature, 0, sizeof(signature));
    int t = parse_block_signature(&buffer, signature, sizeof(signature));
    printf("T = %i", t);
    atohex(signature, sizeof(signature), sig_hex);
    assert_string_equal(sig_hex, expected_signature);

    free((void*) buffer.ptr);
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_block_header_parse),
                                       cmocka_unit_test(test_block_commands_parse)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
