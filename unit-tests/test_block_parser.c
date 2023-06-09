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
#include "block/block_parser.h"
#include "common/buffer.h"
#include <stdio.h>

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

typedef struct {
    const char*     topic;
    const uint16_t  version;
    const char*     group_key;
    const char*     iv;
    const char*     xpriv;
    const char*     ephemeral_public_key;
} expected_seed_command_t;

static int assert_seed_command(buffer_t *buffer, expected_seed_command_t expectation, block_command_t *out) {
    int offset;
    block_command_t command;
    offset = parse_block_command(buffer, &command);
    assert_return_code(offset, 0);

    assert_int_equal(command.type, COMMAND_SEED);
    char topic[65];
    atohex(command.command.seed.topic, 32, topic);
    assert_string_equal(expectation.topic, topic);
    char group_key[67];
    atohex(command.command.seed.group_public_key, 33, group_key);
    assert_string_equal(expectation.group_key, group_key);
    char ephemeral_public_key[67];
    atohex(command.command.seed.ephemeral_public_key, 33, ephemeral_public_key);
    assert_string_equal(expectation.ephemeral_public_key, ephemeral_public_key);
    char encrypted_xpriv[163];
    atohex(command.command.seed.encrypted_xpriv, 81, encrypted_xpriv);
    assert_string_equal(expectation.xpriv, encrypted_xpriv);

    assert_int_equal(command.command.seed.protocol_version, expectation.version);

    if (out != NULL) {
        *out = command;
    }
    return offset;
}

typedef struct {
    const char *name;
    const char *public_key;
    const int permissions;
} expected_add_member_t;

static int assert_add_member_command(buffer_t *buffer, expected_add_member_t expectation, command_t *out) {
    int offset;
    block_command_t command;
    offset = parse_block_command(buffer, &command);
    assert_return_code(offset, 0);

    assert_int_equal(command.type, COMMAND_ADD_MEMBER);
    assert_string_equal(expectation.name, command.command.add_member.name);

    assert_int_equal(command.type, COMMAND_SEED);
    if (out != NULL) {
        *out = command;
    }
    return offset;
}

static void test_block_header_parse(void** state) {
    (void) state;

    const char* stream =
        "01010102207f1781aef1d65ae5f6f48c4fee048090e008e0c29ebd30d4bc324f53b1f1"
        "919c0621021026de3be0412de9746be1a65b9e742d70504e10fb696ec98c958d1aae92"
        "d89c01010110d30520c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a"
        "2614741928510104000000000621022713c32352fceb1e3a4632a3cabc066cc00aa49b"
        "cfc0697d2bd6445dc6d71a7505107a307892d8835c0de6704c3a4f620ad4055110ecf2"
        "14c01f9daa8abb28bca2c01b968d000350158dd0153ec86ddab34a4be666ad2ee5ccd2"
        "12a4103bfd1001583b30714d21b429b94095cded2be403fb1324d81e35d3570b249f87"
        "f658eeb628f517c906210399ddd9c31422c2c82d8c04d5f0a05103f4db23a84ac913f4"
        "ce9cefcb5cff31000346304402207a789d70d2ce923fd28c427b4a4aa3ea03f548f7de"
        "35340ed6dc21a310edb45c02203ad3b54d750fa35073da52cf0f49512424a80dd676ee"
        "b19bc155e5b9623204b9";

    const char* expected_parent_hash =
        "7f1781aef1d65ae5f6f48c4fee048090e008e0c29ebd30d4bc324f53b1f1919c";

    const char* expected_issuer =
        "021026de3be0412de9746be1a65b9e742d70504e10fb696ec98c958d1aae92d89c";

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
        "01010102202940ba81ac48dd8d25a1f4cd1fdc5fcba26e5088a1b212d6019523a069df"
        "d47a0621029af540924fc4916b1db891464d654a4addcaa8302c29afb3e5c006c6e653"
        "657b01010110d10520c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a"
        "261474192851010200000621021f181f623bf36e1b0e21d7afb098c0b0448174d34340"
        "46eaa442151f7c1e93ab051085301091ca76f51a20cfe91480ce321f0551104f686df7"
        "2bac900126676b83f1cc59a372c3d3495a89e0f97ef90245be1a93fb1139eb1cbf00ca"
        "6d6594b5c7832cb87a5a73e45556abb51dec9ac7039f58183642b2e64ba4d8cfcef377"
        "7c70fbd0a57b06210383172c44268387721dc54a8dccddce995f04a212b4c8c92d1eb9"
        "244f5dc0c28d03473045022100e1a2e26e5f8eab4ba9520eb57cc2264d6aa77793e666"
        "e5d3b10288e72f94fd9c02206f1c2c2b4ee497378400a1d31fcdf3493432e256594acf"
        "653c508f5af1dfb8af";
    const char* expected_topic = "c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a261474192851";

    const char* expected_signature =
        "3045022100e1a2e26e5f8eab4ba9520eb57cc2264d6aa77793e666e5d3b10288e72f94"
        "fd9c02206f1c2c2b4ee497378400a1d31fcdf3493432e256594acf653c508f5af1dfb8af";

    const char* expected_group_key =
        "021f181f623bf36e1b0e21d7afb098c0b0448174d3434046eaa442151f7c1e93ab";

    const char* expected_ephemeral_public_key =
        "0383172c44268387721dc54a8dccddce995f04a212b4c8c92d1eb9244f5dc0c28d";

    const char* expected_encrypted_xpriv =
        "104f686df72bac900126676b83f1cc59a372c3d3495a89e0f97ef90245be1a93fb1139"
        "eb1cbf00ca6d6594b5c7832cb87a5a73e45556abb51dec9ac7039f58183642b2e64ba4"
        "d8cfcef3777c70fbd0a57b";

    const char* expected_initialization_vector =
        "85301091ca76f51a20cfe91480ce321f";


    buffer_t buffer;
    hex_to_buffer(stream, &buffer);

    // Parse the block header
    block_header_t header;
    int offset = 0;
    offset = parse_block_header(&buffer, &header);
    buffer.offset = offset;  // Offset should be at the begining of a command

    // Parse the command
    expected_seed_command_t seed_expectations = {
        .topic = expected_topic,
        .group_key = expected_group_key,
        .ephemeral_public_key = expected_ephemeral_public_key,
        .xpriv = expected_encrypted_xpriv,
        .iv = expected_initialization_vector,
        .version = 0,
    };
    assert_seed_command(&buffer, seed_expectations, NULL);

    // Parse signature
    uint8_t signature[71];
    char sig_hex[143];
    memset((void*) signature, 0, sizeof(signature));

    parse_block_signature(&buffer, signature, sizeof(signature));
    atohex(signature, sizeof(signature), sig_hex);
    assert_string_equal(sig_hex, expected_signature);

    free((void*) buffer.ptr);
}

static void test_stream_parse(void** state) {
    (void) state;
    const char* stream =
        "0101010220ef6a7f0bc8c0c1e99188d7a56efbccfb7f4cec54b19ddd62b098a7"
        "26672e89f6062103cb2c1145472029321716e195b7085a4a5e5c2e9ae0e4b849"
        "e803d9f3468339e0010101102c0520c96d450545ff2836204c29af291428a5bf"
        "740304978f5dfb0b4a2614741928514006010118010120600003463044022017"
        "27bc4ccaca9698359eb452f62a0e260f7c4b39dc82e89a4de3134614a9b66d02"
        "201b84cc12c90b7a95550f529be70653c01a39c155aba08c1b48a17f5abb971f"
        "6a0101010220d420e11563ce641ea0e759ef2cf452af2aab1f52d84f4a62f3d9"
        "20a35dc7dbcf062103cb2c1145472029321716e195b7085a4a5e5c2e9ae0e4b8"
        "49e803d9f3468339e0010102112e0403426f62062103deb34b832df74a6b8b0f"
        "b2f879ad322ef3c38750d19620087cc538fdf2847e4501040000000112770530"
        "dd741499e049f2b34728251a8f3c65d473caeee81f74eb758254f6b8e142f205"
        "b46cad2b05e7a9951fa1d10145f6ec6c062103deb34b832df74a6b8b0fb2f879"
        "ad322ef3c38750d19620087cc538fdf2847e450220d420e11563ce641ea0e759"
        "ef2cf452af2aab1f52d84f4a62f3d920a35dc7dbcf0346304402207c9581752c"
        "34f4bebca2dbb70ecfbeeb09f900a7aed4c2f9566f1444ad10aef4022036797f"
        "e63d0ba213e0ce3de7da6d5e61cf70b821700d5f8db2fe09c3de8578f3010101"
        "0220e243a04d348688e5d34d80019727b3a698f9034a804d544feed0102c72f7"
        "1672062103cb2c1145472029321716e195b7085a4a5e5c2e9ae0e4b849e803d9"
        "f3468339e001010211320407436861726c6965062103d47c01b17297214f1f33"
        "56a10ae9c88bbe223ccdd08895c65885cb2185389a4801040000000112770530"
        "84ca9427bf0362ba24dec427f048b799d81eaf80f36be3d3502cd822d02d6946"
        "c66248615828af7361c65ac9d00fbda8062103d47c01b17297214f1f3356a10a"
        "e9c88bbe223ccdd08895c65885cb2185389a480220d420e11563ce641ea0e759"
        "ef2cf452af2aab1f52d84f4a62f3d920a35dc7dbcf0347304502210082f2c223"
        "4b22e9318b3457e294bbf879f1f61c276170d5bb997c1704bc2a19f102205362"
        "9538276ade5cbeb2056ab85339b903f2159e0e1e00493cbf06efa5b33c39";

    const int expected_block_count = 3;

    const char* expected_issuers[] = {
        "03cb2c1145472029321716e195b7085a4a5e5c2e9ae0e4b849e803d9f3468339e0",
        "03cb2c1145472029321716e195b7085a4a5e5c2e9ae0e4b849e803d9f3468339e0",
        "03cb2c1145472029321716e195b7085a4a5e5c2e9ae0e4b849e803d9f3468339e0"};

    const char* expected_parents[] = {
        "ef6a7f0bc8c0c1e99188d7a56efbccfb7f4cec54b19ddd62b098a726672e89f6",
        "d420e11563ce641ea0e759ef2cf452af2aab1f52d84f4a62f3d920a35dc7dbcf",
        "e243a04d348688e5d34d80019727b3a698f9034a804d544feed0102c72f71672"};

    const char* expected_signatures[] = {
        "304402201727bc4ccaca9698359eb452f62a0e260f7c4b39dc82e89a4de3134614a9b66d02201b84cc12c90b7a"
        "95550f529be70653c01a39c155aba08c1b48a17f5abb971f6a",
        "304402207c9581752c34f4bebca2dbb70ecfbeeb09f900a7aed4c2f9566f1444ad10aef4022036797fe63d0ba2"
        "13e0ce3de7da6d5e61cf70b821700d5f8db2fe09c3de8578f3",
        "304502210082f2c2234b22e9318b3457e294bbf879f1f61c276170d5bb997c1704bc2a19f1022053629538276a"
        "de5cbeb2056ab85339b903f2159e0e1e00493cbf06efa5b33c39"};

    const int expected_command_types[] = {COMMAND_SEED,
                                          COMMAND_ADD_MEMBER,
                                          COMMAND_PUBLISH_KEY,
                                          COMMAND_ADD_MEMBER,
                                          COMMAND_PUBLISH_KEY};

    const char* expected_member_name[] = {"", "Bob", "", "Charlie", ""};

    const char* expected_public_keys[] = {
        "",
        "03deb34b832df74a6b8b0fb2f879ad322ef3c38750d19620087cc538fdf2847e45",
        "03deb34b832df74a6b8b0fb2f879ad322ef3c38750d19620087cc538fdf2847e45",
        "03d47c01b17297214f1f3356a10ae9c88bbe223ccdd08895c65885cb2185389a48",
        "03d47c01b17297214f1f3356a10ae9c88bbe223ccdd08895c65885cb2185389a48"};

    const char* expected_versions[] = {
        "",
        "",
        "d420e11563ce641ea0e759ef2cf452af2aab1f52d84f4a62f3d920a35dc7dbcf",
        "",
        "d420e11563ce641ea0e759ef2cf452af2aab1f52d84f4a62f3d920a35dc7dbcf"};

    const int expected_permissions[] = {KEY_READER, KEY_READER, KEY_READER, KEY_READER, KEY_READER};

    const char* expected_encrypted_keys[] = {"",
                                             "",
                                             "dd741499e049f2b34728251a8f3c65d473caeee81f74eb758254f"
                                             "6b8e142f205b46cad2b05e7a9951fa1d10145f6ec6c",
                                             "",
                                             "84ca9427bf0362ba24dec427f048b799d81eaf80f36be3d3502cd"
                                             "822d02d6946c66248615828af7361c65ac9d00fbda8"};

    buffer_t buffer;
    hex_to_buffer(stream, &buffer);
    int block_index = 0;
    int command_count = 0;

    int expected_command_count = 5;

    // while (buffer_can_read(&buffer, 2)) {
    //     // Parse block header
    //     block_header_t header;
    //     parse_block_header(&buffer, &header);

    //     // Check issuer
    //     char issuer_hex[65];
    //     atohex(header.issuer, sizeof(header.issuer), issuer_hex);
    //     assert_string_equal(expected_issuers[block_index], issuer_hex);

    //     // Check parent
    //     char parent_hex[64];
    //     atohex(header.parent, sizeof(header.parent), parent_hex);
    //     assert_string_equal(expected_parents[block_index], parent_hex);

    //     // Parse commands
    //     for (int command_index = 0; command_index < header.length; command_index++) {
    //         block_command_t command;
    //         parse_block_command(&buffer, &command);

    //         // Check command type
    //         assert_int_equal(command.type, expected_command_types[command_count]);

    //         // Check member name
    //         if (command.type == COMMAND_ADD_MEMBER) {
    //             assert_string_equal(command.command.add_member.name,
    //                                 expected_member_name[command_count]);
    //         }

    //         // Check public key
    //         if (command.type == COMMAND_PUBLISH_KEY) {
    //             char public_key_hex[66];
    //             atohex(command.command.publish_key.recipient,
    //                    sizeof(command.command.publish_key.recipient),
    //                    public_key_hex);
    //             assert_string_equal(public_key_hex, expected_public_keys[command_count]);
    //         }
    //         if (command.type == COMMAND_ADD_MEMBER) {
    //             char public_key_hex[66];
    //             atohex(command.command.add_member.public_key,
    //                    sizeof(command.command.add_member.public_key),
    //                    public_key_hex);
    //             assert_string_equal(public_key_hex, expected_public_keys[command_count]);
    //         }

    //         // Check permissions
    //         if (command.type == COMMAND_ADD_MEMBER) {
    //             assert_int_equal(command.command.add_member.permissions,
    //                              expected_permissions[command_count]);
    //         }

    //         // Check encrypted key
    //         if (command.type == COMMAND_PUBLISH_KEY) {
    //             char encrypted_key_hex[MAX_ENCRYPTED_KEY_LEN];
    //             atohex(command.command.publish_key.key,
    //                    command.command.publish_key.key_size,
    //                    encrypted_key_hex);
    //             assert_string_equal(encrypted_key_hex, expected_encrypted_keys[command_count]);
    //         }

    //         // Check versions
    //         if (command.type == COMMAND_PUBLISH_KEY) {
    //             char version_hex[64];
    //             atohex(command.command.publish_key.version,
    //                    sizeof(command.command.publish_key.version),
    //                    version_hex);
    //             assert_false(command.command.publish_key.null_version);
    //             assert_string_equal(version_hex, expected_versions[command_count]);
    //         }

    //         command_count += 1;
    //         assert_true(command_count <= expected_command_count);
    //     }

    //     // Parse signature
    //     uint8_t signature[71];
    //     int sig_size = parse_block_signature(&buffer, signature, sizeof(signature)) - 2;

    //     // Check signature
    //     char signature_hex[142];
    //     memset(signature_hex, 0, sizeof(signature_hex));
    //     atohex(signature, sig_size, signature_hex);
    //     assert_string_equal(expected_signatures[block_index], signature_hex);

    //     // Increment block index
    //     block_index += 1;
    // }
    // assert_int_equal(command_count, expected_command_count);
    // assert_int_equal(block_index, expected_block_count);
    free((void*) buffer.ptr);
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_block_header_parse),
                                       cmocka_unit_test(test_block_commands_parse),
                                       cmocka_unit_test(test_stream_parse)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
