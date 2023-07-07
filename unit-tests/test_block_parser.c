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

static int assert_seed_command(buffer_t *buffer, expected_seed_command_t *expectation, block_command_t *out) {
    int offset;
    block_command_t command;
    offset = parse_block_command(buffer, &command);
    assert_return_code(offset, 0);

    assert_int_equal(command.type, COMMAND_SEED);
    char topic[65];
    atohex(command.command.seed.topic, 32, topic);
    assert_string_equal(expectation->topic, topic);
    char group_key[67];
    atohex(command.command.seed.group_public_key, 33, group_key);
    assert_string_equal(expectation->group_key, group_key);
    char ephemeral_public_key[67];
    atohex(command.command.seed.ephemeral_public_key, 33, ephemeral_public_key);
    assert_string_equal(expectation->ephemeral_public_key, ephemeral_public_key);
    char encrypted_xpriv[163];
    atohex(command.command.seed.encrypted_xpriv, 81, encrypted_xpriv);
    assert_string_equal(expectation->xpriv, encrypted_xpriv);

    assert_int_equal(command.command.seed.protocol_version, expectation->version);

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

static int assert_add_member_command(buffer_t *buffer, expected_add_member_t *expectation, block_command_t *out) {
    int offset;
    block_command_t command;
    offset = parse_block_command(buffer, &command);
    assert_return_code(offset, 0);

    assert_int_equal(command.type, COMMAND_ADD_MEMBER);
    assert_string_equal(expectation->name, command.command.add_member.name);

    if (out != NULL) {
        *out = command;
    }
    return offset;
}

typedef struct {
    const char*    initialization_vector;
    const char*    encrypted_key;
    const char*    recipient;
    const char*    ephemeral_public_key;
} expected_publish_key_t;

static int assert_publish_key_command(buffer_t *buffer, expected_publish_key_t *expectation, block_command_t *out) {
    int offset;
    block_command_t command;
    offset = parse_block_command(buffer, &command);
    assert_return_code(offset, 0);

    assert_int_equal(command.type, COMMAND_PUBLISH_KEY);
    printf("Check initialization vector\n");
    char initialization_vector[33];
    atohex(command.command.publish_key.initialization_vector, 16, initialization_vector);
    assert_string_equal(expectation->initialization_vector, initialization_vector);
    printf("Check encrypted key\n");
    char encrypted_key[2 * MAX_ENCRYPTED_KEY_LEN + 1];
    atohex(command.command.publish_key.encrypted_xpriv, command.command.publish_key.encrypted_xpriv_size, encrypted_key);
    assert_string_equal(expectation->encrypted_key, encrypted_key);
    printf("Check recipient\n");
    char recipient[67];
    atohex(command.command.publish_key.recipient, 33, recipient);
    assert_string_equal(expectation->recipient, recipient);
    printf("Check ephemeral public key\n");
    char ephemeral_public_key[67];
    atohex(command.command.publish_key.ephemeral_public_key, 33, ephemeral_public_key);
    assert_string_equal(expectation->ephemeral_public_key, ephemeral_public_key);

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
    assert_seed_command(&buffer, &seed_expectations, NULL);

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
       "01010102203ada69510582aa0bf041dd494a8157347f498050f351b5e4c376c4c041eca"
       "658062103d65ae4273c9cca7eae94a6553ef930e82408383df59f9b2b697b7b3245268a"
       "7801010110d10520c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a261"
       "474192851010200000621024bb4a18f1007caefc2c3e14c793bf0233170d4e5b0f9253c"
       "b21e9947c7ad658405108058bd4a4c50b0e18b575f3fc6b7a632055110fe49c8d2ab66a"
       "80bdd43b9af73b2433ea712a5285e6c8ab8ff7bf6e8699a03d41007cab2e4617a936328"
       "af0c284e2c5bb466963d5fca5079d8dfc9700ac9a380121855c41bb380cdedeca33a92f"
       "3a2000621030eaab45c1662fed4134350158b2164a6e623ac8a23b9b8421f9fd272f366"
       "a2be03473045022100da9e28c3a3d7de29497a502678fbbc0cd2b1b350ff30020b2389a"
       "75c4155e0f9022072ce5e7bb29d8d71b8eba5563a7f622a1607ed7f4251addeb34b49ac"
       "b1265157010101022012ce46e63711cfa1165941453e24b62b238ffda3673c616e1c4af"
       "d2535b67179062103d65ae4273c9cca7eae94a6553ef930e82408383df59f9b2b697b7b"
       "3245268a78010102112e0403426f620621028cd3462bb33fb3f331a406fb4af0ccfef6d"
       "f8aa1e30eb8fa2866ba18f6d09a1401040000000112ab0510dce39150ff59fe79d673f9"
       "57eb951c84055110b5a98d5912780ac4d0c12f7a3534a7cfae723709d8b3d06f7045641"
       "ef911fc2a72e41ec1c792c83688133b86870934dcf6de3bd1b5e65613f72543d7165ef7"
       "7908475ef4c89b2c03e3c2c9398ad2ee790621028cd3462bb33fb3f331a406fb4af0ccf"
       "ef6df8aa1e30eb8fa2866ba18f6d09a140621036585373498e24e101dd4c073aeddd1bc"
       "d68f652aef763d9c01df095b7a688bb003473045022100918ec25822c8b04dc3123df9f"
       "7637d74aeef94c0d3178b6088c8c20673aba877022027ba331b73aac6f6698fdfda6f68"
       "bae1b23e501df2e6db68e5c32482975e47b8010101022041dd318508647e2d4ad95d734"
       "167ff88bc32a7c909cacfe9bc1850fd422c6414062103d65ae4273c9cca7eae94a6553e"
       "f930e82408383df59f9b2b697b7b3245268a7801010211320407436861726c696506210"
       "25ba82b0d34fc5c19e9f7489e848e03681cfd9721ca8264a6907adcd0bdc1ea6a010400"
       "00000112ab0510d3cf887cd7f8aa2c55c3ec85872c9fe60551101eb76a2c402811e054b"
       "3092d50f7e081462bf37a28b2d287dfac04e37f3fd0c7da57bf2a7fe33925f3f54c83ed"
       "59c7da199516cc607ff495654b06f25f8cec7855ea7b13c3f1db6965fad1db99b8c4ea0"
       "621025ba82b0d34fc5c19e9f7489e848e03681cfd9721ca8264a6907adcd0bdc1ea6a06"
       "210384290c9798060480af23249122efccf70f880ecaf8e0369e8535efd8c49be82c034"
       "73045022100cb26d93214cdb4f229c98d2e2c8ca75897adc55d29a110942e15b73575e9"
       "ead002201cea2cd86cb7fee68ef8b36d33af5683d70a96f71601f675a86583491778e6fe";

    const int expected_block_count = 3;

    const char* expected_issuers[] = {
        "03d65ae4273c9cca7eae94a6553ef930e82408383df59f9b2b697b7b3245268a78",
        "03d65ae4273c9cca7eae94a6553ef930e82408383df59f9b2b697b7b3245268a78",
        "03d65ae4273c9cca7eae94a6553ef930e82408383df59f9b2b697b7b3245268a78"};

    const char* expected_parents[] = {
        "3ada69510582aa0bf041dd494a8157347f498050f351b5e4c376c4c041eca658",
        "12ce46e63711cfa1165941453e24b62b238ffda3673c616e1c4afd2535b67179",
        "41dd318508647e2d4ad95d734167ff88bc32a7c909cacfe9bc1850fd422c6414"};

    const char* expected_signatures[] = {
        "3045022100da9e28c3a3d7de29497a502678fbbc0cd2b1b350ff30020b2389a75c4155"
        "e0f9022072ce5e7bb29d8d71b8eba5563a7f622a1607ed7f4251addeb34b49acb1265157",
        
        "3045022100918ec25822c8b04dc3123df9f7637d74aeef94c0d3178b6088c8c20673ab"
        "a877022027ba331b73aac6f6698fdfda6f68bae1b23e501df2e6db68e5c32482975e47b8",
        
        "3045022100cb26d93214cdb4f229c98d2e2c8ca75897adc55d29a110942e15b73575e9"
        "ead002201cea2cd86cb7fee68ef8b36d33af5683d70a96f71601f675a86583491778e6fe"
    };

    buffer_t buffer;
    hex_to_buffer(stream, &buffer);
    int block_index = 0;

    while (buffer_can_read(&buffer, 2)) {
        // Parse block header
        block_header_t header;
        parse_block_header(&buffer, &header);

        // Check issuer
        char issuer_hex[65];
        atohex(header.issuer, sizeof(header.issuer), issuer_hex);
        assert_string_equal(expected_issuers[block_index], issuer_hex);

        // Check parent
        char parent_hex[64];
        atohex(header.parent, sizeof(header.parent), parent_hex);
        assert_string_equal(expected_parents[block_index], parent_hex);

         // Parse commands
        for (int command_index = 0; command_index < header.length; command_index++) {
            printf("block_index: %d, command_index: %d\n", block_index, command_index);
            if (block_index == 0 && command_index == 0) {
               expected_seed_command_t expectations = {
                    .topic = "c96d450545ff2836204c29af291428a5bf740304978f5dfb0b4a261474192851",
                    .version = 0,
                    .ephemeral_public_key = "030eaab45c1662fed4134350158b2164a6e623ac8a23b9b8421f9fd272f366a2be",
                    .xpriv = "10fe49c8d2ab66a80bdd43b9af73b2433ea712a5285e6c8ab8ff7bf6e8699a03d41007cab2e4617a9"
                            "36328af0c284e2c5bb466963d5fca5079d8dfc9700ac9a380121855c41bb380cdedeca33a92f3a200",
                    .group_key = "024bb4a18f1007caefc2c3e14c793bf0233170d4e5b0f9253cb21e9947c7ad6584",
                    .iv = "8058bd4a4c50b0e18b575f3fc6b7a632"
               };
               assert_seed_command(&buffer, &expectations, NULL);
            } else if (block_index == 1 && command_index == 0) {
                expected_add_member_t expectations = {
                    .name = "Bob",
                    .permissions = 1,
                    .public_key = "028cd3462bb33fb3f331a406fb4af0ccfef6df8aa1e30eb8fa2866ba18f6d09a14"
                };
                assert_add_member_command(&buffer, &expectations, NULL);
            } else if (block_index == 1 && command_index == 1) {
                expected_publish_key_t expectations = {
                    .recipient = "028cd3462bb33fb3f331a406fb4af0ccfef6df8aa1e30eb8fa2866ba18f6d09a14",
                    .encrypted_key = "10b5a98d5912780ac4d0c12f7a3534a7cfae723709d8b3d06f7045641ef911f"
                    "c2a72e41ec1c792c83688133b86870934dcf6de3bd1b5e65613f72543d7165ef77908475ef4c89b2c03e3c2c9398ad2ee79",
                    .ephemeral_public_key = "036585373498e24e101dd4c073aeddd1bcd68f652aef763d9c01df095b7a688bb0",
                    .initialization_vector = "dce39150ff59fe79d673f957eb951c84"
                };
                assert_publish_key_command(&buffer, &expectations, NULL);
            } else if (block_index == 2 && command_index == 0) {
                expected_add_member_t expectations = {
                    .name = "Charlie",
                    .permissions = 1,
                    .public_key = "025ba82b0d34fc5c19e9f7489e848e03681cfd9721ca8264a6907adcd0bdc1ea6a"
                };
                assert_add_member_command(&buffer, &expectations, NULL);
            } else if (block_index == 2 && command_index == 1) {
                expected_publish_key_t expectations = {
                    .encrypted_key = "101eb76a2c402811e054b3092d50f7e081462bf37a28b2d287dfac04e37f3fd0c7d"
                    "a57bf2a7fe33925f3f54c83ed59c7da199516cc607ff495654b06f25f8cec7855ea7b13c3f1db6965fad1db99b8c4ea",
                    .ephemeral_public_key = "0384290c9798060480af23249122efccf70f880ecaf8e0369e8535efd8c49be82c",
                    .recipient = "025ba82b0d34fc5c19e9f7489e848e03681cfd9721ca8264a6907adcd0bdc1ea6a",
                    .initialization_vector = "d3cf887cd7f8aa2c55c3ec85872c9fe6",
                };
                assert_publish_key_command(&buffer, &expectations, NULL);
            }
        }

        // Parse signature
        uint8_t signature[71];
        int sig_size = parse_block_signature(&buffer, signature, sizeof(signature)) - 2;

        // Check signature
        char signature_hex[142];
        memset(signature_hex, 0, sizeof(signature_hex));
        atohex(signature, sig_size, signature_hex);
        assert_string_equal(expected_signatures[block_index], signature_hex);

        // Increment block index
        block_index += 1;
    }

    assert_int_equal(block_index, expected_block_count);

    free((void*) buffer.ptr);
}

static int test_parse_derive_command(void** state) {
    (void) state;
    const char *command = "";
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_block_header_parse),
                                       cmocka_unit_test(test_block_commands_parse),
                                       cmocka_unit_test(test_stream_parse)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
