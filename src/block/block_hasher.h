#pragma once

#include "os.h"
#include "../crypto.h"
#include "types.h"
#include "block_parser.h"

int block_hash_header(const block_header_t *header, crypto_hash_t *digest);
int block_hash_command(const block_command_t *command, crypto_hash_t *digest);
