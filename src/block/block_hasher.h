#pragma once

#include "os.h"
#include "cx.h"
#include "types.h"

int block_hash_header(const block_header_t *header, cx_hash_t *digest);
int block_hash_command(const block_command_t *command, cx_hash_t *digest);
