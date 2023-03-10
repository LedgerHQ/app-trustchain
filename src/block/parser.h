#pragma once

#include "types.h"
#include "../common/buffer.h"

int parse_block_header(buffer_t *data, block_header_t *out);