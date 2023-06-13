#pragma once

#include "../common/buffer.h"
#include "cx.h"

/**
 * Handler for SIGN_INIT command.
 */
int handler_init_signature_flow(buffer_t *cdata);