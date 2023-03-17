#include "parse_stream.h"
#include "../globals.h"
#include "../sw.h"
#include "../stream/stream.h"
#include "../block/block_parser.h"

static int handler_parse_header(buffer_t *data) {
    if (stream_parse_block_header(&G_context.stream, data) < 0) {
        return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
    }

    return io_send_sw(SW_OK);
}

static int handler_parse_command(buffer_t *data, parse_stream_output_mode_t output_mode) {
    // TODO Add trusted param output
    (void) output_mode;
    if (stream_parse_command(&G_context.stream, data, NULL) < 0) {
        return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
    }

    return io_send_sw(SW_OK);
}

static int handler_parse_signature(buffer_t *data) {
    if (stream_parse_signature(&G_context.stream, data) < 0) {
        return io_send_sw(SW_STREAM_PARSER_INVALID_FORMAT);
    }

    return io_send_sw(SW_OK);
}

int handler_parse_stream(buffer_t *cdata,
                         parse_stream_mode_t parse_mode,
                         parse_stream_output_mode_t output_mode) {
    // If parse_mode is set to empty stream reset the context and output success
    if (parse_mode == MODE_PARSE_EMPTY_STREAM) {
        stream_init(&G_context.stream);
        return io_send_sw(SW_OK);
    }

    // If parse_mode is set to block header and we expected something else, reset the context
    if (G_context.stream.parsing_state != STREAM_PARSING_STATE_BLOCK_HEADER &&
        parse_mode == MODE_PARSE_BLOCK_HEADER) {
        stream_init(&G_context.stream);
    }

    // If parse_mode is set to command and we expected something else, reset and output an error
    if (G_context.stream.parsing_state != STREAM_PARSING_STATE_COMMAND &&
        parse_mode == MODE_PARSE_COMMAND) {
        stream_init(&G_context.stream);
        return io_send_sw(SW_STREAM_PARSER_BAD_STATE);
    }

    // If parse_mode is set to signature and we expected something else, reset and output an error
    if (G_context.stream.parsing_state != STREAM_PARSING_STATE_SIGNATURE &&
        parse_mode == MODE_PARSE_SIGNATURE) {
        stream_init(&G_context.stream);
        return io_send_sw(SW_STREAM_PARSER_BAD_STATE);
    }

    // If parse_mode is set to block header and we expected a block header, parse the block header
    if (parse_mode == MODE_PARSE_BLOCK_HEADER) {
        return handler_parse_header(cdata);
    }

    // If parse_mode is set to command and we expected a command, parse the command
    if (parse_mode == MODE_PARSE_COMMAND) {
        return handler_parse_command(cdata, output_mode);
    }

    // If parse_mode is set to signature and we expected a signature, parse the signature
    if (parse_mode == MODE_PARSE_SIGNATURE) {
        return handler_parse_signature(cdata);
    }

    return io_send_sw(SW_WRONG_P1P2);
}