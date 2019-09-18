/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#ifndef __INCLUDE_PARSER_H__
#define __INCLUDE_PARSER_H__

#include <stdint.h>

#define PARSE_DELIMITER				" \f\n\r\t\v"

#define skip_white_spaces(pos)			\
({						\
	__typeof__(pos) _p = (pos);		\
	for ( ; isspace(*_p); _p++)		\
		;				\
	_p;					\
})

static inline size_t
skip_digits(const char *src)
{
	size_t i;

	for (i = 0; isdigit(src[i]); i++)
		;

	return i;
}

int parser_read_arg_bool(const char *p);

int parser_read_uint64(uint64_t *value, const char *p);
int parser_read_uint32(uint32_t *value, const char *p);
int parser_read_uint16(uint16_t *value, const char *p);
int parser_read_uint8(uint8_t *value, const char *p);

int parser_read_uint64_hex(uint64_t *value, const char *p);
int parser_read_uint32_hex(uint32_t *value, const char *p);
int parser_read_uint16_hex(uint16_t *value, const char *p);
int parser_read_uint8_hex(uint8_t *value, const char *p);

int parser_read_int32(int32_t *value, const char *p);

int parse_hex_string(char *src, uint8_t *dst, uint32_t *size);

int parse_tokenize_string(char *string, char *tokens[], uint32_t *n_tokens);

int parse_lcores_list(bool lcores[], const char *corelist);
#endif
