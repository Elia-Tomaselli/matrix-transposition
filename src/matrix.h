#pragma once

#include <stdint.h>

// To change the matrix type, change the typedef and the format specifier
typedef float matrix_type;
#define MATRIX_TYPE_FORMAT_SPECIFIER "%f"

matrix_type** matrix_alloc(uint64_t size);

void matrix_free(matrix_type** matrix);

void matrix_init_random(matrix_type** matrix, uint64_t size);

void matrix_print(matrix_type** matrix, uint64_t size);

void matrix_transpose_dumb(matrix_type** dst, matrix_type** src, uint64_t size);

void matrix_transpose_with_blocks(matrix_type** dst, matrix_type** src, uint64_t size);