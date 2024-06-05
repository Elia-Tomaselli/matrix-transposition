#pragma once

#include <stdint.h>

// If you wish to change the matrix type, change the format
// specifier as well if you are going to print the matrix
typedef float matrix_type;
#define MATRIX_TYPE_FORMAT_SPECIFIER "%f"

typedef struct
{
  matrix_type *h;
  matrix_type *d;
} matrix_t;

void matrix_alloc(matrix_t *matrix, uint64_t size);

void matrix_free(matrix_t *matrix);

void matrix_init_random(matrix_t *matrix, uint64_t size);

void matrix_print(matrix_t *matrix, uint64_t size);
