#include "matrix.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "cache_line_size.h"

matrix_type** matrix_alloc(uint64_t size) {
  matrix_type* matrix_data = (matrix_type*)aligned_alloc(get_cache_line_size(), size * size * sizeof(matrix_type));
  if (matrix_data == NULL) {
    return NULL;
  }

  matrix_type** matrix = (matrix_type**)aligned_alloc(get_cache_line_size(), size * sizeof(matrix_type*));
  if (matrix == NULL) {
    free(matrix);
    return NULL;
  }

  for (uint64_t i = 0; i < size; i++) {
    matrix[i] = matrix_data + i * size;
  }

  return matrix;
}

void matrix_free(matrix_type** matrix) {
  free(*matrix);
  free(matrix);
}

void matrix_init_random(matrix_type** matrix, uint64_t size) {
  matrix_type* matrix_data = *matrix;
  for (uint64_t i = 0; i < size * size; i++) {
    matrix_data[i] = (matrix_type)rand() / RAND_MAX;
  }
}

void matrix_print(matrix_type** matrix, uint64_t size) {
  printf("[\n");
  for (uint64_t i = 0; i < size; i++) {
    printf("\t[");
    for (uint64_t j = 0; j < size; j++) {
      printf(MATRIX_TYPE_FORMAT_SPECIFIER, matrix[i][j]);
      if (j != size - 1)
        printf(", ");
    }
    printf("]");
    if (i != size - 1)
      printf(",\n");
  }
  printf("\n]\n");
}
