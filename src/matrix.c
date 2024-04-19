#include "matrix.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define BLOCK_SIZE 8

#define MIN(a, b) ((a) < (b) ? (a) : (b))

matrix_type** matrix_alloc(uint64_t size) {
  matrix_type* matrix_data = (matrix_type*)malloc(size * size * sizeof(matrix_type));
  if (matrix_data == NULL) {
    return NULL;
  }

  matrix_type** matrix = (matrix_type**)malloc(size * sizeof(matrix_type*));
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

void matrix_transpose_dumb(matrix_type** dst, matrix_type** src, uint64_t size) {
  for (uint64_t i = 0; i < size; i++) {
    for (uint64_t j = 0; j < size; j++) {
      dst[i][j] = src[j][i];
    }
  }
}

void matrix_transpose_with_blocks(matrix_type** dst, matrix_type** src, uint64_t size) {
  matrix_type* dst_data = *dst;
  matrix_type* src_data = *src;

  for (uint64_t block_offset_x = 0; block_offset_x < size; block_offset_x += BLOCK_SIZE) {
    uint64_t block_size_plus_offset_x = BLOCK_SIZE + block_offset_x;
    
    for (uint64_t block_offset_y = 0; block_offset_y < size; block_offset_y += BLOCK_SIZE) {
      uint64_t block_size_plus_offset_y = BLOCK_SIZE + block_offset_y;

      for (uint64_t x = block_offset_x; x < block_size_plus_offset_x && x < size; x++) {
       
        for (uint64_t y = block_offset_y; y < block_size_plus_offset_y && y < size; y++) {
          uint64_t dst_index = y * size + x;
          uint64_t src_index = x * size + y;
          
          dst_data[dst_index] = src_data[src_index];
        }
      }
    }
  }
}