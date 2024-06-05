#pragma once

#include <stdint.h>

// If you wish to change the matrix type, change the format
// specifier as well if you are going to print the matrix
typedef float matrix_type;
#define MATRIX_TYPE_FORMAT_SPECIFIER "%f"

#ifndef BLOCK_SIZE
#define BLOCK_SIZE 16  // Default value if not defined
#endif

#define DO_PREFETCH

matrix_type** matrix_alloc(uint64_t size);

void matrix_free(matrix_type** matrix);

void matrix_init_random(matrix_type** matrix, uint64_t size);

void matrix_print(matrix_type** matrix, uint64_t size);

static inline void matrix_transpose_naive(matrix_type** dst, matrix_type** src, uint64_t size) {
  for (uint64_t i = 0; i < size; i++) {
    for (uint64_t j = 0; j < size; j++) {
      dst[i][j] = src[j][i];
    }
  }
}

static inline void matrix_transpose_with_blocks(matrix_type** dst, matrix_type** src, uint64_t size) {
  matrix_type* dst_data = *dst;
  matrix_type* src_data = *src;

  for (uint64_t block_start_y = 0; block_start_y < size; block_start_y += BLOCK_SIZE) {
    const uint64_t block_end_y = BLOCK_SIZE + block_start_y;
    for (uint64_t block_start_x = 0; block_start_x < size; block_start_x += BLOCK_SIZE) {
      const uint64_t block_end_x = BLOCK_SIZE + block_start_x;

      for (uint64_t y = block_start_y; y < block_end_y && y < size; y++) {
        for (uint64_t x = block_start_x; x < block_end_x && x < size; x++) {
          const uint64_t dst_index = y * size + x;
          const uint64_t src_index = x * size + y;

#ifdef DO_PREFETCH
          __builtin_prefetch(&src_data[src_index], 0, 0);
          __builtin_prefetch(&dst_data[dst_index], 1, 0);
#endif

          dst_data[dst_index] = src_data[src_index];
        }
      }
    }
  }
}
