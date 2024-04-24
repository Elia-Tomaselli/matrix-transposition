#pragma once

#include <stdint.h>

// If you wish to change the matrix type, change the format
// specifier as well if you are going to print the matrix
typedef float matrix_type;
#define MATRIX_TYPE_FORMAT_SPECIFIER "%f"

#define BLOCK_SIZE 16

matrix_type** matrix_alloc(uint64_t size);

void matrix_free(matrix_type** matrix);

void matrix_init_random(matrix_type** matrix, uint64_t size);

void matrix_print(matrix_type** matrix, uint64_t size);

inline void matrix_transpose_dumb(matrix_type** dst, matrix_type** src, uint64_t size) {
  for (uint64_t i = 0; i < size; i++) {
    for (uint64_t j = 0; j < size; j++) {
      dst[i][j] = src[j][i];
    }
  }
}

inline void matrix_transpose_with_blocks(matrix_type** dst, matrix_type** src, uint64_t size) {
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

inline void matrix_transpose_dumb_in_place(matrix_type** matrix, uint64_t size) {
  for (uint64_t i = 0; i < size; i++) {
    for (uint64_t j = i + 1; j < size; j++) {
      matrix_type tmp = matrix[i][j];
      matrix[i][j] = matrix[j][i];
      matrix[j][i] = tmp;
    }
  }
}

inline void matrix_transpose_with_blocks_in_place(matrix_type** matrix, uint64_t size) {
  matrix_type* matrix_data = *matrix;

  for (uint64_t block_offset_x = 0; block_offset_x < size; block_offset_x += BLOCK_SIZE) {
    uint64_t block_size_plus_offset_x = BLOCK_SIZE + block_offset_x;
    for (uint64_t block_offset_y = 0; block_offset_y < size; block_offset_y += BLOCK_SIZE) {
      uint64_t block_size_plus_offset_y = BLOCK_SIZE + block_offset_y;

      for (uint64_t x = block_offset_x; x < block_size_plus_offset_x && x < size; x++) {
        for (uint64_t y = block_offset_y; y < block_size_plus_offset_y && y < size; y++) {
          uint64_t dst_index = y * size + x;
          uint64_t src_index = x * size + y;

          matrix_type tmp = matrix_data[dst_index];
          matrix_data[dst_index] = matrix_data[src_index];
          matrix_data[src_index] = tmp;
        }
      }
    }
  }
}

inline void matrix_transpose_with_blocks_and_prefetch(matrix_type** dst, matrix_type** src, uint64_t size) {
  matrix_type* dst_data = *dst;
  matrix_type* src_data = *src;

  for (uint64_t block_offset_x = 0; block_offset_x < size; block_offset_x += BLOCK_SIZE) {
    uint64_t block_size_plus_offset_x = BLOCK_SIZE + block_offset_x;
    for (uint64_t block_offset_y = 0; block_offset_y < size; block_offset_y += BLOCK_SIZE) {
      uint64_t block_size_plus_offset_y = BLOCK_SIZE + block_offset_y;
      // __builtin_prefetch(&src_data[(block_size_plus_offset_x) * BLOCK_SIZE], 0);
      // __builtin_prefetch(&dst_data[(block_size_plus_offset_Y) * BLOCK_SIZE], 1);

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