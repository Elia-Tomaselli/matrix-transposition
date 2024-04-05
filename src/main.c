#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "matrix.h"

void init_matrix_random(float** matrix, size_t rows, size_t cols) {
  for (size_t i = 0; i < rows; i++) {
    for (size_t j = 0; j < cols; j++) {
      matrix[i][j] = (float)rand() / RAND_MAX;
    }
  }
}

int pow2(int exponent) {
  return 1 << exponent;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Usage: %s <exponent>\n", argv[0]);
    return EXIT_FAILURE;
  }

  uint8_t exponent = (uint8_t)atoi(argv[1]);

  if (exponent == 0 && argv[1][0] != '0') {
    fprintf(stderr, "Error: Invalid input\n");
    return EXIT_FAILURE;
  }

  uint64_t matrix_size = pow2(exponent);

  float** matrix = matrix_alloc(matrix_size, matrix_size);

  if (matrix == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    return EXIT_FAILURE;
  }

  srand(time(NULL));
  init_matrix_random(matrix, matrix_size, matrix_size);

  float** transpose = matrix_transpose(matrix, matrix_size, matrix_size);

  if (transpose == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    matrix_free(matrix, matrix_size);
    return EXIT_FAILURE;
  }

  matrix_free(matrix, matrix_size);
  matrix_free(transpose, matrix_size);

  return 0;
}