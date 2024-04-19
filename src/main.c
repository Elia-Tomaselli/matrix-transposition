#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "matrix.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <exponent>\n", argv[0]);
    return EXIT_FAILURE;
  }

  uint8_t exponent = (uint8_t)atoi(argv[1]);

  if (exponent == 0 && argv[1][0] != '0') {
    fprintf(stderr, "Error: Invalid input\n");
    return EXIT_FAILURE;
  }

  // Same as raising 2 to the power of exponent
  uint64_t size = 1 << exponent;

  matrix_type** matrix = matrix_alloc(size);
  if (matrix == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    return EXIT_FAILURE;
  }

  srand(time(NULL));
  matrix_init_random(matrix, size);

  matrix_type** transposed_matrix = matrix_alloc(size);
  if (transposed_matrix == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    matrix_free(matrix);
    return EXIT_FAILURE;
  }

  matrix_transpose_dumb(transposed_matrix, matrix, size);
  // matrix_transpose_rec(transposed_matrix, matrix, size);

  matrix_print(matrix, size);
  matrix_print(transposed_matrix, size);

  matrix_free(matrix);
  matrix_free(transposed_matrix);

  return 0;
}
