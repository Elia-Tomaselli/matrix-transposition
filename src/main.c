#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "matrix.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <exponent>\n", argv[0]);
    return 1;
  }

  uint8_t exponent = (uint8_t)atoi(argv[1]);

  if (exponent == 0 && argv[1][0] != '0') {
    fprintf(stderr, "Error: Invalid input\n");
    return 1;
  }

  // Same as raising 2 to the power of exponent
  uint64_t size = 1 << exponent;

  matrix_type** matrix = matrix_alloc(size);
  if (matrix == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    return 1;
  }

  srand(time(NULL));
  matrix_init_random(matrix, size);

  matrix_type** matrixT = matrix_alloc(size);
  if (matrixT == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    matrix_free(matrix);
    return 1;
  }

  clock_t start = clock();

  // matrix_transpose_dumb(matrixT, matrix, size);
  matrix_transpose_with_blocks(matrixT, matrix, size);

  clock_t end = clock();

  double time_taken = (double)(end - start) / CLOCKS_PER_SEC;
  printf("Time: %lf\n", time_taken);

  // matrix_print(matrix, size);
  // matrix_print(matrixT, size);

  matrix_free(matrix);
  matrix_free(matrixT);

  return 0;
}
