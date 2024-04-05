#include <stdio.h>
#include <stdlib.h>

float** matrix_alloc(size_t rows, size_t cols) {
  float** matrix = (float**)malloc(rows * sizeof(float*));

  if (matrix == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < rows; i++) {
    matrix[i] = (float*)malloc(cols * sizeof(float));
    if (matrix[i] == NULL) {
      for (size_t j = 0; j < i; j++) {
        free(matrix[j]);
      }
      free(matrix);
      return NULL;
    }
  }

  return matrix;
}

float** matrix_transpose(float** matrix, size_t rows, size_t cols) {
  float** transpose = matrix_alloc(cols, rows);
  if (transpose == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < rows; i++) {
    for (size_t j = 0; j < cols; j++) {
      transpose[j][i] = matrix[i][j];
    }
  }

  return transpose;
}

void matrix_free(float** matrix, size_t rows) {
  for (size_t i = 0; i < rows; i++) {
    free(matrix[i]);
  }

  free(matrix);
}