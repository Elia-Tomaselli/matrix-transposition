#include "matrix.cuh"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "cuda_error.cuh"

void matrix_alloc(matrix_t *matrix, uint64_t size)
{
  matrix_type *h_matrix;
  gpuErrchk(cudaMallocHost((void **)&h_matrix, size * size * sizeof(matrix_type)));
  matrix->h = h_matrix;

  matrix_type *d_matrix;
  gpuErrchk(cudaMalloc((void **)&d_matrix, size * size * sizeof(matrix_type)));
  matrix->d = d_matrix;
}

void matrix_free(matrix_t *matrix)
{
  gpuErrchk(cudaFreeHost(matrix->h));
  gpuErrchk(cudaFree(matrix->d));
}

void matrix_init_random(matrix_t *matrix, uint64_t size)
{
  for (uint64_t i = 0; i < size * size; i++)
    matrix->h[i] = (matrix_type)rand() / RAND_MAX;

  gpuErrchk(cudaMemcpy(matrix->d, matrix->h, size * size * sizeof(matrix_type), cudaMemcpyHostToDevice));
}

void matrix_print(matrix_t* matrix, uint64_t size)
{
  printf("[\n");
  for (uint64_t i = 0; i < size; i++)
  {
    printf("[");
    for (uint64_t j = 0; j < size; j++)
    {
      uint64_t index = i * size + j;
      printf(MATRIX_TYPE_FORMAT_SPECIFIER, matrix->h[index]);
      if (j != size - 1)
        printf(", ");
    }
    printf("]");
    if (i != size - 1)
      printf(",\n");
  }
  printf("\n]\n");
}
